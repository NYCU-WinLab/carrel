package carrel

import (
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strings"
)

// The SSH jump host (issue #98) lets a member reach machines that have no
// public port: `ssh -J jump@<origin> user@<machine address>`. It runs in CT 102
// as a forwarder only. Each saved or installed public key may open port 22 of
// the machines in the tenants that hold it, and nothing else; the session
// itself stays end to end between the member and the machine.

var jumpKey = regexp.MustCompile(`^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)) [A-Za-z0-9+/]+={0,3}`)

// jumpAuthorizedKeys renders the jump user's authorized_keys file.
func jumpAuthorizedKeys(s *Store) string {
	reach := map[string]map[string]bool{}
	for _, t := range s.Tenants() {
		if t["status"] != "active" {
			continue
		}
		n := integer(t["n"])
		machines := filter(s.Objects("machines", n), func(m D) bool { return m["state"] != "deleting" })
		keys := map[string]bool{}
		for _, k := range rowsOf[sshKey](s, "keys", n) {
			keys[k.Key] = true
		}
		for _, m := range machines {
			for _, k := range arr(m["ssh_keys"]) {
				keys[str(k)] = true
			}
		}
		for k := range keys {
			// Type and key only: a comment never reaches the options line.
			key := jumpKey.FindString(strings.TrimSpace(k))
			if key == "" {
				continue
			}
			if reach[key] == nil {
				reach[key] = map[string]bool{}
			}
			for _, m := range machines {
				// A machine without SSH forwards its declared ports (#94).
				ports := servicePortsOf(m)
				if len(ports) == 0 {
					ports = []int{22}
				}
				for _, p := range ports {
					reach[key][fmt.Sprintf("%s:%d", str(m["ip"]), p)] = true
				}
			}
		}
	}
	keys := make([]string, 0, len(reach))
	for k := range reach {
		if len(reach[k]) > 0 {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		targets := make([]string, 0, len(reach[k]))
		for t := range reach[k] {
			targets = append(targets, fmt.Sprintf("permitopen=%q", t))
		}
		sort.Strings(targets)
		fmt.Fprintf(&b, "restrict,port-forwarding,command=\"/usr/sbin/nologin\",%s %s\n", strings.Join(targets, ","), k)
	}
	return b.String()
}

func (e *Execution) jumpEnabled() bool { return e.P.Config.SSHJump }

// maxSavedKeys bounds ssh_key_add, which also keeps the jump file small.
const maxSavedKeys = 50

// jumpCertificates maps each principal a lab certificate may carry to the
// SSH address of every machine whose principals file names it: the creator
// or project:<name>, then the machine_access grants. On the jump host,
// jump-cert.py joins the addresses of all the principals in one certificate
// into a single line, because sshd uses only the first line that matches.
// Only machines that trust the site's CA and serve SSH count. Without a CA it
// is nil, which tells the jump host to drop its map.
func jumpCertificates(s *Store, ca string) D {
	if ca == "" {
		return nil
	}
	reach := map[string]map[string]bool{}
	for _, t := range s.Tenants() {
		if t["status"] != "active" {
			continue
		}
		for _, m := range s.Objects("machines", integer(t["n"])) {
			if m["state"] == "deleting" || str(m["ssh_user_ca"]) != ca || str(m["ip"]) == "" || len(arr(m["service_ports"])) > 0 {
				continue
			}
			for _, p := range caPrincipals(m) {
				name := str(p)
				if !caPrincipal.MatchString(name) {
					continue
				}
				if reach[name] == nil {
					reach[name] = map[string]bool{}
				}
				reach[name][str(m["ip"])+":22"] = true
			}
		}
	}
	principals := D{}
	for name, targets := range reach {
		list := make([]string, 0, len(targets))
		for t := range targets {
			list = append(list, t)
		}
		sort.Strings(list)
		principals[name] = list
	}
	return D{"ca": ca, "principals": principals}
}

// lockJumpState takes jumpMu and reads the jump keys and certificate map.
// The caller unlocks after the send. A read that panics unlocks first, so a
// failed reconcile cannot block every later jump sync.
func (e *Execution) lockJumpState() (keys string, certs D) {
	e.P.jumpMu.Lock()
	ok := false
	defer func() {
		if !ok {
			e.P.jumpMu.Unlock()
		}
	}()
	keys, certs = jumpAuthorizedKeys(e.S), jumpCertificates(e.S, e.P.Config.SSHUserCA)
	ok = true
	return keys, certs
}

// syncJumpNow asks for a jump sync after a key or access change and returns
// at once, so a request never waits for the jump host. One worker runs at a
// time; asks that arrive while it sends coalesce into one more pass. The pass
// reads the store and sends under jumpMu, like the reconcile path, so the last
// request sent carries the latest state. A failed send is logged by SyncJump
// and the next reconcile repairs it.
func (e *Execution) syncJumpNow() {
	if !e.jumpEnabled() {
		return
	}
	p := e.P
	p.jumpQueueMu.Lock()
	defer p.jumpQueueMu.Unlock()
	if p.jumpClosed {
		// Shutting down: the push at the next Start carries this change.
		return
	}
	p.jumpPending = true
	if p.jumpRunning {
		return
	}
	p.jumpRunning = true
	p.wg.Add(1)
	go p.jumpWorker()
}

func (p *Platform) jumpWorker() {
	defer p.wg.Done()
	e := p.execution(p.ctx)
	for {
		p.jumpQueueMu.Lock()
		if !p.jumpPending || p.ctx.Err() != nil {
			p.jumpRunning = false
			p.jumpPending = false
			p.jumpQueueMu.Unlock()
			return
		}
		p.jumpPending = false
		p.jumpQueueMu.Unlock()
		if f := attempt(func() {
			keys, certs := e.lockJumpState()
			defer p.jumpMu.Unlock()
			e.SyncJump(keys, certs)
		}); f != nil {
			slog.Error("jump_sync_failed", "event", "jump_sync_failed")
		}
	}
}

// SyncJump sends the jump host its keys, then the certificate map in a
// separate request, so a jump host that predates certificates still takes
// keys. The map goes every time, nil included: the jump host drops it when
// the site has no CA, and stops using it when no control plane has sent one
// for a while (jump-cert.py). A jump host that cannot be reached costs
// members only that path, so it does not fail the reconcile.
func (e *Execution) SyncJump(keys string, certs D) any {
	if f := attempt(func() { e.Call(D{"op": "sync", "authorized": keys}, jumpTarget) }); f != nil {
		slog.Error("jump_sync_failed", "event", "jump_sync_failed")
		return "unavailable"
	}
	if f := attempt(func() { e.Call(D{"op": "certs", "certs": certs}, jumpTarget) }); f != nil {
		slog.Error("jump_certs_failed", "event", "jump_certs_failed")
		return "keys_only"
	}
	return "synced"
}
