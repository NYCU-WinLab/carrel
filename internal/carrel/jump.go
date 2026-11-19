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
// Only machines that trust the site's CA and serve SSH count.
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

// syncJumpNow sends a key or access change to the jump host at once instead
// of with the next reconcile.
func (e *Execution) syncJumpNow() {
	if e.jumpEnabled() {
		e.SyncJump(jumpAuthorizedKeys(e.S), jumpCertificates(e.S, e.P.Config.SSHUserCA))
	}
}

// SyncJump sends the jump host its keys, then the certificate map in a
// separate request, so a jump host that predates certificates still takes
// keys. A jump host that cannot be reached costs members only that path, so
// it does not fail the reconcile.
func (e *Execution) SyncJump(keys string, certs D) any {
	if f := attempt(func() { e.Call(D{"op": "sync", "authorized": keys}, "carrel-jump") }); f != nil {
		slog.Error("jump_sync_failed", "event", "jump_sync_failed")
		return "unavailable"
	}
	if certs == nil {
		return "synced"
	}
	if f := attempt(func() { e.Call(D{"op": "certs", "certs": certs}, "carrel-jump") }); f != nil {
		slog.Error("jump_certs_failed", "event", "jump_certs_failed")
		return "keys_only"
	}
	return "synced"
}
