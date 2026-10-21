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
				reach[key][str(m["ip"])+":22"] = true
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

func (e *Execution) jumpEnabled() bool { return boolean(e.P.Config["ssh_jump"]) }

// maxSavedKeys bounds ssh_key_add, which also keeps the jump file small.
const maxSavedKeys = 50

// syncJumpNow sends a key change to the jump host at once instead of with
// the next reconcile.
func (e *Execution) syncJumpNow() {
	if e.jumpEnabled() {
		e.SyncJump(jumpAuthorizedKeys(e.S))
	}
}

// SyncJump sends the jump host its keys. A jump host that cannot be reached
// costs members only that path, so it does not fail the reconcile.
func (e *Execution) SyncJump(keys string) any {
	if f := attempt(func() { e.Call(D{"op": "sync", "authorized": keys}, "carrel-jump") }); f != nil {
		slog.Error("jump_sync_failed", "event", "jump_sync_failed")
		return "unavailable"
	}
	return "synced"
}
