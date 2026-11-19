package carrel

import (
	"fmt"
	"log/slog"
	"maps"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// The SSH jump host (issue #98) lets a member reach machines that have no
// public port: `ssh -J jump@<origin> user@<machine address>`. It runs in CT 102
// as a forwarder only. Each saved or installed public key may open port 22 of
// the machines in the tenants that hold it, and nothing else; the session
// itself stays end to end between the member and the machine.

var jumpKey = regexp.MustCompile(`^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)) [A-Za-z0-9+/]+={0,3}`)

// jumpReach maps each saved or installed key to the addresses it opens: every
// port a machine of a tenant that holds it forwards. It also returns the keys
// of each tenant.
func jumpReach(s *Store) (map[string]map[string]bool, map[int][]string) {
	reach, held := map[string]map[string]bool{}, map[int][]string{}
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
			held[n] = append(held[n], key)
			if reach[key] == nil {
				reach[key] = map[string]bool{}
			}
			for _, m := range machines {
				for _, a := range jumpTargets(m) {
					reach[key][a] = true
				}
			}
		}
	}
	return reach, held
}

// jumpTargets is what the jump host forwards to a machine: port 22, or the
// ports a machine without SSH declares (#94).
func jumpTargets(m D) []string {
	ports := servicePortsOf(m)
	if len(ports) == 0 {
		ports = []int{22}
	}
	out := []string{}
	for _, p := range ports {
		out = append(out, fmt.Sprintf("%s:%d", str(m["ip"]), p))
	}
	return out
}

// jumpAuthorizedKeys renders the jump user's authorized_keys file.
func jumpAuthorizedKeys(s *Store) string {
	reach, _ := jumpReach(s)
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
// addresses the jump host forwards it to. sshd offers a member's certificate
// before their keys and uses the first line that matches, so a certificate
// must open at least what the member's keys open, or it would shut them out
// of machines their keys reach. The map does that for a member whose username
// Carrel has recorded (rememberUsername): the username opens every address
// any key of their personal tenant opens, and project:<name> opens every
// machine of that project. "users" lists those usernames; jump-cert.py admits
// a certificate only when it names one of them, and otherwise prints nothing
// so sshd goes on to the keys. On top, a machine that trusts the site's CA
// opens port 22 to the names in its principals file (machine_access). Without
// a CA it is nil, which tells the jump host to drop its map.
func jumpCertificates(s *Store, ca string) D {
	if ca == "" {
		return nil
	}
	reach := map[string]map[string]bool{}
	add := func(name string, targets ...string) {
		if !caPrincipal.MatchString(name) || len(targets) == 0 {
			return
		}
		if reach[name] == nil {
			reach[name] = map[string]bool{}
		}
		for _, t := range targets {
			reach[name][t] = true
		}
	}
	keys, held := jumpReach(s)
	owners := map[string][]int{}
	for _, t := range s.Tenants() {
		if t["status"] != "active" {
			continue
		}
		n, subject := integer(t["n"]), str(t["subject"])
		machines := filter(s.Objects("machines", n), func(m D) bool { return m["state"] != "deleting" && str(m["ip"]) != "" })
		if project := projectTenant.FindStringSubmatch(subject); project != nil {
			for _, m := range machines {
				add("project:"+project[1], jumpTargets(m)...)
			}
		}
		if r := s.SiteGet("usernames", subject); strings.HasPrefix(subject, "user:") && r != nil && portalUsername.MatchString(str(r["username"])) {
			owners[str(r["username"])] = append(owners[str(r["username"])], n)
		}
		for _, m := range machines {
			if str(m["ssh_user_ca"]) != ca || len(arr(m["service_ports"])) > 0 {
				continue
			}
			for _, p := range caPrincipals(m) {
				add(str(p), str(m["ip"])+":22")
			}
		}
	}
	users := []string{}
	for name, tenants := range owners {
		// Two accounts that once had the same username: neither is sure.
		if len(tenants) != 1 {
			continue
		}
		users = append(users, name)
		for _, k := range held[tenants[0]] {
			add(name, slices.Collect(maps.Keys(keys[k]))...)
		}
		for _, m := range s.Objects("machines", tenants[0]) {
			if m["state"] != "deleting" && str(m["ip"]) != "" {
				add(name, jumpTargets(m)...)
			}
		}
	}
	sort.Strings(users)
	principals := D{}
	for name, targets := range reach {
		principals[name] = slices.Sorted(maps.Keys(targets))
	}
	return D{"ca": ca, "principals": principals, "users": users}
}

// rememberUsername records the Keycloak username of the caller's personal
// tenant, from the token of each call, for jumpCertificates: a lab
// certificate names its member by username, and a personal tenant is known
// only by the account's subject.
func (e *Execution) rememberUsername(w D) {
	username, subject := str(w["username"]), "user:"+str(w["sub"])
	if !portalUsername.MatchString(username) || str(w["sub"]) == "" || e.S.Tenant(subject) == nil {
		return
	}
	if r := e.S.SiteGet("usernames", subject); r != nil && r["username"] == username {
		return
	}
	e.S.SitePut("usernames", subject, D{"username": username})
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
// keys. The map goes every time, nil included: the jump host drops it when
// the site has no CA, and stops using it when no control plane has sent one
// for a while (jump-cert.py). A jump host that cannot be reached costs
// members only that path, so it does not fail the reconcile.
func (e *Execution) SyncJump(keys string, certs D) any {
	if f := attempt(func() { e.Call(D{"op": "sync", "authorized": keys}, "carrel-jump") }); f != nil {
		slog.Error("jump_sync_failed", "event", "jump_sync_failed")
		return "unavailable"
	}
	if f := attempt(func() { e.Call(D{"op": "certs", "certs": certs}, "carrel-jump") }); f != nil {
		slog.Error("jump_certs_failed", "event", "jump_certs_failed")
		return "keys_only"
	}
	return "synced"
}
