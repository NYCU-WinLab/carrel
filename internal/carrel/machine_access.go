package carrel

import (
	"regexp"
	"sort"
)

// machine_access lets a machine's tenant name other people who may log in
// with a lab certificate. A grant is a portal username: the certificate
// already carries it, so a grant needs no new certificate and a revocation
// takes effect at the next login after the machine's principals file
// changes. The file is the creator's or project's principal followed by the
// grants.
//
// A VM created with the lab CA pulls the file through its guest report every
// 15 seconds (scripts/guest-report.py); a CT gets it from its node (pct push)
// when the grants change. Machines created before Carrel recorded how they
// sync (ca_sync) have no puller, so they cannot take grants.

// caPrincipal is the shape of a line in a principals file: a username or a
// project group. The node agent and the guest reporter check the same.
var caPrincipal = regexp.MustCompile(`^([a-z0-9][a-z0-9._-]{0,63}|project:[a-z0-9][a-z0-9-]{0,62})$`)

// caReserved are account names the lab CA never signs for a member
// (portal /api/ssh-ca/authorize), so a grant to one could never log in.
var caReserved = []string{"root", "admin", "administrator", "ubuntu", "debian", "user", "p4user", "git", "nobody", "daemon", "bin", "sys", "www-data", "postgres", "docker", "sshd", "operator", "provisioner", "test"}

const maxCAGrants = 50

type caGrant struct {
	Username string  `json:"username"`
	By       string  `json:"by"`
	At       float64 `json:"at"`
}

func caGrantsOf(m D) []caGrant {
	var out []caGrant
	for _, g := range dicts(m["ca_grants"]) {
		out = append(out, caGrant{Username: str(g["username"]), By: str(g["by"]), At: num(g["at"])})
	}
	return out
}

// caPrincipals is a machine's whole principals file: its own principal
// first, then the grants in the order they were made.
func caPrincipals(m D) []any {
	out := append([]any{}, arr(m["ca_principals"])...)
	for _, g := range caGrantsOf(m) {
		out = append(out, g.Username)
	}
	return out
}

// caAccess is what machine_get and machine_access show: who may log in with
// a certificate and whether the machine has the current list.
func (e *Execution) caAccess(m D) D {
	if str(m["ssh_user_ca"]) == "" {
		return nil
	}
	grants := []D{}
	for _, g := range caGrantsOf(m) {
		grants = append(grants, D{"username": g.Username, "by": g.By, "at": g.At})
	}
	out := D{"principal": first(arr(m["ca_principals"])), "grants": grants}
	want := caPrincipals(m)
	switch str(m["ca_sync"]) {
	case "pull":
		// Only a report made after the last change counts: an older one may
		// show a list the VM has since replaced.
		r := e.S.guestReport(m["vmid"])
		if equal(r.Principals, want) && r.ReportedAt != nil && *r.ReportedAt > num(m["ca_changed_at"]) {
			out["applied"] = "applied"
		} else {
			out["applied"] = "pending"
			out["applied_detail"] = "The VM takes the list within 15 seconds while it runs."
		}
	case "push":
		if equal(m["ca_applied"], want) {
			out["applied"] = "applied"
		} else {
			out["applied"] = "pending"
		}
	default:
		out["applied"] = "unsupported"
		out["applied_detail"] = "This machine was created before Carrel could change who logs in: add a username to /etc/ssh/principals/ on the machine by hand, or recreate it."
	}
	return out
}

func first(xs []any) any {
	if len(xs) == 0 {
		return nil
	}
	return xs[0]
}

// MachineAccess grants or revokes certificate logins on one machine.
func (e *Execution) MachineAccess(a, w, t D) D {
	dry, n := boolean(a["dry_run"]), integer(t["n"])
	m := e.Machine(t, a["machine"])
	if str(m["ssh_user_ca"]) == "" {
		fail("invalid", "This machine does not trust the lab CA: it boots from an ISO, serves its own ports, or was created before Carrel set the CA up", D{"recovery": "revise_request"})
	}
	grant, revoke := arr(a["grant"]), arr(a["revoke"])
	if len(grant) == 0 && len(revoke) == 0 {
		return D{"machine": m["name"], "access": e.caAccess(m), "dry_run": dry}
	}
	if str(m["ca_sync"]) == "" {
		fail("invalid", "This machine was created before Carrel could change who logs in; add the username to its principals file by hand, or recreate it", D{"recovery": "revise_request"})
	}
	if state := str(m["state"]); state != "ready" {
		fail("conflict", "The machine is "+state+"; change access once it is ready", D{"recovery": "resolve_prerequisite"})
	}
	for _, v := range grant {
		if contains(revoke, v) {
			fail("invalid", "A username is in both grant and revoke", D{"recovery": "revise_request", "username": v})
		}
	}
	grants := caGrantsOf(m)
	has := func(u string) int {
		for i, g := range grants {
			if g.Username == u {
				return i
			}
		}
		return -1
	}
	for _, v := range revoke {
		if i := has(str(v)); i >= 0 {
			grants = append(grants[:i], grants[i+1:]...)
		}
	}
	by := str(w["username"])
	for _, v := range grant {
		u := str(v)
		if !portalUsername.MatchString(u) || contains(caReserved, u) {
			fail("invalid", "Grant a lab member by their portal username", D{"recovery": "revise_request", "username": u})
		}
		if contains(arr(m["ca_principals"]), u) || has(u) >= 0 {
			continue
		}
		grants = append(grants, caGrant{Username: u, By: by, At: now()})
	}
	if len(grants) > maxCAGrants {
		fail("invalid", "A machine takes at most 50 grants; use a project tenant for a group", D{"recovery": "revise_request"})
	}
	sort.SliceStable(grants, func(i, j int) bool { return grants[i].At < grants[j].At })
	stored := []any{}
	for _, g := range grants {
		stored = append(stored, D{"username": g.Username, "by": g.By, "at": g.At})
	}
	planned := merge(m, D{"ca_grants": stored})
	if dry {
		return D{"machine": m["name"], "access": e.caAccess(planned), "dry_run": true}
	}
	if m["ca_sync"] == "push" {
		// Pending is saved before the node is asked: a push whose answer is
		// lost may have changed the CT, so the old list is no longer known
		// to be there.
		e.Transaction(func(tx *Execution) {
			cur := tx.Machine(t, a["machine"])
			if cur["vmid"] != m["vmid"] || !equal(cur["ca_grants"], m["ca_grants"]) {
				fail("conflict", "Access to this machine changed meanwhile; try again", D{"recovery": "retry"})
			}
			cur["ca_applied"], cur["ca_changed_at"] = nil, now()
			tx.S.Put("machines", cur["vmid"], n, cur)
			m = cur
		})
		applied := false
		err := attempt(func() {
			applied = str(obj(e.Call(D{"op": "action", "machine": m, "action": "principals", "principals": caPrincipals(planned)}))["state"]) == "applied"
		})
		if err != nil || !applied {
			// Put the recorded list back; it stays pending if that fails too.
			e.caRestored(m, true)
			e.S.Put("machines", m["vmid"], n, m)
			fail("unavailable", "The CT did not take the new list; is it running?", D{"recovery": "resolve_prerequisite"})
		}
		planned["ca_applied"] = caPrincipals(planned)
	}
	e.Transaction(func(tx *Execution) {
		cur := tx.Machine(t, a["machine"])
		if cur["vmid"] != m["vmid"] || !equal(cur["ca_grants"], m["ca_grants"]) {
			fail("conflict", "Access to this machine changed meanwhile; try again", D{"recovery": "retry"})
		}
		cur["ca_grants"], cur["ca_applied"], cur["ca_changed_at"] = planned["ca_grants"], planned["ca_applied"], now()
		tx.S.Put("machines", cur["vmid"], n, cur)
		m = cur
	})
	names := []any{}
	for _, g := range caGrantsOf(m) {
		names = append(names, g.Username)
	}
	e.S.Log(by, n, "machine_access", D{"vmid": m["vmid"], "grant": grant, "revoke": revoke, "grants": names}, "ok")
	return D{"machine": m["name"], "access": e.caAccess(m), "dry_run": false}
}

// caRestored is called when a machine's disk may hold an older principals
// file (snapshot rollback, start): a VM's next report must show the current
// list again, and a running CT gets it pushed now. A CT that cannot take it
// stays pending.
func (e *Execution) caRestored(m D, running bool) {
	if m["ca_sync"] == nil {
		return
	}
	m["ca_changed_at"] = now()
	if m["ca_sync"] != "push" {
		return
	}
	want := caPrincipals(m)
	m["ca_applied"] = nil
	if !running {
		return
	}
	if attempt(func() {
		if str(obj(e.Call(D{"op": "action", "machine": m, "action": "principals", "principals": want}))["state"]) == "applied" {
			m["ca_applied"] = want
		}
	}) != nil {
		e.S.Log("system", integer(m["tenant_n"]), "machine_access_restore_failed", D{"vmid": m["vmid"]}, "failed")
	}
}

// guestPrincipals checks the principals a guest says its file holds.
func guestPrincipals(v any) []any {
	xs, ok := v.([]any)
	if !ok || len(xs) > maxCAGrants+1 {
		return nil
	}
	for _, x := range xs {
		if s, ok := x.(string); !ok || !caPrincipal.MatchString(s) {
			return nil
		}
	}
	return xs
}
