package carrel

import (
	"regexp"
	"sort"
	"strings"
)

// sshUserCA is one SSH public key with no comment: what Config.SSHUserCA holds.
var sshUserCA = regexp.MustCompile(`^(ssh-ed25519|ecdsa-sha2-nistp(256|384|521)|ssh-rsa) [A-Za-z0-9+/]+={0,2}$`)

// withCAPrincipal puts the caller's Keycloak username beside every machine of
// a creation, read when the call arrived. MachineSpec makes it the one name a
// lab certificate must carry to log in to the new machine. It runs after
// withPortalKeys, which drops any ca_principal the caller sent.
func (e *Execution) withCAPrincipal(tool string, a, w D) D {
	if tool != "machine_create" && tool != "deployment_plan" && tool != "deployment_apply" {
		return a
	}
	username := str(w["username"])
	if e.P.Config.SSHUserCA == "" || !portalUsername.MatchString(username) {
		return a
	}
	if tool == "machine_create" {
		return merge(a, D{"ca_principal": username})
	}
	machines := []any{}
	for _, m := range dicts(a["machines"]) {
		machines = append(machines, merge(m, D{"ca_principal": username}))
	}
	if len(machines) > 0 {
		a["machines"] = machines
	}
	return a
}

// projectTenant is a project tenant's Keycloak subject; its name is the
// shape the lab CA allows in a project:<name> principal.
var projectTenant = regexp.MustCompile(`^winlab-projects/([a-z0-9][a-z0-9-]{0,62})$`)

// tenantPrincipal is the one name a machine of tenant t trusts: project:<name>
// in a project tenant, else the owner's username.
func tenantPrincipal(t D, username string) string {
	if project := projectTenant.FindStringSubmatch(str(t["subject"])); project != nil {
		return "project:" + project[1]
	}
	return username
}

// withSSHUserCA adds the lab CA and one principal to a machine that boots a
// managed image with SSH: project:<name> in a project tenant, so every
// current member of that Keycloak group logs in, else the creator's
// username. ISO installs and images that serve their own ports have no sshd
// Carrel configures.
func (e *Execution) withSSHUserCA(t, m, a D) D {
	ca, principal := e.P.Config.SSHUserCA, str(a["ca_principal"])
	if ca == "" || !portalUsername.MatchString(principal) || len(arr(m["service_ports"])) > 0 {
		return m
	}
	principal = tenantPrincipal(t, principal)
	// How the machine takes later changes of who logs in (machine_access):
	// a VM's guest reporter pulls them, a CT's node pushes them.
	out := merge(m, D{"ssh_user_ca": ca, "ca_principals": []any{principal}, "ca_sync": "pull", "ca_created": true})
	if m["kind"] == "ct" {
		// The node writes the file at creation, so the CT starts with it.
		out["ca_sync"], out["ca_applied"] = "push", []any{principal}
	}
	return out
}

// machine_ca_backfill gives machines created before the lab CA the same trust
// a new one gets. Per VM, never one bulk call, so one bad disk does not block
// the window: the node writes the files into the stopped VM's disk first, and
// the record changes only after that succeeded, so a failure leaves the VM
// looking old and a second run retries it.

// CABackfill runs over one machine (machine set) or every VM of one tenant or
// of all tenants, one at a time, and reports each VM. A personal tenant does
// not record its owner's portal username (the slug is a lossy form of it), so
// the caller names it in owner; a project tenant needs none.
func (e *Execution) CABackfill(a, w D) D {
	dry, ca := boolean(a["dry_run"]), e.P.Config.SSHUserCA
	if ca == "" {
		fail("invalid", "No SSH user CA is configured", D{"recovery": "resolve_prerequisite"})
	}
	owner, alias := str(a["owner"]), boolean(a["alias_confirmed"])
	if alias && (a["tenant"] == nil || owner == "") {
		fail("invalid", "alias_confirmed needs tenant and owner", D{"recovery": "revise_request"})
	}
	if owner != "" && (!portalUsername.MatchString(owner) || contains(caReserved, owner)) {
		fail("invalid", "owner is a lab member's portal username", D{"recovery": "revise_request"})
	}
	tenants := e.S.Tenants()
	if a["tenant"] != nil {
		t := find(tenants, func(t D) bool { return t["slug"] == a["tenant"] })
		if t == nil {
			fail("not_found", "Tenant not found")
		}
		if alias && !strings.HasPrefix(str(t["subject"]), "user:") {
			fail("invalid", "alias_confirmed is only for a personal tenant; a project tenant uses project:<name>", D{"recovery": "revise_request"})
		}
		tenants = []D{t}
	} else if a["machine"] != nil || owner != "" {
		fail("invalid", "machine and owner need a tenant", D{"recovery": "revise_request"})
	}
	results := []D{}
	for _, t := range tenants {
		machines := e.S.Objects("machines", integer(t["n"]))
		if a["machine"] != nil {
			machines = []D{e.Machine(t, a["machine"])}
		}
		sort.SliceStable(machines, func(i, j int) bool { return integer(machines[i]["vmid"]) < integer(machines[j]["vmid"]) })
		for _, m := range machines {
			result, message := e.backfillOne(t, m, owner, ca, dry, alias)
			results = append(results, D{"tenant": t["slug"], "machine": m["name"], "result": result, "message": message})
		}
	}
	counts := D{}
	for _, r := range results {
		counts[str(r["result"])] = integer(counts[str(r["result"])]) + 1
	}
	e.S.Log(str(w["sub"]), nil, "machine_ca_backfill", D{"counts": counts, "dry_run": dry, "alias_confirmed": alias}, "ok")
	return D{"dry_run": dry, "counts": counts, "machines": results}
}

// backfillOne returns "backfilled" (or "would_backfill" on a dry run),
// "skipped" or "failed", with the reason.
func (e *Execution) backfillOne(t, m D, owner, ca string, dry, alias bool) (string, string) {
	n, vmid := integer(t["n"]), m["vmid"]
	switch {
	case m["kind"] != "vm":
		return "skipped", "Not a VM: a CT gets the CA when it is created"
	case str(m["ssh_user_ca"]) != "":
		return "skipped", "Already trusts the lab CA"
	case m["iso"] != nil:
		return "skipped", "ISO install: no sshd Carrel configures"
	case len(arr(m["service_ports"])) > 0:
		return "skipped", "Serves its own ports: no sshd Carrel configures"
	case m["state"] != "ready" && m["state"] != "stopped":
		return "skipped", "The machine is " + str(m["state"]) + "; backfill once it is ready or stopped"
	case e.machineBusy(n, m):
		return "skipped", "An operation on this machine is queued or running; backfill once it has finished"
	}
	for _, s := range e.snapshots(n) {
		if s.VMID == integer(vmid) {
			return "skipped", "Has snapshots: delete them first, a rollback would undo the backfill"
		}
	}
	principal := tenantPrincipal(t, owner)
	if principal == "" {
		return "skipped", "Personal tenant: name the owner's portal username in owner"
	}
	// The slug of a personal tenant is derived from its owner's username at
	// registration, so a mismatch is a wrong tenant or a typo: refuse it
	// rather than let another member in. Usernames that differ only in . _ -
	// share a slug, so a lossless record, when the tenant has one, decides.
	// A tenant whose slug an administrator assigned fails the slug check;
	// alias_confirmed lets the admin vouch for owner instead, and a recorded
	// username that contradicts it still refuses.
	checked := ""
	if principal == owner {
		if !strings.HasPrefix(str(t["subject"]), "user:") {
			return "skipped", "owner " + owner + " does not own personal tenant " + str(t["slug"])
		}
		if normalizeSlug(owner) != str(t["slug"]) && !alias {
			return "skipped", "owner " + owner + " does not own personal tenant " + str(t["slug"]) + "; if an administrator assigned the slug, confirm with alias_confirmed"
		}
		if recorded := e.recordedUsernames(t); len(recorded) > 0 {
			if !contains(recorded, owner) {
				return "skipped", "owner " + owner + " does not match the usernames recorded for personal tenant " + str(t["slug"]) + " (" + strings.Join(recorded, ", ") + ")"
			}
			checked = "; owner checked against recorded usernames " + strings.Join(recorded, ", ")
		} else {
			// No record: the slug is lossy, the Keycloak sub is not. Fail
			// closed when the lookup is unavailable or disagrees.
			sub, err := e.keycloakSub(owner)
			if err != nil {
				return "skipped", "No username record and the owner's Keycloak sub could not be looked up (" + describe(err) + "); not backfilled"
			}
			if "user:"+sub != str(t["subject"]) {
				return "skipped", "owner " + owner + " does not match the Keycloak sub of personal tenant " + str(t["slug"])
			}
			checked = "; owner checked against Keycloak sub"
		}
	}
	var status string
	if err := attempt(func() { status = powerState(obj(e.Call(D{"op": "status", "machine": m}))) }); err != nil {
		return "failed", "Could not read the power state: " + describe(err)
	}
	if status != "stopped" {
		return "skipped", "The VM is " + status + "; stop it first"
	}
	if dry {
		return "would_backfill", "Would trust principal " + principal + checked
	}
	planned := merge(m, D{"ssh_user_ca": ca, "ca_principals": []any{principal}, "ca_sync": "pull"})
	if err := attempt(func() { e.Call(D{"op": "ca_backfill", "machine": planned}) }); err != nil {
		return "failed", "The node did not write the CA; the record is unchanged: " + describe(err)
	}
	var message string
	e.Transaction(func(tx *Execution) {
		cur := tx.S.Get("machines", str(vmid))
		if cur == nil || str(cur["ssh_user_ca"]) != "" {
			message = "The record changed meanwhile; nothing saved"
			return
		}
		tx.S.Put("machines", vmid, n, merge(cur, D{"ssh_user_ca": ca, "ca_principals": []any{principal}, "ca_sync": "pull", "ca_backfilled": true}))
	})
	if message != "" {
		return "failed", message
	}
	return "backfilled", "Trusts principal " + principal + checked
}

// recordedUsernames are the lossless portal usernames a tenant recorded: the
// by of its saved keys and the ca_principals of its VMs created with the CA,
// live or frozen. A backfilled VM has a principal that came from a caller's
// say-so, and one backfilled before the ca_backfilled flag existed cannot be
// told apart from a CA-created one by its CA fields, so a machine with ca_sync
// counts only with the ca_created marker. Every backfill wrote ca_sync, so a
// VM created with the CA before ca_sync existed still counts without it.
func (e *Execution) recordedUsernames(t D) []string {
	n, seen, out := integer(t["n"]), map[string]bool{}, []string{}
	add := func(name string) {
		if portalUsername.MatchString(name) && !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	for _, k := range rowsOf[sshKey](e.S, "keys", n) {
		add(k.By)
	}
	for _, m := range append(e.S.Objects("machines", n), e.S.Objects("frozen", n)...) {
		if str(m["ssh_user_ca"]) == "" || boolean(m["ca_backfilled"]) || (str(m["ca_sync"]) != "" && !boolean(m["ca_created"])) {
			continue
		}
		for _, p := range arr(m["ca_principals"]) {
			add(str(p))
		}
	}
	sort.Strings(out)
	return out
}
