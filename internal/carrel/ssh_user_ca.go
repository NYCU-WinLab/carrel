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
	out := merge(m, D{"ssh_user_ca": ca, "ca_principals": []any{principal}, "ca_sync": "pull"})
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
	owner := str(a["owner"])
	if owner != "" && (!portalUsername.MatchString(owner) || contains(caReserved, owner)) {
		fail("invalid", "owner is a lab member's portal username", D{"recovery": "revise_request"})
	}
	tenants := e.S.Tenants()
	if a["tenant"] != nil {
		t := find(tenants, func(t D) bool { return t["slug"] == a["tenant"] })
		if t == nil {
			fail("not_found", "Tenant not found")
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
			result, message := e.backfillOne(t, m, owner, ca, dry)
			results = append(results, D{"tenant": t["slug"], "machine": m["name"], "result": result, "message": message})
		}
	}
	counts := D{}
	for _, r := range results {
		counts[str(r["result"])] = integer(counts[str(r["result"])]) + 1
	}
	e.S.Log(str(w["sub"]), nil, "machine_ca_backfill", D{"counts": counts, "dry_run": dry}, "ok")
	return D{"dry_run": dry, "counts": counts, "machines": results}
}

// backfillOne returns "backfilled" (or "would_backfill" on a dry run),
// "skipped" or "failed", with the reason.
func (e *Execution) backfillOne(t, m D, owner, ca string, dry bool) (string, string) {
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
	principal := tenantPrincipal(t, owner)
	if principal == "" {
		return "skipped", "Personal tenant: name the owner's portal username in owner"
	}
	// The slug of a personal tenant is derived from its owner's username at
	// registration, so a mismatch is a wrong tenant or a typo: refuse it
	// rather than let another member in. An aliased tenant cannot pass yet.
	if principal == owner && (!strings.HasPrefix(str(t["subject"]), "user:") || normalizeSlug(owner) != str(t["slug"])) {
		return "skipped", "owner " + owner + " does not own personal tenant " + str(t["slug"])
	}
	var status string
	if err := attempt(func() { status = powerState(obj(e.Call(D{"op": "status", "machine": m}))) }); err != nil {
		return "failed", "Could not read the power state: " + describe(err)
	}
	if status != "stopped" {
		return "skipped", "The VM is " + status + "; stop it first"
	}
	if dry {
		return "would_backfill", "Would trust principal " + principal
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
		tx.S.Put("machines", vmid, n, merge(cur, D{"ssh_user_ca": ca, "ca_principals": []any{principal}, "ca_sync": "pull"}))
	})
	if message != "" {
		return "failed", message
	}
	return "backfilled", "Trusts principal " + principal
}
