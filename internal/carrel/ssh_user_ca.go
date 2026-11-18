package carrel

import "regexp"

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
	if project := projectTenant.FindStringSubmatch(str(t["subject"])); project != nil {
		principal = "project:" + project[1]
	}
	// How the machine takes later changes of who logs in (machine_access):
	// a VM's guest reporter pulls them, a CT's node pushes them.
	sync := "pull"
	if m["kind"] == "ct" {
		sync = "push"
	}
	return merge(m, D{"ssh_user_ca": ca, "ca_principals": []any{principal}, "ca_sync": sync})
}
