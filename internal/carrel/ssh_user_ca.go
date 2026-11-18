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

// withSSHUserCA adds the lab CA and the creator's principal to a machine that
// boots a managed image with SSH. ISO installs and images that serve their
// own ports have no sshd Carrel configures.
func (e *Execution) withSSHUserCA(m, a D) D {
	ca, principal := e.P.Config.SSHUserCA, str(a["ca_principal"])
	if ca == "" || !portalUsername.MatchString(principal) || len(arr(m["service_ports"])) > 0 {
		return m
	}
	return merge(m, D{"ssh_user_ca": ca, "ca_principals": []any{principal}})
}
