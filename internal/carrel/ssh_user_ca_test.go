package carrel

import (
	"context"
	"testing"
)

const userCATestKey = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEypPi2eUS00sJeJA9ebfrquCmA8reWrgdWSL4yGkfm4bKEuRyPmVJoM72JdUwzhH/v3VWkAkfPQ6sxMtzgruck="

func TestANewMachineTrustsTheLabCAForItsCreator(t *testing.T) {
	p, _ := fixture(t)
	ctx := context.Background()
	alice := person("alice", false)
	e := p.execution(ctx)
	tenant := p.Store.Tenant("user:alice")
	spec := func(a D) D {
		return e.MachineSpec(tenant, e.withCAPrincipal("machine_create", e.withPortalKeys("machine_create", a, alice), alice), false)
	}
	key := []any{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIInlineKeyInTheRequest"}

	// No CA configured: the machine is unchanged.
	if m := spec(D{"name": "box", "ssh_keys": key}); m["ssh_user_ca"] != nil || m["ca_principals"] != nil {
		t.Fatalf("CA without configuration: %s", encoded(m))
	}

	p.Config.SSHUserCA = userCATestKey
	m := spec(D{"name": "box", "ssh_keys": key})
	if m["ssh_user_ca"] != userCATestKey || !equal(m["ca_principals"], []any{"alice"}) {
		t.Fatalf("machine: %s", encoded(m))
	}
	// Keys stay: the CA is in addition to them.
	if !equal(m["ssh_keys"], key) {
		t.Fatalf("keys: %s", encoded(m["ssh_keys"]))
	}
	// A caller cannot name the principal: the creator's username wins.
	if m := spec(D{"name": "box", "ssh_keys": key, "ca_principal": "root"}); !equal(m["ca_principals"], []any{"alice"}) {
		t.Fatalf("forged principal: %s", encoded(m["ca_principals"]))
	}
	// Every machine of a deployment gets the creator.
	d := e.withCAPrincipal("deployment_apply", e.withPortalKeys("deployment_apply", D{"machines": []any{D{"name": "a", "ca_principal": "root"}, D{"name": "b"}}}, alice), alice)
	for _, m := range dicts(d["machines"]) {
		if m["ca_principal"] != "alice" {
			t.Fatalf("deployment: %s", encoded(d))
		}
	}
	// A username the CA would not sign gets no principal.
	if a := e.withCAPrincipal("machine_create", D{"name": "box"}, D{"username": "Bad Name"}); a["ca_principal"] != nil {
		t.Fatalf("bad username: %s", encoded(a))
	}
	// Other tools pass through.
	if a := e.withCAPrincipal("machine_get", D{"machine": "box"}, alice); !equal(a, D{"machine": "box"}) {
		t.Fatalf("machine_get: %s", encoded(a))
	}
}

func TestSSHUserCAMustBeOneKey(t *testing.T) {
	for _, bad := range []string{"not a key", userCATestKey + " comment", userCATestKey + "\nssh-ed25519 AAAA", "cert-authority " + userCATestKey} {
		if sshUserCA.MatchString(bad) {
			t.Fatalf("accepted %q", bad)
		}
	}
	if !sshUserCA.MatchString(userCATestKey) {
		t.Fatal("rejected the lab CA")
	}
}

func TestCAPrincipalStaysOutOfTheFingerprint(t *testing.T) {
	got := withoutPortalKeys(D{"name": "box", "ca_principal": "alice"})
	if string(encoded(got)) != `{"name":"box"}` {
		t.Fatal(string(encoded(got)))
	}
}
