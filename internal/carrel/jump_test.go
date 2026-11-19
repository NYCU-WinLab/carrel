package carrel

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestJumpKeysOpenOnlyTheirTenantsMachines(t *testing.T) {
	p, _ := fixture(t)
	alice, bob := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAliceAliceAliceAliceAliceAliceAliceAlice", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBobBobBobBobBobBobBobBobBobBobBobBobBob"
	web := seedMachine(p, "web", 10100)
	web["ssh_keys"] = []any{alice + " alice@laptop,command=\"sh\""}
	p.Store.Put("machines", 10100, 1, web)
	p.Store.Put("keys", "2-k", 2, D{"id": "k", "key": bob})
	other := D{"name": "box", "vmid": 10200, "tenant_n": 2, "ip": "10.200.2.10", "state": "ready", "ssh_keys": []any{bob, "not a key"}}
	p.Store.Put("machines", 10200, 2, other)
	text := jumpAuthorizedKeys(p.Store)
	want := "restrict,port-forwarding,command=\"/usr/sbin/nologin\",permitopen=\"10.200.1.10:22\" " + alice + "\n" +
		"restrict,port-forwarding,command=\"/usr/sbin/nologin\",permitopen=\"10.200.2.10:22\" " + bob + "\n"
	if text != want {
		t.Fatalf("%q", text)
	}
	// A suspended tenant's keys open nothing.
	p.Store.Exec("UPDATE tenants SET status='suspended' WHERE n=2")
	if strings.Contains(jumpAuthorizedKeys(p.Store), "10.200.2.10") {
		t.Fatal("suspended tenant still reachable")
	}
}

func TestAMachineWithoutAPublicPortConnectsThroughTheJumpHost(t *testing.T) {
	p, _ := fixture(t)
	p.Config.SSHJump = true
	m := seedMachine(p, "web", 10100)
	e := p.execution(context.Background())
	pub := e.PublicMachine(m, nil)
	if pub["ssh"] != "ssh -J jump@carrel.winlab.tw user@10.200.1.10" || !strings.Contains(str(pub["ssh_config"]), "ProxyJump jump@carrel.winlab.tw") {
		t.Fatal(pub)
	}
	withPort := e.PublicMachine(m, []portGrant{{VMID: 10100, Port: 22, Proto: "tcp", PublicPort: 20010}})
	if withPort["ssh"] != "ssh -p 20010 user@carrel.winlab.tw" || withPort["ssh_jump"] == nil {
		t.Fatal(withPort)
	}
	// A lab certificate goes through the certificate user, only to a
	// machine that trusts the CA.
	if pub["ssh_jump_certificate"] != nil {
		t.Fatal(pub)
	}
	m["ssh_user_ca"] = "ecdsa-sha2-nistp256 AAAA"
	if got := e.PublicMachine(m, nil)["ssh_jump_certificate"]; got != "ssh -J ca@carrel.winlab.tw user@10.200.1.10" {
		t.Fatal(got)
	}
}

func TestSavedKeysAreBounded(t *testing.T) {
	p, _ := fixture(t)
	ctx, alice := context.Background(), person("alice", false)
	for i := range maxSavedKeys + 1 {
		key := fmt.Sprintf("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI%040d", i)
		r := p.Execute(ctx, "ssh_key_add", D{"key": key}, alice)
		if (i < maxSavedKeys) != (r["ok"] == true) {
			t.Fatalf("key %d: %v", i, r)
		}
	}
}

func TestMachinesWithoutPublicSSHUseNoPort(t *testing.T) {
	p, _ := fixture(t)
	e := p.execution(context.Background())
	tenant := p.Store.TenantN(1)
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAliceAliceAliceAliceAliceAliceAliceAlice"
	spec := D{"name": "hidden", "public_ssh": false, "ssh_keys": []any{key}}
	if f := attempt(func() { e.MachineSpec(tenant, spec, false) }); f == nil {
		t.Fatal("a site without a jump host accepted public_ssh false")
	}
	p.Config.SSHJump = true
	// More machines than the tenant's 10 public ports.
	for i := range 12 {
		s := merge(spec, D{"name": fmt.Sprintf("hidden%d", i)})
		m := e.MachineSpec(tenant, s, false)
		if machineDelta(m)["public_ports"] != 0 {
			t.Fatal("counted a public port")
		}
		m, grant := e.AllocateMachine(tenant, merge(m, D{"node": "carrel01"}))
		if grant.PublicPort != 0 {
			t.Fatal("allocated a port", grant)
		}
		if pub := e.PublicMachine(m, e.ports(1)); !strings.Contains(str(pub["ssh_config"]), "ProxyJump jump@carrel.winlab.tw") {
			t.Fatal(pub)
		}
	}
	if len(e.ports(1)) != 0 {
		t.Fatal("ports were granted")
	}
}

func TestJumpCertificatesMapEachPrincipalToTheMachinesThatLetItIn(t *testing.T) {
	p, _ := fixture(t)
	ca := "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTY="
	if jumpCertificates(p.Store, "") != nil {
		t.Fatal("a site without a CA sent a map")
	}
	own := seedMachine(p, "own", 10100)
	own["ssh_user_ca"], own["ca_principals"] = ca, []any{"alice"}
	own["ca_grants"] = []D{{"username": "bob", "by": "alice", "at": 1.0}}
	p.Store.Put("machines", 10100, 1, own)
	project := D{"name": "lab", "vmid": 10200, "tenant_n": 2, "ip": "10.200.2.10", "state": "ready", "ssh_user_ca": ca, "ca_principals": []any{"project:robotics"}}
	p.Store.Put("machines", 10200, 2, project)
	// Not counted: no CA, another CA, a web image without SSH, being deleted.
	plain := D{"name": "plain", "vmid": 10201, "tenant_n": 2, "ip": "10.200.2.11", "state": "ready", "ca_principals": []any{"alice"}}
	other := merge(plain, D{"name": "other", "vmid": 10202, "ip": "10.200.2.12", "ssh_user_ca": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOther"})
	web := merge(plain, D{"name": "web", "vmid": 10203, "ip": "10.200.2.13", "ssh_user_ca": ca, "service_ports": []any{80}})
	gone := merge(plain, D{"name": "gone", "vmid": 10204, "ip": "10.200.2.14", "ssh_user_ca": ca, "state": "deleting"})
	for _, m := range []D{plain, other, web, gone} {
		p.Store.Put("machines", m["vmid"], 2, m)
	}
	got := jumpCertificates(p.Store, ca)
	want := D{"ca": ca, "principals": D{
		"alice":            []string{"10.200.1.10:22"},
		"bob":              []string{"10.200.1.10:22"},
		"project:robotics": []string{"10.200.2.10:22"},
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%#v", got)
	}
	// A suspended tenant's machines take no certificate through the jump host.
	p.Store.Exec("UPDATE tenants SET status='suspended' WHERE n=2")
	if _, ok := obj(jumpCertificates(p.Store, ca)["principals"])["project:robotics"]; ok {
		t.Fatal("suspended tenant still reachable")
	}
}

func TestSyncJumpAlwaysSendsTheCertificateMapAndKeepsKeysWhenItFails(t *testing.T) {
	p, b := fixture(t)
	e := p.execution(context.Background())
	// No CA: the map still goes, as null, so the jump host drops an old one.
	if r := e.SyncJump("", nil); r != "synced" || b.count("certs") != 1 {
		t.Fatal(r, b.calls)
	}
	if last := b.calls[len(b.calls)-1]; last["certs"] != nil {
		t.Fatal(last)
	}
	// A jump host without certificate support still takes keys.
	b.call = func(r D, _ string) (any, error) {
		if r["op"] == "certs" {
			return nil, fmt.Errorf("unknown operation")
		}
		return D{}, nil
	}
	if r := e.SyncJump("", D{"ca": "x", "principals": D{}}); r != "keys_only" || b.count("sync") != 2 {
		t.Fatal(r)
	}
}
