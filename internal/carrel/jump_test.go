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

func TestJumpCertificatesOpenWhatTheMembersKeysOpen(t *testing.T) {
	p, _ := fixture(t)
	ca := "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTY="
	if jumpCertificates(p.Store, "") != nil {
		t.Fatal("a site without a CA sent a map")
	}
	// Alice's key sits in her own tenant and in the shared project.
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAliceAliceAliceAliceAliceAliceAliceAlice"
	p.Store.Put("keys", "1-k", 1, D{"id": "k", "key": key})
	p.Store.Put("keys", "3-k", 3, D{"id": "k", "key": key})
	own := seedMachine(p, "own", 10100)
	own["ssh_user_ca"], own["ca_principals"] = ca, []any{"alice"}
	own["ca_grants"] = []D{{"username": "bob", "by": "alice", "at": 1.0}}
	p.Store.Put("machines", 10100, 1, own)
	p.Store.Put("machines", 10300, 3, D{"name": "site", "vmid": 10300, "tenant_n": 3, "ip": "10.200.3.10", "state": "ready", "service_ports": []any{80}})
	p.Store.Put("machines", 10301, 3, D{"name": "db", "vmid": 10301, "tenant_n": 3, "ip": "10.200.3.11", "state": "ready"})
	robotics := D{"name": "lab", "vmid": 10200, "tenant_n": 2, "ip": "10.200.2.10", "state": "ready", "ssh_user_ca": ca, "ca_principals": []any{"project:robotics"}}
	p.Store.Put("machines", 10200, 2, robotics)
	// Bob's username is not recorded, so his own machine is not in the map.
	gone := merge(robotics, D{"name": "gone", "vmid": 10201, "ip": "10.200.2.11", "state": "deleting", "ca_principals": []any{"project:gone"}})
	p.Store.Put("machines", 10201, 2, gone)
	e := p.execution(context.Background())
	e.rememberUsername(person("alice", false))
	e.rememberUsername(person("carol", false))
	got := jumpCertificates(p.Store, ca)
	want := D{"ca": ca, "users": []string{"alice"}, "principals": D{
		"alice":            []string{"10.200.1.10:22", "10.200.3.10:80", "10.200.3.11:22"},
		"bob":              []string{"10.200.1.10:22"},
		"project:robotics": []string{"10.200.2.10:22"},
		"project:shared":   []string{"10.200.3.10:80", "10.200.3.11:22"},
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%#v", got)
	}
	// A username two accounts claim vouches for neither.
	p.Store.SitePut("usernames", "user:bob", D{"username": "alice"})
	if users := jumpCertificates(p.Store, ca)["users"]; len(users.([]string)) != 0 {
		t.Fatal(users)
	}
	// A suspended tenant's machines take no certificate through the jump host.
	p.Store.Exec("UPDATE tenants SET status='suspended' WHERE n=2")
	if _, ok := obj(jumpCertificates(p.Store, ca)["principals"])["project:robotics"]; ok {
		t.Fatal("suspended tenant still reachable")
	}
}

func TestEveryCallRecordsTheUsernameOfItsPersonalTenant(t *testing.T) {
	p, _ := fixture(t)
	e := p.execution(context.Background())
	e.Register(person("alice", false), "", false)
	if r := p.Store.SiteGet("usernames", "user:alice"); r == nil || r["username"] != "alice" {
		t.Fatal(r)
	}
	// A renamed account keeps its tenant and takes the new name.
	e.Register(D{"sub": "alice", "username": "alice.c", "projects": []string{}}, "", false)
	if r := p.Store.SiteGet("usernames", "user:alice"); r["username"] != "alice.c" {
		t.Fatal(r)
	}
	// An account without a personal tenant records nothing.
	e.rememberUsername(person("carol", false))
	if p.Store.SiteGet("usernames", "user:carol") != nil {
		t.Fatal("recorded a username without a tenant")
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
