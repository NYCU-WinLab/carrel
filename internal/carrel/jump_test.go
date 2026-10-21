package carrel

import (
	"context"
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
	p.Config["ssh_jump"] = true
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
