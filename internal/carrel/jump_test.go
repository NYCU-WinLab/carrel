package carrel

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
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

func TestAnOlderJumpSyncCannotFollowARevoke(t *testing.T) {
	p, b := fixture(t)
	ca := "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTY="
	p.Config.SSHJump, p.Config.SSHUserCA = true, ca
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAliceAliceAliceAliceAliceAliceAliceAlice"
	m := seedMachine(p, "web", 10100)
	m["ssh_user_ca"], m["ca_principals"] = ca, []any{"alice"}
	m["ca_grants"] = []D{{"username": "bob", "by": "alice", "at": 1.0}}
	p.Store.Put("machines", 10100, 1, m)
	p.Store.Put("keys", "1-k", 1, D{"id": "k", "key": key})
	// The reconcile sync starts with the old state and waits at the jump host.
	started, release := make(chan struct{}), make(chan struct{})
	var mu sync.Mutex
	first := true
	var lastKeys string
	var lastCerts any
	b.call = func(r D, target string) (any, error) {
		if target != "carrel-jump" {
			return D{}, nil
		}
		mu.Lock()
		wait := r["op"] == "sync" && first
		first = false
		mu.Unlock()
		if wait {
			close(started)
			<-release
		}
		mu.Lock()
		defer mu.Unlock()
		switch r["op"] {
		case "sync":
			lastKeys = str(r["authorized"])
		case "certs":
			lastCerts = r["certs"]
		}
		return D{}, nil
	}
	e := p.execution(context.Background())
	reconciled := make(chan struct{})
	go func() { e.Reconcile(); close(reconciled) }()
	<-started
	// The revoke removes the key and the grant, then syncs.
	revoked := make(chan struct{})
	go func() {
		e.S.Remove("keys", "1-k")
		m["ca_grants"] = []D{}
		p.Store.Put("machines", 10100, 1, m)
		e.syncJumpNow()
		close(revoked)
	}()
	time.Sleep(50 * time.Millisecond)
	close(release)
	<-reconciled
	<-revoked
	waitJumpIdle(t, p)
	mu.Lock()
	defer mu.Unlock()
	if strings.Contains(lastKeys, key) {
		t.Fatalf("removed key came back: %q", lastKeys)
	}
	principals := obj(obj(lastCerts)["principals"])
	if _, ok := principals["bob"]; ok {
		t.Fatalf("revoked grant came back: %#v", lastCerts)
	}
}

func TestAFailedJumpReadDoesNotBlockLaterJumpSyncs(t *testing.T) {
	p, b := fixture(t)
	p.Config.SSHJump = true
	b.call = func(r D, target string) (any, error) { return D{}, nil }
	seedMachine(p, "web", 10100)
	// A broken keys row makes the reconcile's jump read panic.
	p.Store.Exec("INSERT INTO objects VALUES('keys','1-bad',1,'{not json')")
	e := p.execution(context.Background())
	if attempt(func() { e.Reconcile() }) == nil {
		t.Fatal("the broken keys row did not fail the reconcile")
	}
	p.Store.Remove("keys", "1-bad")
	e.syncJumpNow()
	waitJumpIdle(t, p)
	if b.count("sync") == 0 {
		t.Fatal("the jump sync never ran after a failed reconcile")
	}
}

// waitJumpIdle waits until the background jump sync has drained.
func waitJumpIdle(t *testing.T, p *Platform) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		p.jumpQueueMu.Lock()
		idle := !p.jumpRunning
		p.jumpQueueMu.Unlock()
		if idle {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the background jump sync did not finish")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestAJumpSyncDoesNotHoldUpTheRequest(t *testing.T) {
	p, b := fixture(t)
	p.Config.SSHJump = true
	seedMachine(p, "web", 10100)
	release := make(chan struct{})
	var mu sync.Mutex
	syncs := 0
	b.call = func(r D, target string) (any, error) {
		if target == "carrel-jump" && r["op"] == "sync" {
			<-release
			mu.Lock()
			syncs++
			mu.Unlock()
		}
		return D{}, nil
	}
	e := p.execution(context.Background())
	returned := make(chan struct{})
	go func() {
		e.syncJumpNow()
		e.syncJumpNow()
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("syncJumpNow waited for the jump host")
	}
	mu.Lock()
	if syncs != 0 {
		t.Fatal("the backend answered before it was released")
	}
	mu.Unlock()
	close(release)
	waitJumpIdle(t, p)
	mu.Lock()
	defer mu.Unlock()
	// The two asks coalesce: at most one running pass and one follow-up.
	if syncs < 1 || syncs > 2 {
		t.Fatalf("expected the sync to arrive once or twice, got %d", syncs)
	}
}

func TestAJumpRevokeCommittedDuringASendIsPushedOnce(t *testing.T) {
	p, b := fixture(t)
	p.Config.SSHJump = true
	const key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJumpRevokeTestKey"
	m := seedMachine(p, "web", 10100)
	m["ssh_keys"] = []string{key}
	p.Store.Put("machines", 10100, 1, m)
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	var once sync.Once
	var mu sync.Mutex
	var sent []string
	b.call = func(r D, target string) (any, error) {
		if target == "carrel-jump" && r["op"] == "sync" {
			first := false
			once.Do(func() { first = true })
			if first {
				entered <- struct{}{}
				<-release
			}
			mu.Lock()
			sent = append(sent, str(r["authorized"]))
			mu.Unlock()
		}
		return D{}, nil
	}
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	e := p.execution(context.Background())
	e.syncJumpNow()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("the first send never reached the backend")
	}
	m["ssh_keys"] = []string{}
	p.Store.Put("machines", 10100, 1, m)
	for i := 0; i < 5; i++ {
		e.syncJumpNow()
	}
	close(release)
	waitJumpIdle(t, p)
	mu.Lock()
	defer mu.Unlock()
	if len(sent) != 2 {
		t.Fatalf("expected the blocked send and one follow-up, got %d", len(sent))
	}
	if !strings.Contains(sent[0], "AAAAC3NzaC1lZDI1NTE5AAAAIJumpRevokeTestKey") {
		t.Fatal("the first send did not carry the key")
	}
	if sent[1] != "" {
		t.Fatalf("the follow-up still carries the revoked key: %q", sent[1])
	}
}

func TestAJumpAskAfterCloseStartsNoWorker(t *testing.T) {
	p, b := fixture(t)
	p.Config.SSHJump = true
	seedMachine(p, "web", 10100)
	e := p.execution(context.Background())
	p.Close()
	e.syncJumpNow()
	if p.jumpRunning || b.count("sync") != 0 {
		t.Fatal("a jump worker started after Close")
	}
}
