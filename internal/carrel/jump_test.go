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
	if r := e.SyncJump("", nil, 1); r != "synced" || b.count("certs") != 1 {
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
	if r := e.SyncJump("", D{"ca": "x", "principals": D{}}, 1); r != "keys_only" || b.count("sync") != 2 {
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
	waitFor(t, started, "the reconcile sync did not reach the jump host")
	// The revoke removes the key and the grant, then syncs.
	revoked := make(chan struct{})
	go func() {
		e.S.Remove("keys", "1-k")
		m["ca_grants"] = []D{}
		p.Store.Put("machines", 10100, 1, m)
		e.syncJumpNow()
		close(revoked)
	}()
	// The worker has taken its ask and is on its way to jumpMu, which the
	// reconcile sync still holds. Without the lock it would finish here.
	waitJumpWorkerClaimed(t, p)
	waitFor(t, revoked, "the revoke did not return")
	close(release)
	waitFor(t, reconciled, "the reconcile did not finish")
	waitJumpIdle(t, p)
	mu.Lock()
	defer mu.Unlock()
	if strings.Contains(lastKeys, key) {
		t.Fatalf("removed key came back: %q", lastKeys)
	}
	if lastCerts == nil {
		t.Fatal("no certificate map was sent")
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
func waitFor(t *testing.T, ch <-chan struct{}, msg string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal(msg)
	}
}

// waitJumpWorkerClaimed waits until the background worker runs and has taken
// its pending ask, so it is past the queue and heading for jumpMu.
func waitJumpWorkerClaimed(t *testing.T, p *Platform) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		p.jumpQueueMu.Lock()
		claimed := p.jumpRunning && !p.jumpPending
		p.jumpQueueMu.Unlock()
		if claimed {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the background jump worker did not start")
		}
		time.Sleep(time.Millisecond)
	}
}

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

func TestAJumpAskWhileCloseWaitsOnABlockedSendStartsNoWorker(t *testing.T) {
	p, b := fixture(t)
	p.Config.SSHJump = true
	seedMachine(p, "web", 10100)
	started := make(chan struct{}, 4)
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	// A failed assertion must not leave the send blocked under Close.
	t.Cleanup(unblock)
	b.call = func(r D, target string) (any, error) {
		if target == "carrel-jump" && r["op"] == "sync" {
			started <- struct{}{}
			<-release
		}
		return D{}, nil
	}
	e := p.execution(context.Background())
	e.syncJumpNow()
	waitFor(t, started, "the first jump send did not start")
	closed := make(chan struct{})
	go func() {
		p.Close()
		close(closed)
	}()
	// Close must shut the queue before it waits, so jumpClosed turns true
	// while the blocked send still holds Wait.
	deadline := time.Now().Add(5 * time.Second)
	for {
		p.jumpQueueMu.Lock()
		shut := p.jumpClosed
		p.jumpQueueMu.Unlock()
		if shut {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Close did not close the jump queue before waiting")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case <-closed:
		t.Fatal("Close returned while a jump send was blocked")
	default:
	}
	e.syncJumpNow()
	p.jumpQueueMu.Lock()
	pending := p.jumpPending
	p.jumpQueueMu.Unlock()
	if pending {
		t.Fatal("an ask during Close was queued")
	}
	unblock()
	waitFor(t, closed, "Close did not return after the send was released")
	if n := b.count("sync"); n != 1 {
		t.Fatalf("expected the one blocked send, got %d", n)
	}
	select {
	case <-started:
		t.Fatal("a second jump send started")
	default:
	}
}

func TestReconcileWithDeferredJumpDoesNotPushJump(t *testing.T) {
	p, b := fixture(t)
	p.Config.SSHJump = true
	var mu sync.Mutex
	pushes := 0
	b.call = func(r D, target string) (any, error) {
		if target == "carrel-jump" && r["op"] == "sync" {
			mu.Lock()
			pushes++
			mu.Unlock()
		}
		return D{}, nil
	}
	count := func() int { mu.Lock(); defer mu.Unlock(); return pushes }
	seedMachine(p, "web", 10100)
	e := p.execution(context.Background())
	e.deferJump = true
	e.Reconcile()
	if n := count(); n != 0 {
		t.Fatalf("reconcile pushed the jump state under the writer: %d syncs", n)
	}
	e.syncJumpNow()
	waitJumpIdle(t, p)
	if count() == 0 {
		t.Fatal("the deferred jump push never ran")
	}
}

func TestKeyToolsReportAPendingJumpSyncWithoutWaiting(t *testing.T) {
	p, b := fixture(t)
	p.Config.SSHJump = true
	release := make(chan struct{})
	var once sync.Once
	open := func() { once.Do(func() { close(release) }) }
	t.Cleanup(open)
	b.call = func(r D, target string) (any, error) {
		if target == "carrel-jump" && r["op"] == "sync" {
			<-release
		}
		return D{}, nil
	}
	app := NewApp(p, nil)
	alice := groupMember("alice")
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAliceAliceAliceAliceAliceAliceAliceAlic"
	done := make(chan D, 1)
	go func() {
		done <- app.Call(context.Background(), "ssh_key_add", D{"tenant": "shared", "key": key}, alice)
	}()
	var r D
	select {
	case r = <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ssh_key_add waited for the jump host")
	}
	assertOK(t, r)
	if got := r["jump"]; got != "pending" {
		t.Fatalf("jump = %v: %s", got, encoded(r))
	}
	open()
	waitJumpIdle(t, p)
	// Once the host took the change, the field is gone.
	r = app.Call(context.Background(), "ssh_key_remove", D{"tenant": "shared", "id": r["id"]}, alice)
	assertOK(t, r)
	waitJumpIdle(t, p)
	p.jumpQueueMu.Lock()
	last := p.jumpLast
	p.jumpQueueMu.Unlock()
	if last != "synced" || (&Execution{P: p}).jumpStatus() != "" {
		t.Fatalf("last = %q", last)
	}
}

func TestAFailedJumpSyncIsRecordedForLaterReads(t *testing.T) {
	p, b := fixture(t)
	p.Config.SSHJump = true
	b.call = func(r D, target string) (any, error) {
		if target == "carrel-jump" {
			return nil, fmt.Errorf("jump host down")
		}
		return D{}, nil
	}
	e := p.execution(context.Background())
	e.syncJumpNow()
	waitJumpIdle(t, p)
	if got := e.jumpStatus(); got != "unavailable" {
		t.Fatalf("jumpStatus = %q", got)
	}
}

func TestAKeyRemovalDuringShutdownReportsJumpPending(t *testing.T) {
	p, _ := fixture(t)
	p.Config.SSHJump = true
	app := NewApp(p, nil)
	alice := groupMember("alice")
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAliceAliceAliceAliceAliceAliceAliceAlic"
	r := app.Call(context.Background(), "ssh_key_add", D{"tenant": "shared", "key": key}, alice)
	assertOK(t, r)
	waitJumpIdle(t, p)
	p.Close()
	// Close drops the queued sync, so the old key stays on the jump host
	// until the next Start: the result must not read as confirmed.
	r = app.Call(context.Background(), "ssh_key_remove", D{"tenant": "shared", "id": r["id"]}, alice)
	assertOK(t, r)
	if got := r["jump"]; got != "pending" {
		t.Fatalf("jump = %v: %s", got, encoded(r))
	}
}

func TestEachJumpSyncSendsAHigherGenOnBothOps(t *testing.T) {
	p, b := fixture(t)
	e := p.execution(context.Background())
	for i := 0; i < 2; i++ {
		keys, certs, gen := e.lockJumpState()
		e.SyncJump(keys, certs, gen)
		p.jumpMu.Unlock()
	}
	last := map[any]float64{}
	n := 0
	for _, c := range b.calls {
		if c["op"] != "sync" && c["op"] != "certs" {
			continue
		}
		gen, ok := c["gen"].(float64)
		if !ok || gen <= last[c["op"]] {
			t.Fatalf("%v gen %v after %v", c["op"], c["gen"], last[c["op"]])
		}
		last[c["op"]] = gen
		n++
	}
	if n != 4 {
		t.Fatal(n, b.calls)
	}
}

func TestARefusedJumpWriteIsNotReportedAsSynced(t *testing.T) {
	p, b := fixture(t)
	e := p.execution(context.Background())
	for op, want := range map[string]string{"sync": "stale", "certs": "keys_only"} {
		b.call = func(r D, _ string) (any, error) {
			if r["op"] == op {
				return D{"changed": false, "stale": true}, nil
			}
			return D{"changed": true}, nil
		}
		if r := e.SyncJump("", nil, 1); r != want {
			t.Fatal(op, r)
		}
	}
	if b.count("certs") != 1 {
		t.Fatal("certs went after a refused keys write", b.calls)
	}
}

func TestTheStartPushRetriesUntilTheJumpHostTakesIt(t *testing.T) {
	p, b := fixture(t)
	p.Config.SSHJump = true
	p.jumpBackoff, p.jumpBackoffMax = time.Millisecond, 4*time.Millisecond
	var mu sync.Mutex
	fails := 3
	b.call = func(r D, target string) (any, error) {
		mu.Lock()
		defer mu.Unlock()
		if target == "carrel-jump" && fails > 0 {
			fails--
			return nil, fmt.Errorf("jump host down")
		}
		return D{}, nil
	}
	p.execution(context.Background()).syncJumpUntilSynced()
	waitJumpIdle(t, p)
	if got := p.execution(context.Background()).jumpStatus(); got != "" {
		t.Fatalf("jumpStatus = %q", got)
	}
	if n := b.count("sync"); n != 4 {
		t.Fatalf("sync sent %d times, want 3 failures and 1 success", n)
	}
	// Synced once: the retry is over.
	if n := b.count("certs"); n != 1 {
		t.Fatalf("certs sent %d times", n)
	}
	p.jumpQueueMu.Lock()
	retry := p.jumpRetry
	p.jumpQueueMu.Unlock()
	if retry {
		t.Fatal("retry still on after a synced push")
	}
}

func TestCloseEndsTheStartPushRetryWhileItBacksOff(t *testing.T) {
	p, b := fixture(t)
	p.Config.SSHJump = true
	p.jumpBackoff, p.jumpBackoffMax = time.Hour, time.Hour
	b.call = func(r D, target string) (any, error) {
		if target == "carrel-jump" {
			return nil, fmt.Errorf("jump host down")
		}
		return D{}, nil
	}
	p.execution(context.Background()).syncJumpUntilSynced()
	deadline := time.Now().Add(5 * time.Second)
	for b.count("sync") < 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	done := make(chan struct{})
	go func() { p.Close(); close(done) }()
	waitFor(t, done, "Close was held up by the jump retry")
	waitJumpIdle(t, p)
}

func TestSSHKeyRemoveQueuesAJumpSyncWithoutTheKey(t *testing.T) {
	p, b := fixture(t)
	p.Config.SSHJump = true
	app := NewApp(p, nil)
	alice := groupMember("alice")
	const body = "AAAAC3NzaC1lZDI1NTE5AAAAIAliceAliceAliceAliceAliceAliceAliceAlic"
	r := app.Call(context.Background(), "ssh_key_add", D{"tenant": "shared", "key": "ssh-ed25519 " + body}, alice)
	assertOK(t, r)
	waitJumpIdle(t, p)
	m := seedMachine(p, "box", 10100)
	p.Store.Put("machines", 10100, integer(p.Store.Tenant("winlab-projects/shared")["n"]), m)
	b.mu.Lock()
	b.calls = nil
	b.mu.Unlock()
	assertOK(t, app.Call(context.Background(), "ssh_key_remove", D{"tenant": "shared", "id": r["id"]}, alice))
	waitJumpIdle(t, p)
	b.mu.Lock()
	defer b.mu.Unlock()
	syncs := 0
	for _, c := range b.calls {
		if c["op"] == "sync" {
			syncs++
			if strings.Contains(str(c["authorized"]), body) {
				t.Fatalf("the sync still carries the removed key: %q", c["authorized"])
			}
		}
	}
	if syncs == 0 {
		t.Fatal("ssh_key_remove queued no jump sync")
	}
}

func TestMachineAccessRevokeQueuesAJumpCertificateSync(t *testing.T) {
	p, b := fixture(t)
	p.Config.SSHJump = true
	ca := "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTY="
	p.Config.SSHUserCA = ca
	m := seedMachine(p, "box", 10100)
	m["ssh_user_ca"], m["ca_sync"], m["ca_principals"] = ca, "pull", []any{"alice"}
	m["ca_grants"] = []D{{"username": "bob", "by": "alice", "at": 1.0}}
	p.Store.Put("machines", 10100, 1, m)
	b.mu.Lock()
	b.calls = nil
	b.mu.Unlock()
	app := NewApp(p, nil)
	assertOK(t, app.Call(context.Background(), "machine_access", D{"machine": "box", "revoke": []any{"bob"}}, person("alice", false)))
	waitJumpIdle(t, p)
	b.mu.Lock()
	defer b.mu.Unlock()
	certs := 0
	for _, c := range b.calls {
		if c["op"] != "certs" {
			continue
		}
		certs++
		if _, ok := obj(obj(c["certs"])["principals"])["bob"]; ok {
			t.Fatalf("the sync still maps the revoked principal: %v", c)
		}
	}
	if certs == 0 {
		t.Fatal("machine_access queued no jump sync")
	}
}
