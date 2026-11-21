package carrel

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
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
	// A project tenant's machine admits the whole project group instead.
	project := merge(tenant, D{"subject": "winlab-projects/iii-edge-ai"})
	a := e.withCAPrincipal("machine_create", e.withPortalKeys("machine_create", D{"name": "proj", "ssh_keys": key}, alice), alice)
	if m := e.MachineSpec(project, a, false); !equal(m["ca_principals"], []any{"project:iii-edge-ai"}) {
		t.Fatalf("project machine: %s", encoded(m["ca_principals"]))
	}
	// A project name the CA would not sign falls back to the creator.
	odd := merge(tenant, D{"subject": "winlab-projects/Odd_Name"})
	if m := e.MachineSpec(odd, a, false); !equal(m["ca_principals"], []any{"alice"}) {
		t.Fatalf("odd project: %s", encoded(m["ca_principals"]))
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

// backfillFixture has stopped, old VMs: a personal one and one in a project tenant.
func backfillFixture(t *testing.T) (*Platform, *fakeBackend, *App) {
	t.Helper()
	p, b := fixture(t)
	p.Config.SSHUserCA = userCATestKey
	keycloak(t, p, `[{"id":"alice","username":"alice"}]`, 200)
	b.call = func(r D, _ string) (any, error) {
		if r["op"] == "status" {
			return D{"status": "stopped"}, nil
		}
		return D{}, nil
	}
	seedMachine(p, "old", 10200)
	shared := seedMachine(p, "proj", 10201)
	n := p.Store.Tenant("winlab-projects/shared")["n"]
	shared["tenant_n"] = n
	p.Store.Exec("UPDATE objects SET tenant=?, data=? WHERE kind='machines' AND id='10201'", n, string(encoded(shared)))
	return p, b, NewApp(p, nil)
}

func storedMachine(p *Platform, vmid int) D {
	return p.Store.Get("machines", str(vmid))
}

func TestBackfillSavesTheRecordOnlyAfterTheNode(t *testing.T) {
	p, b, app := backfillFixture(t)
	ctx, admin := context.Background(), person("root", true)

	// A personal tenant needs the owner named; nothing is written without it.
	r := app.Call(ctx, "machine_ca_backfill", D{"tenant": "alice", "machine": "old"}, admin)
	assertOK(t, r)
	if got := dicts(r["machines"])[0]; got["result"] != "skipped" || storedMachine(p, 10200)["ssh_user_ca"] != nil || b.count("ca_backfill") != 0 {
		t.Fatalf("no owner: %s", encoded(r))
	}

	// A non-admin is refused.
	assertCode(t, app.Call(ctx, "machine_ca_backfill", D{"tenant": "alice", "machine": "old", "owner": "alice"}, person("alice", false)), "forbidden")

	// The node fails: the record stays old and the run can be repeated.
	fail := true
	inner := b.call
	b.call = func(r D, target string) (any, error) {
		if r["op"] == "ca_backfill" && fail {
			return nil, errors.New("qemu-nbd failed")
		}
		return inner(r, target)
	}
	r = app.Call(ctx, "machine_ca_backfill", D{"tenant": "alice", "machine": "old", "owner": "alice"}, admin)
	assertOK(t, r)
	if dicts(r["machines"])[0]["result"] != "failed" || storedMachine(p, 10200)["ssh_user_ca"] != nil || storedMachine(p, 10200)["ca_sync"] != nil {
		t.Fatalf("node failure: %s", encoded(r))
	}

	// Dry run writes nothing and calls no node op.
	r = app.Call(ctx, "machine_ca_backfill", D{"tenant": "alice", "machine": "old", "owner": "alice", "dry_run": true}, admin)
	if dicts(r["machines"])[0]["result"] != "would_backfill" || b.count("ca_backfill") != 1 {
		t.Fatalf("dry run: %s", encoded(r))
	}

	// Success sets the three fields, and the node got them with the machine.
	fail = false
	r = app.Call(ctx, "machine_ca_backfill", D{"tenant": "alice", "machine": "old", "owner": "alice"}, admin)
	assertOK(t, r)
	m := storedMachine(p, 10200)
	if dicts(r["machines"])[0]["result"] != "backfilled" || m["ssh_user_ca"] != userCATestKey || !equal(m["ca_principals"], []any{"alice"}) || m["ca_sync"] != "pull" {
		t.Fatalf("success: %s %s", encoded(r), encoded(m))
	}
	sent := obj(b.calls[len(b.calls)-1]["machine"])
	if b.calls[len(b.calls)-1]["op"] != "ca_backfill" || sent["ssh_user_ca"] != userCATestKey || !equal(sent["ca_principals"], []any{"alice"}) {
		t.Fatalf("node request: %s", encoded(b.calls))
	}

	// machine_access sees a pull-capable VM.
	assertOK(t, app.Call(ctx, "machine_access", D{"machine": "old", "grant": []any{"bob"}}, person("alice", false)))

	// A second run is a no-op.
	before := b.count("ca_backfill")
	r = app.Call(ctx, "machine_ca_backfill", D{"tenant": "alice", "machine": "old", "owner": "alice"}, admin)
	if dicts(r["machines"])[0]["result"] != "skipped" || b.count("ca_backfill") != before {
		t.Fatalf("second run: %s", encoded(r))
	}
}

func TestBackfillSkipsWhatItMust(t *testing.T) {
	p, b, app := backfillFixture(t)
	ctx, admin := context.Background(), person("root", true)
	for vmid, change := range map[int]func(D){
		10210: func(m D) { m["kind"] = "ct" },
		10211: func(m D) { m["iso"] = "debian.iso" },
		10212: func(m D) { m["service_ports"] = []any{22} },
	} {
		m := seedMachine(p, "skip"+str(vmid), vmid)
		change(m)
		p.Store.Put("machines", vmid, 1, m)
	}
	// A running VM is refused.
	inner := b.call
	b.call = func(r D, target string) (any, error) {
		if r["op"] == "status" && obj(r["machine"])["name"] == "old" {
			return D{"status": "running"}, nil
		}
		return inner(r, target)
	}
	// Every VM of a project tenant, then of the personal one, one result each.
	r := app.Call(ctx, "machine_ca_backfill", D{"tenant": "alice", "owner": "alice"}, admin)
	assertOK(t, r)
	got := map[string]string{}
	for _, v := range dicts(r["machines"]) {
		got[str(v["machine"])] = str(v["result"])
	}
	want := map[string]string{"old": "skipped", "skip10210": "skipped", "skip10211": "skipped", "skip10212": "skipped"}
	if !equal(got, want) || b.count("ca_backfill") != 0 {
		t.Fatalf("results: %s", encoded(r))
	}
	if storedMachine(p, 10200)["ssh_user_ca"] != nil {
		t.Fatal("a running VM was changed")
	}
}

func TestBackfillSkipsAVMWithSnapshots(t *testing.T) {
	p, b, app := backfillFixture(t)
	ctx, admin := context.Background(), person("root", true)
	p.Store.Put("snapshots", "10200-before", 1, D{"id": "10200-before", "vmid": 10200, "name": "before", "disk_gb": 20, "state": "ready"})
	for _, dry := range []bool{true, false} {
		r := app.Call(ctx, "machine_ca_backfill", D{"tenant": "alice", "machine": "old", "owner": "alice", "dry_run": dry}, admin)
		got := dicts(r["machines"])[0]
		if got["result"] != "skipped" || !strings.Contains(str(got["message"]), "Has snapshots") || b.count("ca_backfill") != 0 || storedMachine(p, 10200)["ssh_user_ca"] != nil {
			t.Fatalf("dry=%v: %s", dry, encoded(r))
		}
	}
	p.Store.Remove("snapshots", "10200-before")
	r := app.Call(ctx, "machine_ca_backfill", D{"tenant": "alice", "machine": "old", "owner": "alice"}, admin)
	if dicts(r["machines"])[0]["result"] != "backfilled" {
		t.Fatalf("without snapshots: %s", encoded(r))
	}
}

func TestBackfillUsesTheProjectPrincipal(t *testing.T) {
	p, _, app := backfillFixture(t)
	r := app.Call(context.Background(), "machine_ca_backfill", D{"tenant": "shared"}, person("root", true))
	assertOK(t, r)
	m := storedMachine(p, 10201)
	if !equal(m["ca_principals"], []any{"project:shared"}) || m["ca_sync"] != "pull" || m["ssh_user_ca"] != userCATestKey {
		t.Fatalf("project: %s %s", encoded(r), encoded(m))
	}
}

func TestBackfillTakesAVMStoppedTheNormalWay(t *testing.T) {
	p, b, app := backfillFixture(t)
	m := storedMachine(p, 10200)
	m["state"] = "stopped"
	p.Store.Put("machines", 10200, 1, m)
	r := app.Call(context.Background(), "machine_ca_backfill", D{"tenant": "alice", "machine": "old", "owner": "alice"}, person("root", true))
	assertOK(t, r)
	if dicts(r["machines"])[0]["result"] != "backfilled" || b.count("ca_backfill") != 1 || storedMachine(p, 10200)["ssh_user_ca"] != userCATestKey {
		t.Fatalf("stopped: %s", encoded(r))
	}
}

func TestBackfillRefusesAnOwnerOfAnotherTenant(t *testing.T) {
	p, b, app := backfillFixture(t)
	for _, owner := range []string{"bob", "alicee"} {
		r := app.Call(context.Background(), "machine_ca_backfill", D{"tenant": "alice", "machine": "old", "owner": owner}, person("root", true))
		assertOK(t, r)
		if dicts(r["machines"])[0]["result"] != "skipped" || b.count("ca_backfill") != 0 || storedMachine(p, 10200)["ssh_user_ca"] != nil {
			t.Fatalf("owner %s: %s", owner, encoded(r))
		}
	}
}

func TestBackfillSkipsABusyMachine(t *testing.T) {
	p, b, app := backfillFixture(t)
	p.Store.Put("operations", "busy", 1, D{"id": "busy", "tenant_n": 1, "tool": "machine_freeze", "state": "running", "machine_target": D{"vmid": 10200}})
	r := app.Call(context.Background(), "machine_ca_backfill", D{"tenant": "alice", "machine": "old", "owner": "alice"}, person("root", true))
	assertOK(t, r)
	if dicts(r["machines"])[0]["result"] != "skipped" || b.count("ca_backfill") != 0 || storedMachine(p, 10200)["ssh_user_ca"] != nil {
		t.Fatalf("busy: %s", encoded(r))
	}
}

func TestBackfillChecksOwnerAgainstTheUsernameRecord(t *testing.T) {
	p, b, app := backfillFixture(t)
	ctx, admin := context.Background(), person("root", true)
	tenant := p.Store.Register("user:alex-sub", "alex-smith")
	m := seedMachine(p, "old2", 10202)
	m["tenant_n"] = tenant["n"]
	p.Store.Exec("UPDATE objects SET tenant=?, data=? WHERE kind='machines' AND id='10202'", tenant["n"], string(encoded(m)))
	run := func(owner string, dry bool) D {
		r := app.Call(ctx, "machine_ca_backfill", D{"tenant": "alex-smith", "machine": "old2", "owner": owner, "dry_run": dry}, admin)
		assertOK(t, r)
		return dicts(r["machines"])[0]
	}
	// No record: the Keycloak sub decides, not the slug, so a spelling whose
	// sub is another member's is refused although the slug matches.
	keycloakFor(t, p, "alex_smith", `[{"id":"other-sub","username":"alex_smith"}]`, 200)
	if got := run("alex_smith", true); got["result"] != "skipped" || !strings.Contains(str(got["message"]), "Keycloak sub") {
		t.Fatalf("sub mismatch: %s", encoded(got))
	}
	keycloakFor(t, p, "alex_smith", `[{"id":"alex-sub","username":"alex_smith"}]`, 200)
	if got := run("alex_smith", true); got["result"] != "would_backfill" || !strings.Contains(str(got["message"]), "Keycloak sub") {
		t.Fatalf("sub match: %s", encoded(got))
	}
	// A failed lookup skips the VM.
	keycloakFor(t, p, "alex_smith", ``, 500)
	if got := run("alex_smith", false); got["result"] != "skipped" || b.count("ca_backfill") != 0 {
		t.Fatalf("lookup error: %s", encoded(got))
	}
	// Not configured skips it too.
	p.Config.KeycloakURL = ""
	if got := run("alex_smith", true); got["result"] != "skipped" {
		t.Fatalf("lookup unavailable: %s", encoded(got))
	}
	// A key saved by alex.smith is the record; the lookup is not needed (and is down).
	p.Store.Put("keys", "k1", integer(tenant["n"]), D{"id": "k1", "key": userCATestKey, "by": "alex.smith"})
	if got := run("alex_smith", false); got["result"] != "skipped" || !strings.Contains(str(got["message"]), "alex.smith") || b.count("ca_backfill") != 0 {
		t.Fatalf("mismatch: %s", encoded(got))
	}
	// A second recorded username refuses although owner equals one of them.
	p.Store.Put("keys", "k1b", integer(tenant["n"]), D{"id": "k1b", "key": userCATestKey, "by": "alex_smith"})
	if got := run("alex.smith", false); got["result"] != "skipped" || !strings.Contains(str(got["message"]), "more than one username") || b.count("ca_backfill") != 0 {
		t.Fatalf("two recorded usernames: %s", encoded(got))
	}
	p.Store.Remove("keys", "k1b")
	got := run("alex.smith", true)
	if got["result"] != "would_backfill" || !strings.Contains(str(got["message"]), "alex.smith") {
		t.Fatalf("exact match: %s", encoded(got))
	}
	if got := run("alex.smith", false); got["result"] != "backfilled" {
		t.Fatalf("backfill: %s", encoded(got))
	}
}

func TestBackfillAliasConfirmed(t *testing.T) {
	p, b, app := backfillFixture(t)
	ctx, admin := context.Background(), person("root", true)
	tenant := p.Store.Register("user:chen-sub", "ta-chen")
	m := seedMachine(p, "old3", 10203)
	m["tenant_n"] = tenant["n"]
	p.Store.Exec("UPDATE objects SET tenant=?, data=? WHERE kind='machines' AND id='10203'", tenant["n"], string(encoded(m)))
	run := func(owner string, alias bool) D {
		a := D{"tenant": "ta-chen", "machine": "old3", "owner": owner}
		if alias {
			a["alias_confirmed"] = true
		}
		r := app.Call(ctx, "machine_ca_backfill", a, admin)
		assertOK(t, r)
		return dicts(r["machines"])[0]
	}
	if got := run("chen", false); got["result"] != "skipped" || !strings.Contains(str(got["message"]), "alias_confirmed") || b.count("ca_backfill") != 0 {
		t.Fatalf("without the flag: %s", encoded(got))
	}
	// A record that contradicts owner refuses, flag or not.
	p.Store.Put("keys", "k2", integer(tenant["n"]), D{"id": "k2", "key": userCATestKey, "by": "tachen"})
	if got := run("chen", true); got["result"] != "skipped" || b.count("ca_backfill") != 0 {
		t.Fatalf("contradicting record: %s", encoded(got))
	}
	// Two distinct records refuse even when owner equals one of them.
	p.Store.Put("keys", "k3", integer(tenant["n"]), D{"id": "k3", "key": userCATestKey, "by": "chen"})
	if got := run("chen", true); got["result"] != "skipped" || !strings.Contains(str(got["message"]), "more than one username") || !strings.Contains(str(got["message"]), "tachen") || b.count("ca_backfill") != 0 {
		t.Fatalf("two recorded usernames: %s", encoded(got))
	}
	p.Store.Remove("keys", "k3")
	p.Store.Remove("keys", "k2")
	// So does a frozen VM created with the CA.
	p.Store.Put("frozen", 10299, integer(tenant["n"]), D{"vmid": 10299, "name": "cold", "state": "frozen", "ssh_user_ca": "ssh-ed25519 AAAA", "ca_sync": "pull", "ca_principals": []any{"tachen"}, "ca_created": true})
	if got := run("chen", true); got["result"] != "skipped" || !strings.Contains(str(got["message"]), "tachen") || b.count("ca_backfill") != 0 {
		t.Fatalf("contradicting frozen record: %s", encoded(got))
	}
	p.Store.Remove("frozen", 10299)
	// VMs created with the CA before ca_sync existed still count as a record, live or frozen.
	p.Store.Put("frozen", 10298, integer(tenant["n"]), D{"vmid": 10298, "name": "cold2", "state": "frozen", "ssh_user_ca": "ssh-ed25519 AAAA", "ca_principals": []any{"tachen"}})
	if got := run("chen", true); got["result"] != "skipped" || !strings.Contains(str(got["message"]), "tachen") || b.count("ca_backfill") != 0 {
		t.Fatalf("frozen record without ca_sync: %s", encoded(got))
	}
	p.Store.Remove("frozen", 10298)
	live := seedMachine(p, "live-ca", 10297)
	live["tenant_n"], live["ssh_user_ca"], live["ca_principals"] = tenant["n"], "ssh-ed25519 AAAA", []any{"tachen"}
	p.Store.Exec("UPDATE objects SET tenant=?, data=? WHERE kind='machines' AND id='10297'", tenant["n"], string(encoded(live)))
	if got := run("chen", true); got["result"] != "skipped" || !strings.Contains(str(got["message"]), "tachen") || b.count("ca_backfill") != 0 {
		t.Fatalf("live record without ca_sync: %s", encoded(got))
	}
	p.Store.Remove("machines", 10297)
	// A pre-ca_sync CA record that matches owner is accepted, and a backfilled row without ca_sync is no record.
	p.Store.Put("frozen", 10296, integer(tenant["n"]), D{"vmid": 10296, "name": "cold3", "state": "frozen", "ssh_user_ca": "ssh-ed25519 AAAA", "ca_principals": []any{"chen"}})
	p.Store.Put("frozen", 10295, integer(tenant["n"]), D{"vmid": 10295, "name": "cold4", "state": "frozen", "ssh_user_ca": "ssh-ed25519 AAAA", "ca_principals": []any{"tachen"}, "ca_backfilled": true})
	if got := run("chen", true); got["result"] != "backfilled" || !equal(storedMachine(p, 10203)["ca_principals"], []any{"chen"}) {
		t.Fatalf("with the flag: %s", encoded(got))
	}
	// The flag needs tenant and owner.
	assertCode(t, app.Call(ctx, "machine_ca_backfill", D{"tenant": "ta-chen", "alias_confirmed": true}, admin), "invalid")
	assertCode(t, app.Call(ctx, "machine_ca_backfill", D{"owner": "chen", "alias_confirmed": true}, admin), "invalid")
}

func TestBackfillReleasesTheWriterDuringNodeIO(t *testing.T) {
	p, b, app := backfillFixture(t)
	ctx, admin := context.Background(), person("root", true)
	inNode, release := make(chan struct{}), make(chan struct{})
	inner := b.call
	b.call = func(r D, target string) (any, error) {
		if r["op"] == "ca_backfill" {
			close(inNode)
			<-release
		}
		return inner(r, target)
	}
	done := make(chan D)
	go func() {
		done <- app.Call(ctx, "machine_ca_backfill", D{"tenant": "alice", "machine": "old", "owner": "alice"}, admin)
	}()
	<-inNode
	locked := make(chan struct{})
	go func() {
		p.writer.Lock()
		p.writer.Unlock()
		close(locked)
	}()
	select {
	case <-locked:
	case <-time.After(5 * time.Second):
		t.Fatal("the writer is still held during the node call")
	}
	close(release)
	r := <-done
	assertOK(t, r)
	if got := dicts(r["machines"])[0]["result"]; got != "backfilled" || storedMachine(p, 10200)["ssh_user_ca"] != userCATestKey {
		t.Fatalf("after the node call: %s", encoded(r))
	}
}

// blockBackfill makes the node stop inside ca_backfill until release is
// closed, and starts a backfill of alice's old VM as owner.
func blockBackfill(t *testing.T, b *fakeBackend, app *App, owner string) (chan struct{}, chan D) {
	t.Helper()
	inNode, release := make(chan struct{}), make(chan struct{})
	inner := b.call
	var once bool
	b.call = func(r D, target string) (any, error) {
		if r["op"] == "ca_backfill" && !once {
			once = true
			close(inNode)
			<-release
		}
		return inner(r, target)
	}
	done := make(chan D)
	go func() {
		done <- app.Call(context.Background(), "machine_ca_backfill", D{"tenant": "alice", "machine": "old", "owner": owner}, person("root", true))
	}()
	<-inNode
	return release, done
}

func TestBackfillRefusesASecondRunOnTheSameVM(t *testing.T) {
	p, b, app := backfillFixture(t)
	release, done := blockBackfill(t, b, app, "alice")
	// A second run while the first writes the disk must not write another
	// principal into it.
	r := app.Call(context.Background(), "machine_ca_backfill", D{"tenant": "alice", "machine": "old", "owner": "alice", "alias_confirmed": true}, person("root", true))
	assertOK(t, r)
	if got := dicts(r["machines"])[0]["result"]; got != "skipped" || b.count("ca_backfill") != 1 {
		t.Fatalf("second run during the write: %s", encoded(r))
	}
	close(release)
	r = <-done
	if got := dicts(r["machines"])[0]["result"]; got != "backfilled" || !equal(storedMachine(p, 10200)["ca_principals"], []any{"alice"}) || len(p.backfillVMIDs()) != 0 {
		t.Fatalf("first run: %s", encoded(r))
	}
}

func TestBackfillHoldsASnapshotUntilTheRecordIsSaved(t *testing.T) {
	p, b, app := backfillFixture(t)
	release, done := blockBackfill(t, b, app, "alice")
	inner := b.call
	var trusted []any
	b.call = func(r D, target string) (any, error) {
		switch {
		case r["op"] == "inventory":
			return baseInventory(), nil
		case r["op"] == "action" && r["action"] == "snapshot":
			trusted = append(trusted, storedMachine(p, 10200)["ssh_user_ca"])
		}
		return inner(r, target)
	}
	runQueue(p)
	r := p.Execute(context.Background(), "snapshot_create", D{"machine": "old", "name": "s1", "wait_seconds": 0}, person("alice", false))
	assertOK(t, r)
	id := str(obj(r["operation"])["id"])
	awaitState(t, p, id, "waiting_for_machine_operation")
	if len(trusted) != 0 {
		t.Fatal("the snapshot ran while the disk was being written")
	}
	close(release)
	assertOK(t, <-done)
	awaitStateWithin(t, p, id, "succeeded", 10*time.Second)
	if len(trusted) != 1 || trusted[0] != userCATestKey {
		t.Fatalf("the snapshot did not follow the saved record: %v", trusted)
	}
}

func TestRecordedUsernamesCountsOnlyCACreated(t *testing.T) {
	p, _, _ := backfillFixture(t)
	tenant := p.Store.Register("user:li-sub", "li")
	n := integer(tenant["n"])
	ca := func(vmid int, name, principal string, extra D) D {
		return merge(D{"vmid": vmid, "name": name, "ssh_user_ca": userCATestKey, "ca_sync": "pull", "ca_principals": []any{principal}}, extra)
	}
	recorded := func() []string { return (&Execution{P: p, S: p.Store}).recordedUsernames(tenant) }
	p.Store.Put("machines", 10310, n, ca(10310, "legacy", "legacy-user", nil))
	p.Store.Put("machines", 10311, n, ca(10311, "filled", "filled-user", D{"ca_backfilled": true}))
	if got := recorded(); len(got) != 0 {
		t.Fatalf("legacy and backfilled VMs counted: %v", got)
	}
	p.Store.Put("machines", 10313, n, D{"vmid": 10313, "name": "flagged", "ssh_user_ca": userCATestKey, "ca_principals": []any{"flagged-user"}, "ca_backfilled": true})
	if got := recorded(); len(got) != 0 {
		t.Fatalf("backfilled VM without ca_sync counted: %v", got)
	}
	p.Store.Put("machines", 10312, n, ca(10312, "made", "made-user", D{"ca_created": true}))
	if got := recorded(); !equal(got, []string{"made-user"}) {
		t.Fatalf("CA-created VM: %v", got)
	}
}

// Dry runs read the in-flight set without the writer: a member's dry-run
// rename or an admin's dry-run backfill during a backfill must not race the
// insert and delete (run with -race).
func TestBackfillDryRunsDoNotRaceTheInFlightSet(t *testing.T) {
	p, _, app := backfillFixture(t)
	stop := make(chan struct{})
	var readers sync.WaitGroup
	for _, call := range []func(){
		func() {
			p.Execute(context.Background(), "machine_rename", D{"machine": "old", "name": "crate", "confirm": "old", "dry_run": true}, person("alice", false))
		},
		func() {
			p.Execute(context.Background(), "machine_ca_backfill", D{"tenant": "alice", "machine": "old", "owner": "alice", "dry_run": true}, person("root", true))
		},
	} {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
					call()
				}
			}
		}()
	}
	for range 20 {
		seedMachine(p, "old", 10200)
		r := app.Call(context.Background(), "machine_ca_backfill", D{"tenant": "alice", "machine": "old", "owner": "alice"}, person("root", true))
		if got := dicts(r["machines"])[0]["result"]; got != "backfilled" {
			t.Errorf("backfill: %s", encoded(r))
		}
	}
	close(stop)
	readers.Wait()
	if len(p.backfillVMIDs()) != 0 {
		t.Fatal("the in-flight set is not empty")
	}
}

// The input schema itself, not only the handler, requires tenant and owner with alias_confirmed.
func TestCABackfillSchemaRequiresTenantAndOwnerWithAlias(t *testing.T) {
	p, _, _ := backfillFixture(t)
	app := NewApp(p, nil)
	schema := app.schemas["machine_ca_backfill"]
	for _, tc := range []struct {
		args D
		ok   bool
	}{
		{D{"alias_confirmed": false}, true},
		{D{"alias_confirmed": true, "tenant": "ta-chen", "owner": "chen"}, true},
		{D{"alias_confirmed": true}, false},
		{D{"alias_confirmed": true, "tenant": "ta-chen"}, false},
		{D{"alias_confirmed": true, "owner": "chen"}, false},
	} {
		if err := schema.Validate(map[string]any(tc.args)); (err == nil) != tc.ok {
			t.Errorf("%v: ok=%v err=%v", tc.args, tc.ok, err)
		}
	}
}
