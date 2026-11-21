package carrel

import (
	"context"
	"errors"
	"strings"
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
	// No record: the slug check alone decides, so both spellings pass.
	if got := run("alex_smith", true); got["result"] != "would_backfill" {
		t.Fatalf("slug fallback: %s", encoded(got))
	}
	// A key saved by alex.smith is the record.
	p.Store.Put("keys", "k1", integer(tenant["n"]), D{"id": "k1", "key": userCATestKey, "by": "alex.smith"})
	if got := run("alex_smith", false); got["result"] != "skipped" || !strings.Contains(str(got["message"]), "alex.smith") || b.count("ca_backfill") != 0 {
		t.Fatalf("mismatch: %s", encoded(got))
	}
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
	p.Store.Remove("keys", "k2")
	// So does a frozen VM created with the CA.
	p.Store.Put("frozen", 10299, integer(tenant["n"]), D{"vmid": 10299, "name": "cold", "state": "frozen", "ssh_user_ca": "ssh-ed25519 AAAA", "ca_sync": "pull", "ca_principals": []any{"tachen"}})
	if got := run("chen", true); got["result"] != "skipped" || !strings.Contains(str(got["message"]), "tachen") || b.count("ca_backfill") != 0 {
		t.Fatalf("contradicting frozen record: %s", encoded(got))
	}
	p.Store.Remove("frozen", 10299)
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
