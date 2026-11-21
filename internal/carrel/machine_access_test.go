package carrel

import (
	"context"
	"errors"
	"testing"
)

func caMachine(p *Platform, name string, vmid int, kind, sync string) D {
	m := seedMachine(p, name, vmid)
	m["kind"] = kind
	m["ssh_user_ca"] = userCATestKey
	m["ca_principals"] = []any{"alice"}
	if sync != "" {
		m["ca_sync"] = sync
	}
	p.Store.Put("machines", vmid, 1, m)
	return m
}

func accessOf(t *testing.T, r D) D {
	t.Helper()
	assertOK(t, r)
	return obj(r["access"])
}

func TestMachineAccessOnAVM(t *testing.T) {
	p, _ := fixture(t)
	app := NewApp(p, nil)
	ctx := context.Background()
	alice := person("alice", false)
	m := caMachine(p, "box", 10100, "vm", "pull")
	e := p.execution(ctx)
	report := D{"vmid": 10100, "token": "test-token", "boot_id": "00000000-0000-0000-0000-000000000001", "initialization_status": "complete", "application_status": "not_checked"}

	// Grant: the VM's next report gets the whole file, creator first.
	a := accessOf(t, app.Call(ctx, "machine_access", D{"machine": "box", "grant": []any{"bob", "carol", "bob"}}, alice))
	if a["applied"] != "pending" || len(dicts(a["grants"])) != 2 {
		t.Fatalf("grant: %s", encoded(a))
	}
	got := e.GuestReport(report, str(m["ip"]))
	if !equal(got["principals"], []any{"alice", "bob", "carol"}) {
		t.Fatalf("report answer: %s", encoded(got))
	}
	// Applied once the VM reports the same list.
	e.GuestReport(merge(report, D{"principals": []any{"alice", "bob", "carol"}}), str(m["ip"]))
	if a := accessOf(t, app.Call(ctx, "machine_access", D{"machine": "box"}, alice)); a["applied"] != "applied" {
		t.Fatalf("applied: %s", encoded(a))
	}
	// machine_get shows the same.
	r := app.Call(ctx, "machine_get", D{"machine": "box"}, alice)
	assertOK(t, r)
	if lab := obj(dicts(r["machines"])[0]["lab_ca"]); lab["principal"] != "alice" || lab["applied"] != "applied" {
		t.Fatalf("machine_get: %s", encoded(lab))
	}
	// Revoke: gone from the next answer.
	accessOf(t, app.Call(ctx, "machine_access", D{"machine": "box", "revoke": []any{"bob"}}, alice))
	if got := e.GuestReport(report, str(m["ip"])); !equal(got["principals"], []any{"alice", "carol"}) {
		t.Fatalf("after revoke: %s", encoded(got))
	}
	// The creator's own principal cannot be revoked or doubled.
	accessOf(t, app.Call(ctx, "machine_access", D{"machine": "box", "grant": []any{"alice"}}, alice))
	a = accessOf(t, app.Call(ctx, "machine_access", D{"machine": "box", "revoke": []any{"alice"}}, alice))
	if a["principal"] != "alice" || len(dicts(a["grants"])) != 1 {
		t.Fatalf("own principal: %s", encoded(a))
	}
	// Dry run changes nothing.
	accessOf(t, app.Call(ctx, "machine_access", D{"machine": "box", "grant": []any{"dave"}, "dry_run": true}, alice))
	if got := e.GuestReport(report, str(m["ip"])); !equal(got["principals"], []any{"alice", "carol"}) {
		t.Fatalf("dry run wrote: %s", encoded(got))
	}
	// Names the CA never signs, and other shapes, are refused.
	for _, bad := range []string{"root", "user", "test", "svc:carrel", "project:x", "Bob", "a\nroot"} {
		r := app.Call(ctx, "machine_access", D{"machine": "box", "grant": []any{bad}}, alice)
		assertCode(t, r, "invalid")
	}
	// The same name in grant and revoke is refused.
	assertCode(t, app.Call(ctx, "machine_access", D{"machine": "box", "grant": []any{"erin"}, "revoke": []any{"erin"}}, alice), "invalid")
	// Another tenant cannot touch it.
	assertCode(t, app.Call(ctx, "machine_access", D{"machine": "box", "grant": []any{"mallory"}}, person("bob", false)), "not_found")
	// A machine without a puller says so instead of pretending.
	caMachine(p, "old", 10101, "vm", "")
	if a := accessOf(t, app.Call(ctx, "machine_access", D{"machine": "old"}, alice)); a["applied"] != "unsupported" {
		t.Fatalf("old: %s", encoded(a))
	}
	assertCode(t, app.Call(ctx, "machine_access", D{"machine": "old", "grant": []any{"bob"}}, alice), "invalid")
	// A machine without the CA has nothing to grant.
	seedMachine(p, "plain", 10102)
	assertCode(t, app.Call(ctx, "machine_access", D{"machine": "plain"}, alice), "invalid")
}

func TestMachineAccessOnACTPushesFromTheNode(t *testing.T) {
	p, b := fixture(t)
	app := NewApp(p, nil)
	ctx := context.Background()
	alice := person("alice", false)
	caMachine(p, "ct", 10100, "ct", "push")
	b.call = func(r D, _ string) (any, error) {
		if r["op"] == "action" && r["action"] == "principals" {
			return D{"state": "applied"}, nil
		}
		return D{"status": "running"}, nil
	}
	a := accessOf(t, app.Call(ctx, "machine_access", D{"machine": "ct", "grant": []any{"bob"}}, alice))
	if a["applied"] != "applied" {
		t.Fatalf("ct: %s", encoded(a))
	}
	var pushed D
	for _, c := range b.calls {
		if c["action"] == "principals" {
			pushed = c
		}
	}
	if !equal(pushed["principals"], []any{"alice", "bob"}) {
		t.Fatalf("pushed: %s", encoded(pushed))
	}
	// The node refusing (a stopped CT) changes nothing.
	b.call = func(r D, _ string) (any, error) {
		if r["action"] == "principals" {
			return nil, errors.New("the CT is not running")
		}
		return D{"status": "running"}, nil
	}
	if r := app.Call(ctx, "machine_access", D{"machine": "ct", "grant": []any{"carol"}}, alice); boolean(r["ok"]) {
		t.Fatalf("stopped CT: %s", encoded(r))
	}
	if a := accessOf(t, app.Call(ctx, "machine_access", D{"machine": "ct"}, alice)); len(dicts(a["grants"])) != 1 || a["applied"] != "pending" {
		t.Fatalf("kept, pending: %s", encoded(a))
	}
	// A push that changed the CT but lost its answer: the recorded list is
	// pushed back, and only then is it applied again.
	calls := 0
	b.call = func(r D, _ string) (any, error) {
		if r["action"] == "principals" {
			calls++
			if calls == 1 {
				return nil, errors.New("connection reset")
			}
			if !equal(r["principals"], []any{"alice", "bob"}) {
				t.Fatalf("restore pushed %s", encoded(r["principals"]))
			}
			return D{"state": "applied"}, nil
		}
		return D{"status": "running"}, nil
	}
	if r := app.Call(ctx, "machine_access", D{"machine": "ct", "grant": []any{"dave"}}, alice); boolean(r["ok"]) {
		t.Fatalf("lost answer: %s", encoded(r))
	}
	if a := accessOf(t, app.Call(ctx, "machine_access", D{"machine": "ct"}, alice)); a["applied"] != "applied" || calls != 2 {
		t.Fatalf("restored: %d %s", calls, encoded(a))
	}
}

func TestANewMachineRecordsHowItSyncsAccess(t *testing.T) {
	p, _ := fixture(t)
	ctx := context.Background()
	alice := person("alice", false)
	e := p.execution(ctx)
	p.Config.SSHUserCA = userCATestKey
	tenant := p.Store.Tenant("user:alice")
	key := []any{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIInlineKeyInTheRequest"}
	for kind, want := range map[string]string{"vm": "pull", "ct": "push"} {
		a := e.withCAPrincipal("machine_create", e.withPortalKeys("machine_create", D{"name": "box", "kind": kind, "ssh_keys": key}, alice), alice)
		m := e.MachineSpec(tenant, a, false)
		if m["ca_sync"] != want {
			t.Fatalf("%s: %s", kind, encoded(m))
		}
		// The marker recordedUsernames relies on is written for both kinds,
		// and a thaw keeps it.
		if m["ca_created"] != true || thawRecord(m, nodeRef{Name: "n1"})["ca_created"] != true {
			t.Fatalf("%s: ca_created not recorded or kept: %s", kind, encoded(m))
		}
		// A new CT has its file from creation: applied, not pending.
		if kind == "ct" && e.caAccess(m)["applied"] != "applied" {
			t.Fatalf("new CT: %s", encoded(e.caAccess(m)))
		}
	}
}

func TestACallerCannotSendCACreated(t *testing.T) {
	p, _ := fixture(t)
	e := p.execution(context.Background())
	alice := person("alice", false)
	tenant := p.Store.Tenant("user:alice")
	for _, kind := range []string{"vm", "ct"} {
		a := e.withCAPrincipal("machine_create", e.withPortalKeys("machine_create", D{"name": "box", "kind": kind, "ca_created": true, "ssh_keys": []any{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIInlineKeyInTheRequest"}}, alice), alice)
		if m := e.MachineSpec(tenant, a, false); m["ca_created"] != nil {
			t.Fatalf("%s: a caller-sent marker reached the record: %s", kind, encoded(m))
		}
	}
}

func TestGuestPrincipalsAreChecked(t *testing.T) {
	for _, bad := range []any{"alice", []any{"alice\nroot"}, []any{1}, []any{"svc:x"}} {
		if guestPrincipals(bad) != nil {
			t.Fatalf("accepted %v", bad)
		}
	}
	if !equal(guestPrincipals([]any{"alice", "project:demo"}), []any{"alice", "project:demo"}) {
		t.Fatal("refused a good list")
	}
}

func TestARevokeIsNotAppliedByAnOlderReport(t *testing.T) {
	p, _ := fixture(t)
	app := NewApp(p, nil)
	ctx := context.Background()
	alice := person("alice", false)
	m := caMachine(p, "box", 10100, "vm", "pull")
	e := p.execution(ctx)
	report := D{"vmid": 10100, "token": "test-token", "boot_id": "00000000-0000-0000-0000-000000000001", "initialization_status": "complete", "application_status": "not_checked", "principals": []any{"alice"}}
	// The VM reports [alice]; bob is granted and revoked before it reports again.
	e.GuestReport(report, str(m["ip"]))
	accessOf(t, app.Call(ctx, "machine_access", D{"machine": "box", "grant": []any{"bob"}}, alice))
	a := accessOf(t, app.Call(ctx, "machine_access", D{"machine": "box", "revoke": []any{"bob"}}, alice))
	if a["applied"] != "pending" {
		t.Fatalf("an older report counted: %s", encoded(a))
	}
	// A report after the change does.
	e.GuestReport(report, str(m["ip"]))
	if a := accessOf(t, app.Call(ctx, "machine_access", D{"machine": "box"}, alice)); a["applied"] != "applied" {
		t.Fatalf("fresh report: %s", encoded(a))
	}
}

func TestARolledBackCTGetsTheCurrentListAgain(t *testing.T) {
	p, b := fixture(t)
	ctx := context.Background()
	e := p.execution(ctx)
	m := caMachine(p, "ct", 10100, "ct", "push")
	m["ca_grants"] = []any{D{"username": "carol", "by": "alice", "at": 1.0}}
	m["ca_applied"] = []any{"alice", "carol"}
	pushes := 0
	b.call = func(r D, _ string) (any, error) {
		if r["action"] == "principals" {
			pushes++
			return D{"state": "applied"}, nil
		}
		return D{"status": "running"}, nil
	}
	// Rolled back and running: pushed again.
	e.caRestored(m, true)
	if pushes != 1 || !equal(m["ca_applied"], []any{"alice", "carol"}) {
		t.Fatalf("running: %d %s", pushes, encoded(m["ca_applied"]))
	}
	// Rolled back and stopped: pending until it starts.
	e.caRestored(m, false)
	if pushes != 1 || m["ca_applied"] != nil || e.caAccess(m)["applied"] != "pending" {
		t.Fatalf("stopped: %d %s", pushes, encoded(m))
	}
	// The node refusing leaves it pending.
	b.call = func(r D, _ string) (any, error) { return nil, errors.New("no") }
	e.caRestored(m, true)
	if m["ca_applied"] != nil {
		t.Fatalf("refused push counted: %s", encoded(m["ca_applied"]))
	}
}
