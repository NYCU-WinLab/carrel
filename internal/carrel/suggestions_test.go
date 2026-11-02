package carrel

import (
	"context"
	"testing"
)

func TestMachineWithWebsiteSuggestsAppLinkUntilLinked(t *testing.T) {
	p, _ := fixture(t)
	p.Config.AppsDir = t.TempDir()
	seedMachine(p, "web", 10100)
	seedMachine(p, "plain", 10101)
	p.Store.Put("domains", "d1", 1, domainRecord{ID: "d1", TenantN: 1, VMID: 10100, Slug: "alice", Sub: "web", Name: "web.alice.winlab.tw", TargetPort: 3000, State: "ready"}.D())
	p.Store.Put("domains", "d2", 1, domainRecord{ID: "d2", TenantN: 1, VMID: 10101, Slug: "alice", Name: "_mc._tcp.alice.winlab.tw", TargetPort: 25565, State: "ready"}.D())
	a := NewApp(p, nil)
	ctx, alice := context.Background(), person("alice", false)

	r := a.Call(ctx, "machine_get", D{"machine": "web"}, alice)
	assertOK(t, r)
	s := dicts(r["suggestions"])
	if len(s) != 1 || s[0]["tool"] != "app_link" || obj(s[0]["args"])["machine"] != "web" || integer(obj(s[0]["args"])["port"]) != 3000 {
		t.Fatalf("want one app_link suggestion, got %s", encoded(r["suggestions"]))
	}
	// An SRV record is no website.
	if r := a.Call(ctx, "machine_get", D{"machine": "plain"}, alice); r["suggestions"] != nil {
		t.Fatalf("SRV-only machine got %s", encoded(r["suggestions"]))
	}
	assertOK(t, a.Call(ctx, "app_link", D{"machine": "web", "name": "site", "repo": "alice/site", "start": "x", "port": 3000}, alice))
	if r := a.Call(ctx, "machine_get", D{"machine": "web"}, alice); r["suggestions"] != nil {
		t.Fatalf("linked machine still got %s", encoded(r["suggestions"]))
	}
	// Another tenant never sees alice's machines or suggestions.
	if r := a.Call(ctx, "machine_get", D{"machine": "web"}, person("bob", false)); r["suggestions"] != nil {
		t.Fatalf("bob got %s", encoded(r))
	}
}

func TestSuccessfulDomainAddSuggestsAppLink(t *testing.T) {
	p, _ := fixture(t)
	seedMachine(p, "web", 10100)
	p.Store.Put("domains", "d1", 1, domainRecord{ID: "d1", TenantN: 1, VMID: 10100, Slug: "alice", Sub: "web", Name: "web.alice.winlab.tw", TargetPort: 8080, State: "ready"}.D())
	e := p.execution(context.Background())
	op := D{"tool": "domain_add", "state": "succeeded", "result": D{"domain": D{"name": "web.alice.winlab.tw"}}}
	r := D{"ok": true, "operation": op}
	e.addSuggestions("domain_add", D{}, 1, r)
	if s := dicts(r["suggestions"]); len(s) != 1 || s[0]["tool"] != "app_link" {
		t.Fatalf("got %s", encoded(r))
	}
	// Pending operations, dry runs and failures carry nothing.
	for _, c := range []struct {
		a D
		r D
	}{
		{D{}, D{"ok": true, "operation": D{"tool": "domain_add", "state": "waiting", "result": op["result"]}}},
		{D{"dry_run": true}, D{"ok": true, "operation": op}},
		{D{}, D{"ok": false, "operation": op}},
	} {
		e.addSuggestions("domain_add", c.a, 1, c.r)
		if c.r["suggestions"] != nil {
			t.Fatalf("unexpected suggestion in %s", encoded(c.r))
		}
	}
}

func TestInlineKeySuggestsSavingIt(t *testing.T) {
	p, _ := fixture(t)
	e := p.execution(context.Background())
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAliceAliceAliceAliceAliceAliceAliceAlice"
	done := D{"ok": true, "operation": D{"tool": "machine_create", "state": "succeeded"}}
	e.addSuggestions("machine_create", D{"ssh_keys": []any{key + " laptop"}}, 1, done)
	if s := dicts(done["suggestions"]); len(s) != 1 || s[0]["tool"] != "ssh_key_add" {
		t.Fatalf("got %s", encoded(done))
	}
	p.Store.Put("keys", "1-k", 1, D{"id": "k", "key": key + " other-comment"})
	again := D{"ok": true, "operation": D{"tool": "machine_create", "state": "succeeded"}}
	e.addSuggestions("machine_create", D{"ssh_keys": []any{key + " laptop"}}, 1, again)
	if again["suggestions"] != nil {
		t.Fatalf("saved key still suggested: %s", encoded(again))
	}
}
