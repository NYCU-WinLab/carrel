package carrel

// TestSiteSpecialNames covers the lab website's own names (PLAN 6.10): the
// apex and www.winlab.tw may be requested and approved as exact names, while
// the zone's wildcard and the other reserved labels stay refused. The apex
// speaks for itself only, so SRV names elsewhere in the zone stay open.

import (
	"context"
	"testing"
)

func TestSiteSpecialNames(t *testing.T) {
	p, b, _ := originFixture(t)
	dns := &statefulDNS{records: map[string][]D{}, list: true}
	p.Config.CloudflareAPI = dns.serve(t).URL
	p.Config.CloudflareToken = "test"
	p.Config.ZoneDir = t.TempDir()
	p.sshProbe = func(context.Context, D) bool { return true }
	rec := &recorder{fakeBackend: b, p: p}
	p.Backend = rec
	runQueue(p)
	g := &goldenRun{t: t, p: p, app: NewApp(p, nil), rec: rec, tools: map[string]bool{}}
	alice, bob, admin := person("alice", false), person("bob", false), person("root", true)
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGoldenGoldenGoldenGoldenGoldenGoldenGold golden"
	dns.records["winlab.tw"] = []D{{"id": "apex", "type": "A", "name": "winlab.tw", "content": "216.198.79.1"}}
	dns.records["www.winlab.tw"] = []D{{"id": "www", "type": "CNAME", "name": "www.winlab.tw", "content": "x.vercel-dns-017.com"}}
	g.call("s", "ssh_key_add", D{"key": key}, bob)
	g.call("s", "ssh_key_add", D{"key": key}, alice)

	code := func(r D) string {
		if r["ok"] == true {
			return "ok"
		}
		return str(obj(r["error"])["code"])
	}
	// Another tenant's SRV name, asked for before the apex.
	if r := g.call("p", "domain_request", D{"name": "_minecraft._tcp.mc.winlab.tw", "kind": "srv", "reason": "a game server"}, alice); r["ok"] != true {
		t.Fatalf("srv request: %v", r)
	}
	for _, c := range []struct {
		name, kind, want string
	}{
		{"*.winlab.tw", "wildcard", "invalid"},
		{"*.winlab.tw", "delegated", "forbidden"},
		{"api.winlab.tw", "exact", "conflict"},
		{"x.www.winlab.tw", "exact", "conflict"},
		{"www.winlab.tw", "exact", "ok"},
		{"winlab.tw", "exact", "ok"},
	} {
		r := g.call("r", "domain_request", D{"name": c.name, "kind": c.kind, "reason": "the lab website"}, bob)
		if got := code(r); got != c.want {
			t.Errorf("domain_request %s %s = %s, want %s: %v", c.kind, c.name, got, c.want, r)
		}
		if c.want != "ok" {
			continue
		}
		req := obj(r["request"])
		if req["existing_record"] != true {
			t.Errorf("%s: existing_record = %v, want true", c.name, req["existing_record"])
		}
		// Approval checks the rules again.
		a := g.call("a", "request_approve", D{"id": req["id"], "adopt": true, "dry_run": true}, admin)
		if code(a) != "ok" {
			t.Errorf("request_approve dry run for %s = %v", c.name, a)
		}
	}
	// And one asked for after the apex.
	if r := g.call("q", "domain_request", D{"name": "_minecraft._tcp.mc2.winlab.tw", "kind": "srv", "reason": "a second game server"}, alice); code(r) != "ok" {
		t.Errorf("srv request after the apex = %v", r)
	}
	// An SRV name on the apex itself stays refused.
	if r := g.call("q", "domain_request", D{"name": "_minecraft._tcp.winlab.tw", "kind": "srv", "reason": "the apex"}, alice); code(r) == "ok" {
		t.Errorf("srv on the apex was accepted: %v", r)
	}
}

// TestZoneApexExact keeps the apex of an added zone grantable as an exact
// name, as it was before the site's apex opened.
func TestZoneApexExact(t *testing.T) {
	p, b, _ := originFixture(t)
	dns := &statefulDNS{records: map[string][]D{}, list: true, zones: []D{{"id": "0123456789abcdef0123456789abcdef", "name": "lab.example", "token": "zone-token-0123456789abcdef"}}}
	p.Config.CloudflareAPI = dns.serve(t).URL
	p.Config.CloudflareToken = "test"
	p.Config.ZoneDir = t.TempDir()
	p.sshProbe = func(context.Context, D) bool { return true }
	rec := &recorder{fakeBackend: b, p: p}
	p.Backend = rec
	runQueue(p)
	g := &goldenRun{t: t, p: p, app: NewApp(p, nil), rec: rec, tools: map[string]bool{}}
	alice, admin := person("alice", false), person("root", true)
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGoldenGoldenGoldenGoldenGoldenGoldenGold golden"
	g.call("s", "ssh_key_add", D{"key": key}, alice)
	if r := g.call("z", "zone_add", D{"name": "lab.example", "token": "zone-token-0123456789abcdef", "tenants": []any{"alice"}}, admin); r["ok"] != true {
		t.Fatalf("zone_add: %v", r)
	}
	if r := g.call("z", "domain_request", D{"name": "lab.example", "reason": "alice's apex"}, alice); r["ok"] != true {
		t.Errorf("exact apex of an added zone = %v", r)
	}
	if r := g.call("z", "domain_request", D{"name": "*.lab.example", "kind": "wildcard", "reason": "the zone's wildcard"}, alice); r["ok"] == true {
		t.Errorf("wildcard of an added zone was accepted: %v", r)
	}
}
