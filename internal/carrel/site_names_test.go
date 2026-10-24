package carrel

// TestSiteSpecialNames covers the lab website's own names (PLAN 6.10): the
// apex and www.winlab.tw may be requested and approved as exact names, while
// the zone's wildcard and the other reserved labels stay refused.

import (
	"context"
	"testing"
)

func TestSiteSpecialNames(t *testing.T) {
	p, b, _ := originFixture(t)
	dns := &statefulDNS{records: map[string][]D{}, list: true}
	p.Config["cloudflare_api"] = dns.serve(t).URL
	p.Config["cloudflare_token"] = "test"
	p.Config["zone_dir"] = t.TempDir()
	p.sshProbe = func(context.Context, D) bool { return true }
	rec := &recorder{fakeBackend: b, p: p}
	p.Backend = rec
	runQueue(p)
	g := &goldenRun{t: t, p: p, app: NewApp(p, nil), rec: rec, tools: map[string]bool{}}
	bob, admin := person("bob", false), person("root", true)
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGoldenGoldenGoldenGoldenGoldenGoldenGold golden"
	dns.records["winlab.tw"] = []D{{"id": "apex", "type": "A", "name": "winlab.tw", "content": "216.198.79.1"}}
	dns.records["www.winlab.tw"] = []D{{"id": "www", "type": "CNAME", "name": "www.winlab.tw", "content": "x.vercel-dns-017.com"}}
	g.call("s", "ssh_key_add", D{"key": key}, bob)

	code := func(r D) string {
		if r["ok"] == true {
			return "ok"
		}
		return str(obj(r["error"])["code"])
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
}
