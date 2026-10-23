package carrel

// TestGoldenSpecialDomains records special domains (PLAN 6.10) end to end:
// requests and the rules that refuse them, approval with and without adopt,
// publication under exact and wildcard grants, the gateway configuration,
// the DNS writes, and the release of an unused grant.

import (
	"context"
	"strings"
	"testing"
)

func TestGoldenSpecialDomains(t *testing.T) {
	saved := randomSource
	randomSource = &seededReader{}
	t.Cleanup(func() { randomSource = saved })
	p, b, _ := originFixture(t)
	dns := &statefulDNS{records: map[string][]D{}, list: true}
	p.Config["cloudflare_api"] = dns.serve(t).URL
	p.Config["cloudflare_token"] = "test"
	p.sshProbe = func(context.Context, D) bool { return true }
	e := p.execution(context.Background())
	// Issuance as the control plane would leave it: a pair for the grant.
	p.certificatePrepare = func(d D) D {
		if d["grant"] == true {
			crt, key := testPair(t, str(d["name"]))
			e.storeCertificate("_grant-"+str(d["id"]), crt, key)
		}
		return D{"state": "ready"}
	}
	rec := &recorder{fakeBackend: b, p: p}
	p.Backend = rec
	ctx, stop := context.WithCancel(context.Background())
	t.Cleanup(stop)
	go rec.guests(ctx)
	runQueue(p)
	g := &goldenRun{t: t, p: p, app: NewApp(p, nil), rec: rec, tools: map[string]bool{}}
	specialDomainScenario(g, dns)
	g.dump()
	checkGolden(t, "special-domains.txt", strings.Join(g.lines, "\n")+"\n")
}

func specialDomainScenario(g *goldenRun, dns *statefulDNS) {
	alice, bob, admin := person("alice", false), person("bob", false), person("root", true)
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGoldenGoldenGoldenGoldenGoldenGoldenGold golden"
	bg := context.Background()
	flush := func(step string) {
		dns.mu.Lock()
		for _, l := range dns.log {
			g.lines = append(g.lines, step+" dns "+normalize([]byte(l)))
		}
		dns.log = nil
		dns.mu.Unlock()
	}
	call := func(step, tool string, a, who D) D { r := g.call(step, tool, a, who); flush(step); return r }
	do := func(step string, f func()) { g.do(step, f); flush(step) }
	rows := func(step string) {
		for _, kind := range []string{"domain_grants", "domains"} {
			for _, data := range g.p.Store.objectData(kind) {
				g.lines = append(g.lines, step+" "+kind+" "+normalize([]byte(data)))
			}
		}
	}
	records := func(step string) {
		dns.mu.Lock()
		defer dns.mu.Unlock()
		for _, name := range []string{"video.winlab.tw", "*.lab.winlab.tw", "x.taken.winlab.tw"} {
			g.lines = append(g.lines, step+" record "+name+" "+normalize(encoded(dns.records[name])))
		}
	}
	status := func(step string) {
		s := g.p.execution(bg).PublicStatus()
		g.lines = append(g.lines, step+" status "+normalize(encoded(D{"tenants": s["tenants"], "others": s["others"]})))
	}
	requestID := func(r D) any { return obj(r["request"])["id"] }

	// Someone else's records: the old home of video, and a name under a
	// base a wildcard would cover.
	dns.records["video.winlab.tw"] = []D{{"id": "old1", "type": "A", "name": "video.winlab.tw", "content": "140.113.194.229"}}
	dns.records["x.taken.winlab.tw"] = []D{{"id": "old2", "type": "A", "name": "x.taken.winlab.tw", "content": "140.113.194.230"}}

	call("s", "ssh_key_add", D{"key": key}, alice)
	call("s", "ssh_key_add", D{"key": key}, bob)
	call("s", "machine_create", D{"name": "web"}, alice)
	call("s", "machine_create", D{"name": "bweb"}, bob)

	// r: requests and the rules that refuse them.
	call("r", "domain_request", D{"name": "video.winlab.tw", "reason": "lab video site", "dry_run": true}, alice)
	video := call("r", "domain_request", D{"name": "video.winlab.tw", "reason": "lab video site"}, alice)
	call("r", "domain_request", D{"name": "video.winlab.tw", "reason": "mine too"}, bob)
	lab := call("r", "domain_request", D{"name": "*.lab.winlab.tw", "kind": "wildcard", "reason": "lab services"}, bob)
	call("r", "domain_request", D{"name": "x.lab.winlab.tw", "reason": "under bob's wildcard"}, alice)
	call("r", "domain_request", D{"name": "site.alice.winlab.tw", "reason": "already mine"}, alice)
	call("r", "domain_request", D{"name": "alice.winlab.tw", "reason": "alice's apex"}, bob)
	apex := call("r", "domain_request", D{"name": "alice.winlab.tw", "reason": "my apex"}, alice)
	call("r", "domain_request", D{"name": "extra.winlab.tw", "reason": "third pending"}, alice)
	call("r", "domain_request", D{"name": "more.winlab.tw", "reason": "one too many"}, alice)
	call("r", "domain_request", D{"name": "auth.winlab.tw", "reason": "platform name"}, alice)
	call("r", "domain_request", D{"name": "carrel.winlab.tw", "reason": "platform name"}, alice)
	call("r", "domain_request", D{"name": "*.taken.winlab.tw", "kind": "wildcard", "reason": "covers a name"}, bob)
	call("r", "domain_request", D{"name": "lab.winlab.tw", "kind": "wildcard", "reason": "no star"}, bob)
	call("r", "domain_add", D{"machine": "web", "name": "video.winlab.tw", "target_port": 3000}, alice)
	call("r", "request_list", D{}, alice)

	// a: approval.
	call("a", "request_list_all", D{}, admin)
	call("a", "request_approve", D{"id": requestID(video)}, admin)
	call("a", "request_approve", D{"id": requestID(video), "adopt": true, "dry_run": true}, admin)
	call("a", "request_approve", D{"id": requestID(video), "adopt": true}, admin)
	call("a", "request_approve", D{"id": requestID(lab)}, admin)
	call("a", "request_reject", D{"id": requestID(apex)}, admin)
	// An exact name under the tenant's own wildcard wins over the wildcard.
	api := call("a", "domain_request", D{"name": "api.lab.winlab.tw", "reason": "its own certificate"}, bob)
	call("a", "request_approve", D{"id": requestID(api)}, admin)
	call("a", "domain_list", D{}, alice)
	rows("a")
	records("a")

	// d: publication. The adopted record changes in place once the gateway
	// holds the certificate.
	call("d", "domain_add", D{"machine": "web", "name": "video.winlab.tw", "target_port": 3000}, alice)
	records("d")
	call("d", "domain_add", D{"machine": "bweb", "name": "*.lab.winlab.tw", "target_port": 80}, bob)
	call("d", "domain_add", D{"machine": "bweb", "name": "api.lab.winlab.tw", "target_port": 8080}, bob)
	call("d", "domain_add", D{"machine": "bweb", "name": "a.b.lab.winlab.tw", "target_port": 8080}, bob)
	call("d", "domain_add", D{"machine": "web", "name": "api.lab.winlab.tw", "target_port": 8080}, alice)
	call("d", "domain_add", D{"machine": "web", "sub": "site", "name": "video.winlab.tw", "target_port": 8080}, alice)
	call("d", "domain_list", D{}, bob)
	rows("d")
	records("d")
	status("d")

	// m: maintenance keeps records in place; a removed domain leaves the
	// grant unused; an unused grant is released after 30 days.
	do("m", func() { g.p.execution(bg).MaintainGrants() })
	call("m", "domain_remove", D{"name": "video.winlab.tw"}, alice)
	do("m", func() { g.p.execution(bg).MaintainGrants() })
	call("m", "domain_list", D{}, alice)
	records("m")
	for _, gr := range g.p.Store.Objects("domain_grants", 1) {
		gr["unused_since"] = now() - 31*86400
		g.p.Store.Put("domain_grants", gr["id"], 1, gr)
	}
	do("m", func() { g.p.execution(bg).MaintainGrants() })
	call("m", "domain_list", D{}, alice)
	call("m", "request_list", D{}, alice)
	rows("m")
	records("m")
	// A machine's deletion removes its domains; the grant stays.
	call("m", "machine_delete", D{"machine": "bweb", "confirm": "bweb"}, bob)
	do("m", func() { g.p.execution(bg).MaintainGrants() })
	call("m", "domain_list", D{}, bob)
	rows("m")
	records("m")
}
