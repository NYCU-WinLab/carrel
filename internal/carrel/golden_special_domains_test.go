package carrel

// TestGoldenSpecialDomains records special domains (PLAN 6.10) end to end:
// requests and the rules that refuse them, approval with and without adopt,
// publication under exact and wildcard grants, the gateway configuration,
// the DNS writes, and the release of an unused grant.

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestGoldenSpecialDomains(t *testing.T) {
	saved := randomSource
	randomSource = &seededReader{}
	t.Cleanup(func() { randomSource = saved })
	p, b, _ := originFixture(t)
	dns := &statefulDNS{records: map[string][]D{}, list: true, zones: []D{{"id": "0123456789abcdef0123456789abcdef", "name": "lab.example", "token": "zone-token-0123456789abcdef"}}}
	p.Config["cloudflare_api"] = dns.serve(t).URL
	p.Config["cloudflare_token"] = "test"
	p.Config["zone_dir"] = t.TempDir()
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

	// z: an added zone, open to alice only. Its token stays out of results,
	// rows and the audit log.
	call("z", "zone_add", D{"name": "lab.example", "token": "wrong-token-0123456789abcdef", "tenants": []any{"alice"}}, admin)
	call("z", "zone_add", D{"name": "sub.winlab.tw", "token": "zone-token-0123456789abcdef"}, admin)
	call("z", "zone_add", D{"name": "lab.example", "token": "zone-token-0123456789abcdef", "tenants": []any{"alice"}, "dry_run": true}, admin)
	// The token can stay off the client: an admin places the file first
	// (issue #161).
	call("z", "zone_add", D{"name": "lab.example", "tenants": []any{"alice"}}, admin)
	must(os.MkdirAll(g.p.execution(bg).zoneDir(), 0700))
	must(os.WriteFile(g.p.execution(bg).zoneTokenPath("lab.example"), []byte("zone-token-0123456789abcdef\n"), 0644))
	call("z", "zone_add", D{"name": "lab.example", "tenants": []any{"alice"}}, admin)
	if info, err := os.Stat(g.p.execution(bg).zoneTokenPath("lab.example")); err != nil || info.Mode().Perm() != 0600 {
		g.lines = append(g.lines, "z token file not 0600")
	}
	// A new token alone keeps the tenant list.
	call("z", "zone_add", D{"name": "lab.example", "token": "zone-token-0123456789abcdef"}, admin)
	call("z", "zone_list", D{}, admin)
	call("z", "domain_request", D{"name": "app.lab.example", "reason": "not open to bob"}, bob)
	call("z", "domain_request", D{"name": "*.lab.example", "kind": "wildcard", "reason": "the zone's wildcard"}, alice)
	call("z", "domain_request", D{"name": "nowhere.example", "reason": "no such zone"}, alice)
	www := call("z", "domain_request", D{"name": "www.lab.example", "reason": "alice's site"}, alice)
	call("z", "request_approve", D{"id": requestID(www)}, admin)
	call("z", "domain_add", D{"machine": "web", "name": "www.lab.example", "target_port": 8080}, alice)
	call("z", "zone_remove", D{"name": "lab.example", "confirm": "lab.example"}, admin)
	rows("z")
	// dl: a delegated name in alice's own zone. The gateway asks before it
	// obtains each certificate (delegated.go).
	call("dl", "domain_request", D{"name": "*.apps.winlab.tw", "kind": "delegated", "reason": "not a zone of one tenant"}, alice)
	call("dl", "domain_request", D{"name": "*.d.lab.example", "kind": "delegated", "reason": "not open to bob"}, bob)
	dl := call("dl", "domain_request", D{"name": "*.d.lab.example", "kind": "delegated", "reason": "an ingress controller"}, alice)
	call("dl", "request_approve", D{"id": requestID(dl)}, admin)
	ask := func(step, name string) {
		ok, why := g.p.execution(bg).AskDelegated(name)
		g.lines = append(g.lines, fmt.Sprintf("%s ask %s %v %s", step, name, ok, why))
	}
	g.p.tenantAsk = func(address string, port int, name string) bool {
		g.lines = append(g.lines, fmt.Sprintf("dl tenant ask %s:%d %s", address, port, name))
		return name != "refused.d.lab.example"
	}
	ask("dl", "x.d.lab.example")
	call("dl", "domain_add", D{"machine": "web", "name": "x.d.lab.example", "target_port": 8443}, alice)
	call("dl", "domain_add", D{"machine": "web", "name": "*.d.lab.example", "target_port": 8443}, alice)
	ask("dl", "x.d.lab.example")
	ask("dl", "x.d.lab.example")
	ask("dl", "a.b.d.lab.example")
	ask("dl", "a.b.c.d.lab.example")
	ask("dl", "refused.d.lab.example")
	ask("dl", "x.other.example")
	ask("dl", "Bad_Name.d.lab.example")
	for i := range 20 {
		ok, _ := g.p.execution(bg).AskDelegated(fmt.Sprintf("n%d.d.lab.example", i))
		if !ok && i < 17 {
			g.lines = append(g.lines, fmt.Sprintf("dl budget ended early at %d", i))
		}
	}
	ask("dl", "late.d.lab.example")
	ask("dl", "x.d.lab.example")
	rows("dl")
	// p: a special port and an SRV record that names it.
	call("p", "port_request", D{"public_port": 25565, "reason": "minecraft", "dry_run": true}, alice)
	mc := call("p", "port_request", D{"public_port": 25565, "reason": "minecraft"}, alice)
	call("p", "port_request", D{"public_port": 25565, "reason": "mine too"}, bob)
	call("p", "port_request", D{"public_port": 25565, "proto": "udp", "reason": "another protocol"}, bob)
	for _, port := range []int{22, 443, 20030, 31001} {
		call("p", "port_request", D{"public_port": port, "reason": "never granted"}, bob)
	}
	call("p", "request_approve", D{"id": requestID(mc), "adopt": true}, admin)
	call("p", "request_approve", D{"id": requestID(mc)}, admin)
	call("p", "port_list", D{}, alice)
	call("p", "port_open", D{"machine": "bweb", "port": 25565, "proto": "tcp", "public_port": 25565}, bob)
	opened := call("p", "port_open", D{"machine": "web", "port": 25565, "proto": "tcp", "public_port": 25565}, alice)
	call("p", "port_open", D{"machine": "web", "port": 25566, "proto": "tcp", "public_port": 25565}, alice)
	srv := call("p", "domain_request", D{"name": "_minecraft._tcp.mc.winlab.tw", "kind": "srv", "reason": "minecraft"}, alice)
	call("p", "domain_request", D{"name": "_minecraft._tcp.winlab.tw", "kind": "srv", "reason": "the zone apex"}, alice)
	// An SRV record speaks for its name: not under another tenant's grant.
	call("p", "domain_request", D{"name": "_minecraft._tcp.video.winlab.tw", "kind": "srv", "reason": "alice's name"}, bob)
	call("p", "domain_request", D{"name": "_minecraft._tcp.x.lab.winlab.tw", "kind": "srv", "reason": "under bob's wildcard"}, alice)
	// Someone else's address at the name needs adopt.
	dns.records["mc2.winlab.tw"] = []D{{"id": "old3", "type": "A", "name": "mc2.winlab.tw", "content": "140.113.194.231"}}
	call("p", "domain_request", D{"name": "_minecraft._tcp.mc2.winlab.tw", "kind": "srv", "reason": "foreign base", "dry_run": true}, alice)
	call("p", "request_approve", D{"id": requestID(srv)}, admin)
	call("p", "domain_add", D{"machine": "web", "name": "_minecraft._tcp.mc.winlab.tw", "target_port": 25566}, alice)
	call("p", "domain_add", D{"machine": "web", "name": "_minecraft._tcp.mc.winlab.tw", "target_port": 25565}, alice)
	// Nor may another tenant take the name an SRV record speaks for.
	call("p", "domain_request", D{"name": "mc.winlab.tw", "reason": "over alice's SRV"}, bob)
	do("p", func() { g.p.execution(bg).MaintainGrants() })
	do("p", func() { g.p.execution(bg).MaintainSpecialPorts() })
	call("p", "port_list", D{}, alice)
	call("p", "port_close", D{"id": obj(obj(obj(opened["operation"])["result"])["port"])["id"]}, alice)
	do("p", func() { g.p.execution(bg).MaintainGrants() })
	do("p", func() { g.p.execution(bg).MaintainSpecialPorts() })
	call("p", "port_list", D{}, alice)
	rows("p")
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
