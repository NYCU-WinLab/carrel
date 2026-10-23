package carrel

import (
	"context"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestGrantCovers(t *testing.T) {
	exact := domainGrant{Kind: "exact", Name: "video.winlab.tw"}
	wild := domainGrant{Kind: "wildcard", Name: "*.lab.winlab.tw"}
	for _, c := range []struct {
		g    domainGrant
		name string
		want bool
	}{
		{exact, "video.winlab.tw", true},
		{exact, "x.video.winlab.tw", false},
		{wild, "*.lab.winlab.tw", true},
		{wild, "api.lab.winlab.tw", true},
		{wild, "a.b.lab.winlab.tw", false},
		{wild, "lab.winlab.tw", false},
		{wild, "API.lab.winlab.tw", false},
		{wild, "x.lab.winlab.tw.evil", false},
	} {
		if got := c.g.covers(c.name); got != c.want {
			t.Errorf("%s covers %s = %v", c.g.Name, c.name, got)
		}
	}
}

// The gateway checks the grants it renders again: a bad row in the database
// must not reach another tenant's subtree or inject Caddyfile syntax.
func TestGatewayRefusesInvalidGrants(t *testing.T) {
	state := func(grant D, name string) D {
		return D{
			"tenants":       []any{D{"n": 1, "slug": "alice"}, D{"n": 2, "slug": "bob"}},
			"machines":      []any{D{"vmid": 10100, "tenant_n": 1, "name": "web", "ip": "10.200.1.10"}},
			"domain_grants": []any{grant},
			"domains":       []any{D{"id": "d1", "tenant_n": 1, "vmid": 10100, "grant": grant["id"], "name": name, "target_port": 80, "state": "ready"}},
		}
	}
	for _, c := range []struct {
		why   string
		grant D
		name  string
	}{
		{"another tenant's subtree", D{"id": "g1", "tenant_n": 1, "kind": "wildcard", "name": "*.bob.winlab.tw"}, "x.bob.winlab.tw"},
		{"another tenant's apex", D{"id": "g1", "tenant_n": 1, "kind": "exact", "name": "bob.winlab.tw"}, "bob.winlab.tw"},
		{"own subtree", D{"id": "g1", "tenant_n": 1, "kind": "exact", "name": "x.alice.winlab.tw"}, "x.alice.winlab.tw"},
		{"Caddyfile syntax", D{"id": "g1", "tenant_n": 1, "kind": "exact", "name": "v.winlab.tw {\n respond 1\n}\nx.winlab.tw"}, "v.winlab.tw"},
		{"kind and name disagree", D{"id": "g1", "tenant_n": 1, "kind": "exact", "name": "*.lab.winlab.tw"}, "*.lab.winlab.tw"},
		{"origin", D{"id": "g1", "tenant_n": 1, "kind": "exact", "name": "carrel.winlab.tw"}, "carrel.winlab.tw"},
		{"domain of another tenant", D{"id": "g1", "tenant_n": 2, "kind": "exact", "name": "video.winlab.tw"}, "video.winlab.tw"},
		{"name outside the grant", D{"id": "g1", "tenant_n": 1, "kind": "wildcard", "name": "*.lab.winlab.tw"}, "x.other.winlab.tw"},
	} {
		err := attempt(func() { gatewayConfig(state(c.grant, c.name), "carrel.winlab.tw", nil, nil) })
		if err == nil {
			t.Errorf("%s: accepted", c.why)
		}
	}
	// The own apex is allowed: the tenant's site block is its wildcard.
	ok := attempt(func() {
		gatewayConfig(state(D{"id": "g1", "tenant_n": 1, "kind": "exact", "name": "alice.winlab.tw"}, "alice.winlab.tw"), "carrel.winlab.tw", nil, nil)
	})
	if ok == nil || !strings.Contains(str(obj(failureResult(ok)["error"])["message"]), "Missing domain certificate") {
		t.Fatalf("own apex: %v", ok)
	}
}

// A record someone else wrote moves only for a grant approved with adopt,
// and only once the gateway holds the grant's certificate.
func TestGrantRecordAdoptsOnlyWhenAllowed(t *testing.T) {
	p, _, _ := originFixture(t)
	dns := &statefulDNS{records: map[string][]D{}}
	p.Config["cloudflare_api"] = dns.serve(t).URL
	e := p.execution(context.Background())
	g := domainGrant{ID: "g1", TenantN: 1, Kind: "exact", Name: "video.winlab.tw"}
	dns.records[g.Name] = []D{{"id": "old", "type": "A", "name": g.Name, "content": "140.113.194.229"}}
	crt, key := testPair(t, g.Name)
	e.storeCertificate(g.lineage(), crt, key)
	e.GrantRecord(g, false)
	if len(dns.log) != 0 {
		t.Fatal("moved a record before the gateway held the certificate")
	}
	p.delivered.Store(map[string]any{g.lineage(): fingerprint(string(crt))})
	if err := attempt(func() { e.GrantRecord(g, false) }); err == nil || len(dns.log) != 0 {
		t.Fatalf("replaced a foreign record without adopt: %v %v", err, dns.log)
	}
	g.Adopt = true
	e.GrantRecord(g, false)
	if len(dns.log) != 1 || !strings.HasPrefix(dns.log[0], "PATCH") || dns.records[g.Name][0]["comment"] != g.owner() || dns.records[g.Name][0]["content"] != "140.113.60.184" {
		t.Fatal(dns.log, dns.records[g.Name])
	}
	// Once it is carrel's, the record stays put; removal deletes it.
	e.GrantRecord(g, false)
	if len(dns.log) != 1 {
		t.Fatal(dns.log)
	}
	e.GrantRecord(g, true)
	if len(dns.records[g.Name]) != 0 {
		t.Fatal(dns.records[g.Name])
	}
}

// A name belongs to the longest managed zone it sits in; the site's zone
// always counts, others only once added. ACME challenges and grant records
// go to that zone.
func TestZoneOfPicksTheLongestManagedZone(t *testing.T) {
	p, _ := fixture(t)
	p.Config["zone_dir"] = t.TempDir()
	e := p.execution(context.Background())
	p.Store.SitePut("zone", "lab.example", D{"id": "0123456789abcdef0123456789abcdef", "name": "lab.example", "tenants": []int{1}})
	p.Store.SitePut("zone", "deep.lab2.example", D{"id": "fedcba9876543210fedcba9876543210", "name": "deep.lab2.example"})
	for name, want := range map[string]string{
		"video.winlab.tw":       "winlab.tw",
		"*.x.winlab.tw":         "winlab.tw",
		"www.lab.example":       "lab.example",
		"lab.example":           "lab.example",
		"a.deep.lab2.example":   "deep.lab2.example",
		"other.lab2.example":    "",
		"winlab.tw.lab.example": "lab.example",
	} {
		got, ok := e.zoneOf(name)
		if got != want || ok != (want != "") {
			t.Errorf("%s: %q %v", name, got, ok)
		}
	}
	if !e.zoneOpen("lab.example", 1) || e.zoneOpen("lab.example", 2) || !e.zoneOpen("deep.lab2.example", 2) || !e.zoneOpen("winlab.tw", 2) {
		t.Fatal("zone openness")
	}
	// Without its token file a zone cannot be used.
	if err := attempt(func() { e.zoneNamed("lab.example") }); err == nil {
		t.Fatal("used a zone without a token")
	}
}

// Only the gateway asks about delegated names: from anywhere else, and by
// the public origin, the endpoint refuses (delegated.go).
func TestGatewayAskIsTheGatewaysAlone(t *testing.T) {
	p, _ := fixture(t)
	p.Config["origin"] = "https://carrel.winlab.tw"
	app := NewApp(p, nil)
	for _, c := range []struct {
		remote, host string
		want         int
	}{
		{"10.200.0.2:41000", "10.200.0.3:8080", 404},
		{"10.200.1.10:41000", "10.200.0.3:8080", 403},
		{"203.0.113.9:41000", "carrel.winlab.tw", 403},
	} {
		r := httptest.NewRequest("GET", "/gateway/ask?domain=x.d.lab.example", nil)
		r.RemoteAddr, r.Host = c.remote, c.host
		w := httptest.NewRecorder()
		app.ServeHTTP(w, r)
		if w.Code != c.want {
			t.Errorf("%s: %d", c.remote, w.Code)
		}
	}
}

// Concurrent asks share the zone's weekly budget: each takes its place
// before the tenant is asked, so no more than the budget get through.
func TestDelegatedBudgetHoldsUnderConcurrentAsks(t *testing.T) {
	p, _ := fixture(t)
	p.Config["zone_dir"] = t.TempDir()
	p.Store.SitePut("zone", "lab.example", D{"id": "0123456789abcdef0123456789abcdef", "name": "lab.example", "tenants": []int{1}})
	p.Store.Put("machines", "10100", 1, D{"vmid": 10100, "tenant_n": 1, "name": "web", "ip": "10.200.1.10"})
	for i, base := range []string{"a.lab.example", "b.lab.example"} {
		id := fmt.Sprintf("g%015d", i)
		p.Store.Put("domain_grants", id, 1, D{"id": id, "tenant_n": 1, "kind": "delegated", "name": "*." + base, "zone": "lab.example", "granted_at": 1, "request_id": "r"})
		p.Store.Put("domains", "d"+id, 1, D{"id": "d" + id, "tenant_n": 1, "vmid": 10100, "grant": id, "name": "*." + base, "slug": "alice", "target_port": 8443, "state": "ready", "ready_at": 1})
	}
	p.tenantAsk = func(string, int, string) bool { time.Sleep(50 * time.Millisecond); return true }
	var allowed atomic.Int32
	var wg sync.WaitGroup
	for i := range 60 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Two grants in one zone: the budget is the zone's.
			base := []string{"a", "b"}[i%2]
			if ok, _ := p.execution(context.Background()).AskDelegated(fmt.Sprintf("r%d.%s.lab.example", i, base)); ok {
				allowed.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := allowed.Load(); got != delegatedWeeklyNames {
		t.Fatalf("%d names allowed, budget %d", got, delegatedWeeklyNames)
	}
	// A refused name gives its place back.
	p.Store.Exec("DELETE FROM objects WHERE kind='delegated_names'")
	p.tenantAsk = func(string, int, string) bool { return false }
	for i := range 30 {
		p.execution(context.Background()).AskDelegated(fmt.Sprintf("no%d.a.lab.example", i))
	}
	if rows := p.Store.Objects("delegated_names"); len(rows) != 0 {
		t.Fatalf("refusals kept places: %d", len(rows))
	}
}

// A rename waits for every operation that may still reach the machine: a
// deployment's bindings, its machines, or a queued job naming it.
func TestRenameRefusesAMachineAnOperationHolds(t *testing.T) {
	p, _ := fixture(t)
	p.Store.Put("machines", "10100", 1, D{"vmid": 10100, "tenant_n": 1, "name": "web", "ip": "10.200.1.10", "kind": "vm", "state": "ready"})
	tenant := p.Store.TenantN(1)
	try := func(op D) any {
		p.Store.Exec("DELETE FROM objects WHERE kind='operations'")
		p.Store.Put("operations", "op1", 1, merge(D{"id": "op1", "tenant_n": 1, "state": "running"}, op))
		return attempt(func() {
			p.execution(context.Background()).RenameMachine(D{"machine": "web", "name": "site", "confirm": "web", "dry_run": true}, tenant)
		})
	}
	for _, op := range []D{
		{"tool": "deployment_apply", "deployment": D{"bindings": D{"10100": "x"}}},
		{"tool": "deployment_apply", "deployment": D{"machines": []any{10100}}},
		{"tool": "machine_power", "machine_target": D{"vmid": 10100}},
		{"tool": "machine_delete", "state": "queued", "args": D{"machine": "web"}},
		{"tool": "deployment_apply", "state": "queued", "args": D{"publications": []any{D{"machine": "web"}}}},
		{"tool": "deployment_apply", "state": "queued", "args": D{"connections": []any{D{"from": "db", "to": "web"}}}},
	} {
		if err := try(op); err == nil {
			t.Errorf("renamed while %v", op)
		}
	}
	if err := try(D{"tool": "machine_power", "machine_target": D{"vmid": 10101}}); err != nil {
		t.Fatalf("refused for another machine's operation: %v", err)
	}
}
