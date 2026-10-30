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

// A grant asks its tenant at most delegatedAsksPerMinute times a minute, and
// the gateway endpoint answers a recent refusal without asking again (#166).
func TestDelegatedAsksAreBounded(t *testing.T) {
	p, _ := fixture(t)
	p.Config["zone_dir"] = t.TempDir()
	p.Store.SitePut("zone", "lab.example", D{"id": "0123456789abcdef0123456789abcdef", "name": "lab.example", "tenants": []int{1}})
	p.Store.Put("machines", "10100", 1, D{"vmid": 10100, "tenant_n": 1, "name": "web", "ip": "10.200.1.10"})
	p.Store.Put("domain_grants", "g0", 1, D{"id": "g0", "tenant_n": 1, "kind": "delegated", "name": "*.a.lab.example", "zone": "lab.example", "granted_at": 1, "request_id": "r"})
	p.Store.Put("domains", "dg0", 1, D{"id": "dg0", "tenant_n": 1, "vmid": 10100, "grant": "g0", "name": "*.a.lab.example", "slug": "alice", "target_port": 8443, "state": "ready", "ready_at": 1})
	var asked atomic.Int32
	p.tenantAsk = func(string, int, string) bool { asked.Add(1); return false }
	limited := 0
	for i := range delegatedAsksPerMinute + 5 {
		if _, why := p.execution(context.Background()).AskDelegated(fmt.Sprintf("n%d.a.lab.example", i)); why == "rate_limited" {
			limited++
		}
	}
	if asked.Load() != delegatedAsksPerMinute || limited != 5 {
		t.Fatalf("tenant asked %d times, %d limited", asked.Load(), limited)
	}
	if rows := p.Store.Objects("delegated_names"); len(rows) != 0 {
		t.Fatalf("limited asks kept places: %d", len(rows))
	}
	p.delegatedAsks = askLimiter{}
	asked.Store(0)
	app := NewApp(p, nil)
	for range 3 {
		r := httptest.NewRequest("GET", "/gateway/ask?domain=again.a.lab.example", nil)
		r.RemoteAddr, r.Host = "10.200.0.2:41000", "10.200.0.3:8080"
		w := httptest.NewRecorder()
		app.ServeHTTP(w, r)
		if w.Code != 404 {
			t.Fatalf("ask answered %d", w.Code)
		}
	}
	if asked.Load() != 1 {
		t.Fatalf("tenant asked %d times for one refused name", asked.Load())
	}
	// A limited name is not remembered: it passes once the grant has room.
	p.delegatedAsks = askLimiter{}
	for range delegatedAsksPerMinute {
		p.delegatedAsks.allow("g0")
	}
	p.tenantAsk = func(string, int, string) bool { return true }
	ask := func() int {
		r := httptest.NewRequest("GET", "/gateway/ask?domain=late.a.lab.example", nil)
		r.RemoteAddr, r.Host = "10.200.0.2:41000", "10.200.0.3:8080"
		w := httptest.NewRecorder()
		app.ServeHTTP(w, r)
		return w.Code
	}
	if code := ask(); code != 404 {
		t.Fatalf("limited ask answered %d", code)
	}
	p.delegatedAsks.mu.Lock()
	p.delegatedAsks.asks = nil
	p.delegatedAsks.mu.Unlock()
	if code := ask(); code != 200 {
		t.Fatalf("ask after the limit answered %d", code)
	}
}

// A second ask for a name whose tenant is being asked waits for that answer
// instead of failing, and the tenant is asked once (#166).
func TestDelegatedConcurrentAsksShareAnswer(t *testing.T) {
	p, _ := fixture(t)
	p.Config["zone_dir"] = t.TempDir()
	p.Store.SitePut("zone", "lab.example", D{"id": "0123456789abcdef0123456789abcdef", "name": "lab.example", "tenants": []int{1}})
	p.Store.Put("machines", "10100", 1, D{"vmid": 10100, "tenant_n": 1, "name": "web", "ip": "10.200.1.10"})
	p.Store.Put("domain_grants", "g0", 1, D{"id": "g0", "tenant_n": 1, "kind": "delegated", "name": "*.a.lab.example", "zone": "lab.example", "granted_at": 1, "request_id": "r"})
	p.Store.Put("domains", "dg0", 1, D{"id": "dg0", "tenant_n": 1, "vmid": 10100, "grant": "g0", "name": "*.a.lab.example", "slug": "alice", "target_port": 8443, "state": "ready", "ready_at": 1})
	for _, agree := range []bool{true, false} {
		p.delegatedAsks = askLimiter{}
		var asked atomic.Int32
		p.tenantAsk = func(string, int, string) bool { asked.Add(1); time.Sleep(500 * time.Millisecond); return agree }
		name := fmt.Sprintf("shop%v.a.lab.example", agree)
		var wg sync.WaitGroup
		answers := make([]bool, 2)
		for i := range answers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				time.Sleep(time.Duration(i) * 100 * time.Millisecond)
				answers[i], _ = p.execution(context.Background()).AskDelegated(name)
			}()
		}
		wg.Wait()
		if asked.Load() != 1 || answers[0] != agree || answers[1] != agree {
			t.Fatalf("agree=%v: tenant asked %d times, answers %v", agree, asked.Load(), answers)
		}
	}
	// A tenant suspended while the second ask waits: it is refused.
	p.delegatedAsks = askLimiter{}
	p.tenantAsk = func(string, int, string) bool {
		p.Store.Exec("UPDATE tenants SET status='suspended' WHERE n=1")
		time.Sleep(300 * time.Millisecond)
		return true
	}
	var wg sync.WaitGroup
	var why string
	wg.Add(1)
	go func() { defer wg.Done(); p.execution(context.Background()).AskDelegated("late.a.lab.example") }()
	time.Sleep(100 * time.Millisecond)
	_, why = p.execution(context.Background()).AskDelegated("late.a.lab.example")
	wg.Wait()
	if why != "tenant_inactive" {
		t.Fatalf("waiting ask after suspension answered %q", why)
	}
}

// A grant transferred (route removed, names dropped, tenant changed) while
// its old target is being asked: the answer is void, and no name row is
// left under the old tenant (#186).
func TestDelegatedAskDuringTransferLeavesNoRow(t *testing.T) {
	p, _ := fixture(t)
	p.Config["zone_dir"] = t.TempDir()
	p.Store.SitePut("zone", "lab.example", D{"id": "0123456789abcdef0123456789abcdef", "name": "lab.example", "tenants": []int{1, 2}})
	p.Store.Put("machines", "10100", 1, D{"vmid": 10100, "tenant_n": 1, "name": "web", "ip": "10.200.1.10"})
	p.Store.Put("domain_grants", "g0", 1, D{"id": "g0", "tenant_n": 1, "kind": "delegated", "name": "*.a.lab.example", "zone": "lab.example", "granted_at": 1, "request_id": "r"})
	p.Store.Put("domains", "dg0", 1, D{"id": "dg0", "tenant_n": 1, "vmid": 10100, "grant": "g0", "name": "*.a.lab.example", "slug": "alice", "target_port": 8443, "state": "ready", "ready_at": 1})
	p.tenantAsk = func(string, int, string) bool {
		// What domain_remove then domain_transfer do to the store.
		p.Store.Remove("domains", "dg0")
		for _, n := range rowsOf[delegatedName](p.Store, "delegated_names") {
			p.Store.Remove("delegated_names", n.ID)
		}
		g, _ := rowOf[domainGrant](p.Store, "domain_grants", "g0")
		g.TenantN = 2
		p.Store.Put("domain_grants", g.ID, g.TenantN, g.D())
		return true
	}
	ok, why := p.execution(context.Background()).AskDelegated("shop.a.lab.example")
	if ok || why != "released" {
		t.Fatalf("ask during transfer answered %v %q", ok, why)
	}
	if rows := rowsOf[delegatedName](p.Store, "delegated_names"); len(rows) != 0 {
		t.Fatalf("name rows left after transfer: %+v", rows)
	}
	// The grant lost only its route: the reservation is refused as well.
	p.Store.Put("domain_grants", "g0", 1, D{"id": "g0", "tenant_n": 1, "kind": "delegated", "name": "*.a.lab.example", "zone": "lab.example", "granted_at": 1, "request_id": "r"})
	p.Store.Put("domains", "dg0", 1, D{"id": "dg0", "tenant_n": 1, "vmid": 10100, "grant": "g0", "name": "*.a.lab.example", "slug": "alice", "target_port": 8443, "state": "ready", "ready_at": 1})
	p.tenantAsk = func(string, int, string) bool { p.Store.Remove("domains", "dg0"); return true }
	if ok, why := p.execution(context.Background()).AskDelegated("blog.a.lab.example"); ok || why != "released" {
		t.Fatalf("ask after route removal answered %v %q", ok, why)
	}
	if rows := rowsOf[delegatedName](p.Store, "delegated_names"); len(rows) != 0 {
		t.Fatalf("name rows left after route removal: %+v", rows)
	}
}

// The gateway answers delegated names agreed to before itself, so a restart
// while the control plane is down keeps their sites (#166).
func TestGatewayAnswersKnownDelegatedNames(t *testing.T) {
	grant := D{"id": "g0", "tenant_n": 1, "kind": "delegated", "name": "*.a.lab.example", "zone": "lab.example"}
	state := D{
		"tenants":       []any{D{"n": 1, "slug": "alice"}},
		"machines":      []any{D{"vmid": 10100, "tenant_n": 1, "name": "web", "ip": "10.200.1.10"}},
		"domains":       []any{D{"id": "dg0", "tenant_n": 1, "vmid": 10100, "grant": "g0", "name": "*.a.lab.example", "target_port": 8443, "state": "ready"}},
		"domain_grants": []any{grant},
		"delegated_names": []any{
			D{"id": "shop.a.lab.example", "grant": "g0"},
			D{"id": "old.a.lab.example", "grant": "gone"},
		},
	}
	caddy, _, _ := gatewayConfig(state, "carrel.winlab.tw", nil, nil)
	for _, want := range []string{
		"ask http://127.0.0.1:2020/gateway/ask",
		"http://127.0.0.1:2020 {\n bind 127.0.0.1\n @known query domain=shop.a.lab.example\n handle @known {\n  respond 200\n }\n handle {\n  reverse_proxy 10.200.0.3:8080\n }\n}",
	} {
		if !strings.Contains(caddy, want) {
			t.Fatalf("missing %q in\n%s", want, caddy)
		}
	}
	if strings.Contains(caddy, "old.a.lab.example") {
		t.Fatalf("a released grant's name is answered:\n%s", caddy)
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
