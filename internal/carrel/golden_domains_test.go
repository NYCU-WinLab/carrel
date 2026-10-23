package carrel

// TestGoldenDomainEdges was written for the review of #85. Besides MCP
// results and adapter requests it records Cloudflare writes, domain rows
// while jobs run, operation rows and the public status: certificates that
// queue, rows without an operation ID, the maintenance pass and the last
// domain's DNS record.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// statefulDNS keeps records like Cloudflare does and logs every write. With
// list, a GET without a name lists every record, as zone checks read them.
type statefulDNS struct {
	mu      sync.Mutex
	records map[string][]D
	log     []string
	n       int
	list    bool
	zones   []D
	// failPatches makes the next PATCH requests fail as a 502 would.
	failPatches int
}

func (f *statefulDNS) serve(t *testing.T) *httptest.Server {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		var body D
		_ = json.NewDecoder(r.Body).Decode(&body)
		id := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		result := any(D{})
		switch {
		case strings.HasSuffix(r.URL.Path, "/zones"):
			// Zone lookup by name, as zone_add asks with the new token.
			found := []D{}
			for _, z := range f.zones {
				if z["name"] == r.URL.Query().Get("name") && r.Header.Get("Authorization") == "Bearer "+str(z["token"]) {
					found = append(found, pick(z, "id", "name"))
				}
			}
			result = found
			_ = json.NewEncoder(w).Encode(D{"success": true, "result": result})
			return
		}
		if r.Method == "PATCH" && f.failPatches > 0 {
			f.failPatches--
			f.log = append(f.log, "PATCH "+r.URL.Path+" failed 502")
			w.WriteHeader(502)
			_ = json.NewEncoder(w).Encode(D{"success": false})
			return
		}
		switch r.Method {
		case "GET":
			if rs := f.records[r.URL.Query().Get("name")]; rs != nil {
				result = rs
			} else if f.list && r.URL.Query().Get("name") == "" {
				all := []D{}
				names := []string{}
				for name := range f.records {
					names = append(names, name)
				}
				sort.Strings(names)
				for _, name := range names {
					all = append(all, f.records[name]...)
				}
				result = all
			} else {
				result = []D{}
			}
		case "POST":
			f.n++
			created := merge(body, D{"id": fmt.Sprintf("r%d", f.n)})
			f.records[str(body["name"])] = []D{created}
			result = created
		case "DELETE":
			for k, rs := range f.records {
				if len(rs) > 0 && rs[0]["id"] == id {
					delete(f.records, k)
				}
			}
		case "PATCH":
			for _, rs := range f.records {
				if len(rs) > 0 && rs[0]["id"] == id {
					for k, v := range body {
						rs[0][k] = v
					}
				}
			}
		}
		if r.Method != "GET" {
			f.log = append(f.log, r.Method+" "+r.URL.Path+" "+string(encoded(body)))
		}
		_ = json.NewEncoder(w).Encode(D{"success": true, "result": result})
	}))
	t.Cleanup(s.Close)
	return s
}

func TestGoldenDomainEdges(t *testing.T) {
	saved := randomSource
	randomSource = &seededReader{}
	t.Cleanup(func() { randomSource = saved })
	p, b, _ := originFixture(t)
	dns := &statefulDNS{records: map[string][]D{}}
	p.Config["cloudflare_api"] = dns.serve(t).URL
	p.sshProbe = func(context.Context, D) bool { return true }
	p.Config["cloudflare_token"] = "test"
	for _, slug := range []string{"alice", "bob"} {
		crt, key := testPair(t, "*."+slug+".winlab.tw")
		p.execution(context.Background()).storeCertificate(slug, crt, key)
	}
	p.Store.Put("certificates", "1", 1, D{"id": "1", "tenant_n": 1, "slug": "alice"})
	p.Store.Put("certificates", "2", 2, D{"id": "2", "tenant_n": 2, "slug": "bob"})
	var mu sync.Mutex
	answers := []func() D{}
	p.certificatePrepare = func(D) D {
		mu.Lock()
		defer mu.Unlock()
		if len(answers) > 0 {
			a := answers[0]
			answers = answers[1:]
			return a()
		}
		return D{"state": "ready"}
	}
	cert := func(a func() D) { mu.Lock(); answers = append(answers, a); mu.Unlock() }
	rec := &recorder{fakeBackend: b, p: p}
	p.Backend = rec
	ctx, stop := context.WithCancel(context.Background())
	t.Cleanup(stop)
	go rec.guests(ctx)
	runQueue(p)
	g := &goldenRun{t: t, p: p, app: NewApp(p, nil), rec: rec, tools: map[string]bool{}}
	domainEdgeScenario(g, dns, cert)
	g.dump()
	checkGolden(t, "domain-edges.txt", strings.Join(g.lines, "\n")+"\n")
}

func domainEdgeScenario(g *goldenRun, dns *statefulDNS, cert func(func() D)) {
	alice, bob := person("alice", false), person("bob", false)
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
	// racy submits a job that the queue may or may not have picked up by the
	// time the response is rendered (issue #115): those fields are masked.
	racy := func(step, tool string, a, who D) D {
		r := g.app.Call(context.Background(), tool, a, who)
		shown := clone(r)
		if op := obj(shown["operation"]); op != nil {
			for _, k := range []string{"attempts", "phase", "state", "next_action", "poll_after_seconds", "updated_at"} {
				if _, ok := op[k]; ok {
					op[k] = "<racy>"
				}
			}
		}
		g.record(step, tool, shown)
		flush(step)
		return r
	}
	do := func(step string, f func()) { g.do(step, f); flush(step) }
	rows := func(step string) {
		for _, data := range g.p.Store.objectData("domains") {
			g.lines = append(g.lines, step+" row "+normalize([]byte(data)))
		}
	}
	opRow := func(step string, id any) {
		g.lines = append(g.lines, step+" op "+normalize(encoded(g.p.Store.Get("operations", str(id)))))
	}
	// wait polls an operation until its state or phase is one of want.
	wait := func(step string, id any, want ...string) {
		for deadline := time.Now().Add(8 * time.Second); time.Now().Before(deadline); time.Sleep(2 * time.Millisecond) {
			op := g.p.Store.Get("operations", str(id))
			for _, w := range want {
				if op["state"] == w || op["phase"] == w {
					g.lines = append(g.lines, fmt.Sprintf("%s reached %s", step, w))
					flush(step)
					return
				}
			}
		}
		g.lines = append(g.lines, step+" timeout "+strings.Join(want, ","))
	}
	settle := func() {
		for deadline := time.Now().Add(8 * time.Second); len(g.p.Store.ActiveOperations()) > 0 && time.Now().Before(deadline); {
			time.Sleep(5 * time.Millisecond)
		}
		for _, sent := range g.rec.take() {
			g.lines = append(g.lines, "settle adapter "+sent)
		}
	}
	status := func(step string) {
		s := g.p.execution(bg).PublicStatus()
		g.lines = append(g.lines, step+" status "+normalize(encoded(D{"tenants": s["tenants"], "others": s["others"]})))
	}
	maintain := func(step string) {
		do(step, func() { g.p.execution(bg).MaintainDomains() })
		rows(step)
	}
	later := func(seconds float64) func() D {
		return func() D { return D{"state": "queued", "ready_at": now() + seconds} }
	}
	opOf := func(r D) any { return obj(r["operation"])["id"] }

	call("s", "ssh_key_add", D{"key": key}, alice)
	call("s", "ssh_key_add", D{"key": key}, bob)
	call("s", "machine_create", D{"name": "web"}, alice)
	call("s", "machine_create", D{"name": "api"}, alice)
	call("s", "machine_create", D{"name": "bweb"}, bob)
	web, api, bweb := machineRow(g, 1, "web"), machineRow(g, 1, "api"), machineRow(g, 2, "bweb")
	status("s")

	// q1: certificate queued with a fractional ready_at, then ready.
	cert(later(0.5))
	r := racy("q1", "domain_add", D{"machine": "web", "sub": "q1", "target_port": 8080, "wait_seconds": 0}, alice)
	wait("q1", opOf(r), "waiting")
	rows("q1w")
	opRow("q1w", opOf(r))
	maintain("q1m")
	status("q1w")
	wait("q1", opOf(r), "succeeded", "failed")
	settle()
	call("q1", "operation_get", D{"id": opOf(r), "detail": "full"}, alice)
	rows("q1")

	// q2: queued with a whole-second ready_at given as int64.
	cert(func() D { return D{"state": "queued", "ready_at": time.Now().Unix() + 1} })
	r = racy("q2", "domain_add", D{"machine": "api", "sub": "q2", "target_port": 3000, "wait_seconds": 0}, alice)
	wait("q2", opOf(r), "waiting")
	rows("q2w")
	opRow("q2w", opOf(r))
	wait("q2", opOf(r), "succeeded", "failed")
	settle()
	call("q2", "operation_get", D{"id": opOf(r), "detail": "full"}, alice)

	// q3: queued with a ready_at already past.
	cert(later(-5))
	call("q3", "domain_add", D{"machine": "web", "sub": "q3", "target_port": 8081, "detail": "full"}, alice)
	rows("q3")

	// r1: the record's operation changes while the job waits.
	cert(later(0.5))
	r = racy("r1", "domain_add", D{"machine": "web", "sub": "r1", "target_port": 8082, "wait_seconds": 0}, alice)
	wait("r1", opOf(r), "waiting")
	for _, d := range g.p.Store.Objects("domains", 1) {
		if d["sub"] == "r1" {
			d["operation_id"] = "intruder"
			g.p.Store.Put("domains", d["id"], 1, d)
		}
	}
	wait("r1", opOf(r), "succeeded", "failed")
	settle()
	opRow("r1", opOf(r))
	rows("r1")
	// r2: the record starts deleting while the job waits.
	cert(later(0.5))
	r = racy("r2", "domain_add", D{"machine": "web", "sub": "r2", "target_port": 8083, "wait_seconds": 0}, alice)
	wait("r2", opOf(r), "waiting")
	for _, d := range g.p.Store.Objects("domains", 1) {
		if d["sub"] == "r2" {
			d["state"] = "deleting"
			g.p.Store.Put("domains", d["id"], 1, d)
		}
	}
	wait("r2", opOf(r), "succeeded", "failed")
	settle()
	opRow("r2", opOf(r))
	rows("r2")
	for _, d := range g.p.Store.Objects("domains", 1) {
		if d["sub"] == "r1" || d["sub"] == "r2" {
			g.p.Store.Remove("domains", d["id"])
		}
	}

	// l: a ready legacy record without an operation ID, reused directly and
	// by a deployment.
	g.p.Store.Put("domains", "legacy0000000001", 1, D{"id": "legacy0000000001", "tenant_n": 1, "vmid": web["vmid"], "sub": "old", "slug": "alice", "name": "old.alice.winlab.tw", "target_port": 8080, "state": "ready", "ready_at": 1})
	call("l", "domain_add", D{"machine": "web", "sub": "old", "target_port": 8080, "detail": "full"}, alice)
	rows("l")
	legacy := D{"publications": []any{D{"machine": "web", "protocol": "https", "port": 8080, "sub": "old"}, D{"machine": "web", "protocol": "tcp", "port": 22}}}
	call("l", "deployment_plan", obj(copyValue(legacy)), alice)
	applied := call("l", "deployment_apply", obj(copyValue(legacy)), alice)
	call("l", "operation_get", D{"id": opOf(applied), "detail": "full"}, alice)

	// p: a deployment with a new machine waits for its certificate; it also
	// reuses q1.
	spec := D{
		"machines":     []any{D{"name": "fresh"}},
		"publications": []any{D{"machine": "fresh", "protocol": "https", "port": 80, "sub": "fresh"}, D{"machine": "web", "protocol": "https", "port": 8084, "sub": "shop"}, D{"machine": "web", "protocol": "https", "port": 8080, "sub": "q1"}},
	}
	cert(later(0.6))
	call("p", "deployment_plan", obj(copyValue(spec)), alice)
	r = racy("p", "deployment_apply", merge(obj(copyValue(spec)), D{"wait_seconds": 0}), alice)
	wait("p", opOf(r), "waiting_for_certificate")
	rows("pw")
	opRow("pw", opOf(r))
	wait("p", opOf(r), "succeeded", "failed", "rolled_back")
	settle()
	call("p", "operation_get", D{"id": opOf(r), "detail": "full"}, alice)
	call("p", "domain_list", D{}, alice)
	call("p", "machine_get", D{"machine": "fresh", "detail": "full"}, alice)

	// m: maintenance with active operations, missing operation IDs, a
	// suspended tenant and a future ready_at.
	row := func(id, sub string, n int, vmid any, slug, state string, readyAt any, op any) {
		d := D{"id": id, "tenant_n": n, "vmid": vmid, "sub": sub, "slug": slug, "name": sub + "." + slug + ".winlab.tw", "target_port": 8090, "state": state, "ready_at": readyAt}
		if op != nil {
			d["operation_id"] = op
		}
		g.p.Store.Put("domains", id, n, d)
	}
	row("act1000000000001", "act1", 1, web["vmid"], "alice", "queued", 1, "opA")
	row("act2000000000002", "act2", 1, web["vmid"], "alice", "queued", 1, nil)
	row("act3000000000003", "act3", 1, api["vmid"], "alice", "configuring", 1, "opB")
	row("fut0000000000004", "fut", 1, api["vmid"], "alice", "queued", 4102444800, "opZ")
	row("bq00000000000005", "bq", 2, bweb["vmid"], "bob", "queued", 1, nil)
	g.p.Store.Put("operations", "opA", 1, D{"id": "opA", "tenant_n": 1, "tool": "machine_power", "state": "waiting", "phase": "waiting_for_machine_operation", "ready_at": 4102444800})
	g.p.Store.Put("operations", "opC", 1, D{"id": "opC", "tenant_n": 1, "tool": "domain_add", "state": "waiting", "phase": "waiting_for_certificate", "ready_at": 4102444800, "domain_target": []any{"act2000000000002", nil}})
	g.p.Store.Exec("UPDATE tenants SET status='suspended' WHERE n=2")
	maintain("m1")
	status("m1")
	g.p.Store.Remove("operations", "opA")
	g.p.Store.Remove("operations", "opC")
	maintain("m2")
	g.p.Store.Exec("UPDATE tenants SET status='active' WHERE n=2")
	cert(func() D { return D{"state": "queued", "ready_at": now() - 1} })
	maintain("m3")
	maintain("m4")
	status("m4")
	call("m", "domain_list", D{}, bob)

	// b: domain_remove waits behind an operation on the same machine.
	g.p.Store.Put("operations", "busy", 1, D{"id": "busy", "tenant_n": 1, "tool": "machine_power", "state": "running", "phase": "waiting_for_guest", "machine_target": D{"vmid": web["vmid"]}})
	r = racy("b", "domain_remove", D{"name": "act1.alice.winlab.tw", "wait_seconds": 0}, alice)
	wait("b", opOf(r), "waiting_for_machine_operation", "succeeded", "failed")
	opRow("b", opOf(r))
	g.p.Store.Remove("operations", "busy")
	wait("b", opOf(r), "succeeded", "failed")
	settle()
	call("b", "operation_get", D{"id": opOf(r), "detail": "full"}, alice)

	// x: rollback of a failed deployment with an HTTPS publication.
	boom := D{"machines": []any{D{"name": "boom"}}, "publications": []any{D{"machine": "boom", "protocol": "https", "port": 80, "sub": "boom"}}}
	failed := call("x", "deployment_apply", obj(copyValue(boom)), alice)
	call("x", "operation_get", D{"id": opOf(failed), "detail": "full"}, alice)
	rows("x")

	// d: removals, legacy first; the last live domain drops the DNS record
	// even with another one still deleting.
	call("d", "domain_remove", D{"name": "old.alice.winlab.tw", "dry_run": true, "detail": "full"}, alice)
	call("d", "domain_remove", D{"name": "old.alice.winlab.tw", "detail": "full"}, alice)
	names := []string{}
	for _, d := range g.p.Store.Objects("domains", 1) {
		names = append(names, str(d["name"]))
	}
	for i, name := range names {
		if i == len(names)-1 {
			row("del0000000000006", "del", 1, api["vmid"], "alice", "deleting", 1, "opD")
		}
		call("d", "domain_remove", D{"name": name, "detail": "full"}, alice)
	}
	maintain("d1")
	status("d1")
	g.p.Store.Remove("domains", "del0000000000006")
	maintain("d2")
	call("d", "domain_list", D{}, alice)
	call("d", "domain_remove", D{"name": "bq.bob.winlab.tw"}, bob)
	maintain("d3")
	status("d3")
}
