package carrel

// The golden test pins the exact bytes the control plane produces: every MCP
// tool's result, every request sent to a node or the gateway, and every
// stored row. Replacing D maps with structs must keep them byte-identical.
// Regenerate only for an intended change, and say so in the PR:
//
//	go test ./internal/carrel -run TestGolden -update

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "rewrite testdata/golden")

// seededReader stands in for crypto/rand: the same IDs and tokens every run.
type seededReader struct {
	mu   sync.Mutex
	n    uint64
	rest []byte
}

func (r *seededReader) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for len(r.rest) < len(p) {
		var block [8]byte
		binary.BigEndian.PutUint64(block[:], r.n)
		r.n++
		sum := sha256.Sum256(block[:])
		r.rest = append(r.rest, sum[:]...)
	}
	n := copy(p, r.rest)
	r.rest = r.rest[n:]
	return n, nil
}

// Wall-clock values and durations differ every run; their shape stays.
// Clock readings are Unix times (2023 to 2033), wherever they appear.
var (
	volatile = regexp.MustCompile(`"(duration_seconds|age_seconds|report_age_seconds|seconds)":(-?[0-9][0-9.eE+-]*)`)
	epoch    = regexp.MustCompile(`([:\[,])(1[7-9][0-9]{8})(\.[0-9]+)?\b`)
	stamps   = regexp.MustCompile(`"20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z"`)
)

// Test certificates are generated per run.
var pemBlock = regexp.MustCompile(`-----BEGIN ([A-Z ]+)-----[^-]+-----END [A-Z ]+-----(\\n)?`)

func normalize(b []byte) string {
	s := pemBlock.ReplaceAllString(string(b), "<pem $1>")
	s = epoch.ReplaceAllStringFunc(s, func(m string) string {
		if strings.Contains(m, ".") {
			return m[:1] + `"<time:float>"`
		}
		return m[:1] + `"<time:int>"`
	})
	s = stamps.ReplaceAllString(s, `"<stamp>"`)
	return volatile.ReplaceAllStringFunc(s, func(m string) string {
		key, value, _ := strings.Cut(m, ":")
		if strings.ContainsAny(value, ".eE") {
			return key + `:"<float>"`
		}
		return key + `:"<int>"`
	})
}

// recorder answers like a node and keeps the bytes of every request.
type recorder struct {
	*fakeBackend
	p    *Platform
	mu   sync.Mutex
	sent []string
}

func (r *recorder) Call(ctx context.Context, req D, target string) (any, error) {
	r.mu.Lock()
	r.sent = append(r.sent, target+" "+normalize(encoded(req)))
	r.mu.Unlock()
	m := obj(req["machine"])
	switch req["op"] {
	case "create":
		if m["name"] == "boom" {
			return nil, errors.New("create failed")
		}
		return D{"state": "running", "vmid": m["vmid"]}, nil
	case "action":
		switch req["action"] {
		case "start", "reboot":
			return D{"power_state": "running", "changed": true, "boot_changed": true}, nil
		case "resume":
			return D{"power_state": "running", "changed": true, "boot_changed": false}, nil
		case "shutdown", "stop":
			return D{"power_state": "stopped", "changed": true}, nil
		case "pause":
			return D{"power_state": "paused", "changed": true}, nil
		case "delete":
			return D{"state": "absent"}, nil
		}
		return D{"state": "ok"}, nil
	case "status":
		state := "running"
		if current := r.p.Store.Get("machines", str(m["vmid"])); current != nil && contains([]any{"stopped", "paused"}, current["power_state"]) {
			state = str(current["power_state"])
		}
		return D{"status": state}, nil
	case "metrics":
		return []D{{"time": 1, "cpu": 0.25, "mem": 512, "maxmem": 1024}}, nil
	}
	return r.fakeBackend.Call(ctx, req, target)
}

// guests answers every readiness wait once, as a freshly booted guest
// would: a new boot, its NIC addresses, initialization complete.
func (r *recorder) guests(ctx context.Context) {
	answered := map[string]bool{}
	for ctx.Err() == nil {
		for _, op := range r.p.Store.ActiveOperations() {
			if op["phase"] != "waiting_for_guest" {
				continue
			}
			for _, m := range r.p.Store.Objects("machines", integer(op["tenant_n"])) {
				key := str(op["id"]) + "/" + str(m["vmid"])
				if m["kind"] != "vm" || m["state"] != "initializing" || answered[key] {
					continue
				}
				answered[key] = true
				interfaces := []D{}
				for _, nic := range dicts(m["nics"]) {
					interfaces = append(interfaces, D{"mac": nic["mac"], "ip": nic["ip"], "mtu": 1450})
				}
				r.p.Store.Put("guest_reports", m["vmid"], integer(m["tenant_n"]), D{"boot_id": "boot-" + key, "reported_at": now(), "initialization_status": "complete", "application_status": "not_checked", "interfaces": interfaces})
				r.p.notifyReport(integer(m["vmid"]))
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (r *recorder) take() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.sent
	r.sent = nil
	// Node reconciles and the gateway sync run concurrently.
	sort.Strings(out)
	return out
}

type goldenRun struct {
	t     *testing.T
	p     *Platform
	app   *App
	rec   *recorder
	lines []string
	tools map[string]bool
}

func (g *goldenRun) call(step, tool string, args, who D) D {
	g.t.Helper()
	r := g.app.Call(context.Background(), tool, args, who)
	// Admin jobs return queued; let every job finish before the next step.
	for deadline := time.Now().Add(10 * time.Second); len(g.p.Store.ActiveOperations()) > 0; {
		if time.Now().After(deadline) {
			g.t.Fatalf("%s: jobs still active", step)
		}
		time.Sleep(5 * time.Millisecond)
	}
	g.record(step, tool, r)
	return r
}

// submit records a call without waiting for the jobs it leaves queued.
func (g *goldenRun) submit(step, tool string, args, who D) D {
	g.t.Helper()
	r := g.app.Call(context.Background(), tool, args, who)
	g.record(step, tool, r)
	return r
}

func (g *goldenRun) record(step, tool string, r D) {
	g.tools[tool] = true
	g.lines = append(g.lines, step+" mcp "+normalize(encoded(r)))
	for _, sent := range g.rec.take() {
		g.lines = append(g.lines, step+" adapter "+sent)
	}
}

// do records the adapter requests of work outside an MCP call.
func (g *goldenRun) do(step string, f func()) {
	g.t.Helper()
	if err := attempt(f); err != nil {
		g.lines = append(g.lines, step+" failure "+normalize(encoded(failureResult(err))))
	}
	for _, sent := range g.rec.take() {
		g.lines = append(g.lines, step+" adapter "+sent)
	}
}

func (g *goldenRun) dump() {
	for _, table := range []string{"tenants", "objects", "oauth", "audit"} {
		rows, err := g.p.Store.DB.Query("SELECT * FROM " + table + " ORDER BY 1, 2")
		must(err)
		columns, _ := rows.Columns()
		for rows.Next() {
			values := make([]sql.NullString, len(columns))
			pointers := make([]any, len(columns))
			for i := range values {
				pointers[i] = &values[i]
			}
			must(rows.Scan(pointers...))
			cells := []string{}
			for i, v := range values {
				cell := "null"
				if v.Valid {
					cell = v.String
				}
				if table == "audit" && (columns[i] == "at" || columns[i] == "id") {
					cell = "<" + columns[i] + ">"
				}
				cells = append(cells, columns[i]+"="+cell)
			}
			g.lines = append(g.lines, "db "+table+" "+normalize([]byte(strings.Join(cells, " "))))
		}
		must(rows.Close())
	}
}

func TestGolden(t *testing.T) { runGolden(t, "scenario.txt", goldenScenario, true) }

// TestGoldenEdges covers the grant paths the main scenario does not reach:
// reuse, dry runs, legacy rows, deleting conflicts, rollback and cleanup.
func TestGoldenEdges(t *testing.T) { runGolden(t, "edges.txt", edgeScenario, false) }

// TestGoldenDomains covers domains: reuse and conflicts, publications,
// certificate queueing and the maintenance pass that finishes them.
func TestGoldenDomains(t *testing.T) { runGolden(t, "domains.txt", domainScenario, false) }

func runGolden(t *testing.T, file string, scenario func(*goldenRun), everyTool bool) {
	saved := randomSource
	randomSource = &seededReader{}
	t.Cleanup(func() { randomSource = saved })
	p, b, _ := originFixture(t)
	p.sshProbe = func(context.Context, D) bool { return true }
	// Domains: a token for the DNS stub, and the tenant's wildcard pair as
	// issuance would leave it.
	p.Config["cloudflare_token"] = "test"
	crt, key := testPair(t, "*.alice.winlab.tw")
	p.execution(context.Background()).storeCertificate("alice", crt, key)
	p.Store.Put("certificates", "1", 1, D{"id": "1", "tenant_n": 1, "slug": "alice"})
	p.certificatePrepare = func(D) D { return D{"state": "ready"} }
	rec := &recorder{fakeBackend: b, p: p}
	p.Backend = rec
	ctx, stop := context.WithCancel(context.Background())
	t.Cleanup(stop)
	go rec.guests(ctx)
	runQueue(p)
	g := &goldenRun{t: t, p: p, app: NewApp(p, nil), rec: rec, tools: map[string]bool{}}
	scenario(g)
	g.dump()
	for _, tool := range dicts(Contract["tools"]) {
		if everyTool && !g.tools[str(tool["name"])] {
			t.Errorf("tool %s has no golden step", tool["name"])
		}
	}
	checkGolden(t, file, strings.Join(g.lines, "\n")+"\n")
}

// checkGolden compares got with testdata/golden/<file>, or rewrites it
// with -update.
func checkGolden(t *testing.T, file, got string) {
	t.Helper()
	path := filepath.Join("testdata", "golden", file)
	if *update {
		must(os.MkdirAll(filepath.Dir(path), 0o755))
		must(os.WriteFile(path, []byte(got), 0o644))
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("no golden file; run with -update: %v", err)
	}
	if got != string(want) {
		gl, wl := readLines(got), readLines(string(want))
		for i := 0; i < max(len(gl), len(wl)); i++ {
			var a, w string
			if i < len(gl) {
				a = gl[i]
			}
			if i < len(wl) {
				w = wl[i]
			}
			if a != w {
				t.Fatalf("golden line %d differs\nwant: %s\ngot:  %s", i+1, w, a)
			}
		}
	}
}

func readLines(s string) []string {
	out := []string{}
	scanner := bufio.NewScanner(bytes.NewBufferString(s))
	scanner.Buffer(make([]byte, 1<<20), 1<<24)
	for scanner.Scan() {
		out = append(out, scanner.Text())
	}
	return out
}

func goldenScenario(g *goldenRun) {
	alice, bob, admin := person("alice", false), person("bob", false), person("root", true)
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGoldenGoldenGoldenGoldenGoldenGoldenGold golden"
	call := g.call

	call("start", "whoami", D{}, alice)
	call("start", "whoami", D{}, bob)
	call("start", "quota_get", D{}, alice)
	call("start", "catalog_get", D{}, alice)
	call("start", "capacity_get", D{}, alice)
	call("errors", "machine_get", D{"machine": "missing"}, alice)
	call("errors", "quota_get", D{"tenant": "bob"}, alice)
	call("errors", "machine_create", D{"name": "bad", "extra": true}, alice)

	call("keys", "ssh_key_add", D{"key": key, "dry_run": true}, alice)
	added := call("keys", "ssh_key_add", D{"key": key}, alice)
	call("keys", "ssh_key_list", D{}, alice)

	call("create", "machine_create", D{"name": "web", "dry_run": true}, alice)
	call("create", "machine_create", D{"name": "web", "detail": "full"}, alice)
	call("create", "machine_create", D{"name": "box", "kind": "ct"}, alice)
	call("read", "machine_list", D{}, alice)
	call("read", "machine_list", D{"detail": "full"}, alice)
	call("read", "machine_get", D{"machine": "web"}, alice)
	call("read", "machine_get", D{"machine": "web", "detail": "full"}, alice)
	call("read", "machine_metrics", D{"machine": "web"}, alice)

	call("power", "machine_power", D{"machine": "web", "action": "shutdown", "dry_run": true}, alice)
	call("power", "machine_power", D{"machine": "web", "action": "shutdown"}, alice)
	call("power", "machine_power", D{"machine": "web", "action": "start"}, alice)
	call("resize", "machine_resize", D{"machine": "web", "cpu": 2, "dry_run": true}, alice)
	call("resize", "machine_resize", D{"machine": "web", "cpu": 2}, alice)

	call("network", "network_create", D{"name": "lab", "dry_run": true}, alice)
	call("network", "network_create", D{"name": "lab"}, alice)
	call("network", "network_list", D{}, alice)
	call("network", "machine_nic_attach", D{"machine": "web", "network": "lab"}, alice)
	call("network", "machine_nic_detach", D{"machine": "web", "nic": 1}, alice)
	call("network", "network_delete", D{"network": "lab", "confirm": "lab"}, alice)

	call("ports", "port_open", D{"machine": "web", "port": 8080, "proto": "tcp", "dry_run": true}, alice)
	opened := call("ports", "port_open", D{"machine": "web", "port": 8080, "proto": "tcp"}, alice)
	call("ports", "port_list", D{}, alice)
	call("ports", "port_close", D{"id": obj(obj(obj(opened["operation"])["result"])["port"])["id"]}, alice)

	call("domains", "domain_add", D{"machine": "web", "sub": "site", "target_port": 8080}, alice)
	call("domains", "domain_list", D{}, alice)
	call("domains", "domain_remove", D{"name": "site.alice.winlab.tw"}, alice)

	call("peers", "peer_allow", D{"machine": "web", "port": 5432, "from_tenant": "bob"}, alice)
	peers := call("peers", "peer_list", D{}, alice)
	if list := dicts(peers["peers"]); len(list) > 0 {
		call("peers", "peer_revoke", D{"id": list[0]["id"]}, alice)
	} else {
		call("peers", "peer_revoke", D{"id": "missing"}, alice)
	}

	call("snapshots", "snapshot_create", D{"machine": "web", "name": "s1"}, alice)
	call("snapshots", "snapshot_list", D{"machine": "web"}, alice)
	call("snapshots", "snapshot_rollback", D{"machine": "web", "name": "s1", "confirm": "s1"}, alice)
	call("snapshots", "snapshot_delete", D{"machine": "web", "name": "s1"}, alice)

	approved := call("requests", "quota_request", D{"dimension": "vcpu", "amount": 12, "reason": "golden"}, alice)
	rejected := call("requests", "quota_request", D{"dimension": "disk_gb", "amount": 200, "reason": "golden"}, alice)
	call("requests", "request_list", D{}, alice)
	call("admin", "request_list_all", D{}, admin)
	call("admin", "request_approve", D{"id": obj(approved["request"])["id"]}, admin)
	call("admin", "request_reject", D{"id": obj(rejected["request"])["id"]}, admin)
	call("admin", "tenant_list", D{}, admin)
	call("admin", "node_list", D{}, admin)
	call("admin", "usage_report", D{}, admin)
	call("admin", "quota_set", D{"tenant": "alice", "dimension": "domains", "amount": 12, "dry_run": true}, admin)
	call("admin", "quota_set", D{"tenant": "alice", "dimension": "domains", "amount": 12}, admin)
	call("admin", "reconcile_run", D{"dry_run": true}, admin)
	call("admin", "reconcile_run", D{}, admin)

	call("apps", "app_link", D{"machine": "web", "name": "site", "repo": "alice/site", "start": "./run", "port": 8080, "dry_run": true}, alice)
	call("apps", "app_link", D{"machine": "web", "name": "site", "repo": "alice/site", "start": "./run", "port": 8080}, alice)
	call("apps", "app_list", D{}, alice)
	call("apps", "app_get", D{"app": "site"}, alice)
	call("apps", "app_deploy", D{"app": "site", "release": "0000000000000000"}, alice)
	call("apps", "app_rollback", D{"app": "site"}, alice)
	call("apps", "app_unlink", D{"app": "site", "confirm": "site"}, alice)

	spec := D{
		"machines":    []any{D{"name": "api"}, D{"name": "db", "network_access": "restricted"}},
		"connections": []any{D{"from": "api", "to": "db", "port": 5432, "protocol": "tcp"}},
	}
	call("deployment", "deployment_plan", obj(copyValue(spec)), alice)
	applied := call("deployment", "deployment_apply", obj(copyValue(spec)), alice)
	call("deployment", "deployment_plan", D{"access": []any{D{"machine": "web", "network_access": "restricted", "confirm": "web"}}}, alice)
	call("deployment", "deployment_apply", D{"access": []any{D{"machine": "web", "network_access": "restricted", "confirm": "web"}}}, alice)

	id := obj(applied["operation"])["id"]
	call("operations", "operation_get", D{"id": id}, alice)
	call("operations", "operation_get", D{"id": id, "detail": "full"}, alice)
	call("operations", "operation_retry", D{"id": id}, alice)

	call("audit", "audit_log", D{}, alice)
	call("keys", "ssh_key_remove", D{"id": added["id"]}, alice)
	call("delete", "machine_delete", D{"machine": "box", "confirm": "box", "dry_run": true}, alice)
	call("delete", "machine_delete", D{"machine": "box", "confirm": "box"}, alice)
	call("admin", "tenant_suspend", D{"tenant": "bob"}, admin)

	call("vips", "vip_add", D{"name": "api", "machines": []any{"api", "db"}}, alice)
	call("vips", "vip_list", D{}, alice)
	call("vips", "vip_remove", D{"name": "api"}, alice)

	call("migrate", "machine_migrate", D{"tenant": "alice", "machine": "api", "node": "carrel01"}, admin)
	call("migrate", "machine_migrate", D{"tenant": "alice", "machine": "api", "node": "carrel01"}, alice)

	call("drain", "node_drain", D{"node": "carrel01"}, admin)
	call("drain", "node_undrain", D{"node": "carrel01"}, admin)
	call("drain", "node_drain", D{"node": "carrel01"}, alice)
}

func machineRow(g *goldenRun, n int, name string) D {
	return find(g.p.Store.Objects("machines", n), func(m D) bool { return m["name"] == name })
}

// edgeScenario was written for the review of #82.
func edgeScenario(g *goldenRun) {
	alice, bob := person("alice", false), person("bob", false)
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGoldenGoldenGoldenGoldenGoldenGoldenGold golden"
	call := g.call
	call("s", "whoami", D{}, alice)
	call("s", "whoami", D{}, bob)
	call("s", "ssh_key_add", D{"key": key}, alice)
	call("s", "ssh_key_add", D{"key": key}, bob)
	call("m", "machine_create", D{"name": "web"}, alice)
	call("m", "machine_create", D{"name": "db", "network_access": "restricted"}, alice)
	call("m", "machine_create", D{"name": "client"}, bob)
	web, db := machineRow(g, 1, "web"), machineRow(g, 1, "db")

	// Ports: new, existing, existing dry, SSH grant reuse, UDP dry and real.
	call("p", "port_open", D{"machine": "web", "port": 8080, "proto": "tcp"}, alice)
	call("p", "port_open", D{"machine": "web", "port": 8080, "proto": "tcp"}, alice)
	call("p", "port_open", D{"machine": "web", "port": 8080, "proto": "tcp", "dry_run": true}, alice)
	call("p", "port_open", D{"machine": "web", "port": 8080, "proto": "tcp", "detail": "full"}, alice)
	call("p", "port_open", D{"machine": "web", "port": 22, "proto": "tcp"}, alice)
	call("p", "port_open", D{"machine": "web", "port": 9000, "proto": "udp", "dry_run": true}, alice)
	call("p", "port_open", D{"machine": "web", "port": 9000, "proto": "udp", "detail": "full"}, alice)
	call("p", "port_list", D{}, alice)
	var udp any
	for _, x := range g.p.Store.Objects("ports", 1) {
		if x["proto"] == "udp" {
			udp = x["id"]
		}
	}
	call("p", "port_close", D{"id": udp, "dry_run": true}, alice)
	call("p", "port_close", D{"id": udp, "detail": "full"}, alice)
	call("p", "port_close", D{"id": "missing"}, alice)

	// Peers: new, existing, dry existing, dry new, from a machine, revoke.
	call("q", "peer_allow", D{"machine": "db", "port": 5432, "from_tenant": "bob"}, alice)
	call("q", "peer_allow", D{"machine": "db", "port": 5432, "from_tenant": "bob", "detail": "full"}, alice)
	call("q", "peer_allow", D{"machine": "db", "port": 5432, "from_tenant": "bob", "dry_run": true}, alice)
	call("q", "peer_allow", D{"machine": "db", "port": 6000, "from_tenant": "bob", "dry_run": true}, alice)
	call("q", "peer_allow", D{"machine": "db", "port": 5432, "from_tenant": "bob", "from_machine": "client", "detail": "full"}, alice)
	call("q", "peer_allow", D{"machine": "db", "port": 5433, "from_tenant": "alice", "from_machine": "web"}, alice)
	call("q", "machine_get", D{"machine": "db", "detail": "full"}, alice)
	call("q", "machine_get", D{"machine": "db"}, alice)
	call("q", "machine_list", D{"detail": "full"}, alice)
	call("q", "peer_list", D{}, alice)
	first := g.p.Store.Objects("peers", 1)[0]["id"]
	call("q", "peer_revoke", D{"id": first, "dry_run": true}, alice)
	call("q", "peer_revoke", D{"id": first, "detail": "full"}, alice)
	call("q", "peer_revoke", D{"id": "missing"}, alice)

	// Older rows: a peer without proto or operation ID, a port without an
	// operation ID.
	g.p.Store.Put("peers", "legacy0000000001", 1, D{"id": "legacy0000000001", "tenant_n": 1, "source": str(web["ip"]) + "/32", "target": db["ip"], "port": 7000})
	g.p.Store.Put("ports", "1-20018-tcp", 1, D{"id": "1-20018-tcp", "tenant_n": 1, "vmid": web["vmid"], "ip": web["ip"], "public_port": 20018, "port": 7070, "proto": "tcp"})
	call("l", "machine_get", D{"machine": "db", "detail": "full"}, alice)
	call("l", "peer_allow", D{"machine": "db", "port": 7000, "from_tenant": "alice", "from_machine": "web", "detail": "full"}, alice)
	call("l", "port_open", D{"machine": "web", "port": 7070, "proto": "tcp", "detail": "full"}, alice)

	spec := D{
		"connections":  []any{D{"from": "web", "to": "db", "port": 7000, "protocol": "tcp"}, D{"from": "web", "to": "db", "port": 7001}},
		"publications": []any{D{"machine": "web", "protocol": "tcp", "port": 7070}, D{"machine": "web", "protocol": "udp", "port": 7071}, D{"machine": "db", "protocol": "tcp", "port": 22}},
	}
	call("d", "deployment_plan", obj(copyValue(spec)), alice)
	applied := call("d", "deployment_apply", obj(copyValue(spec)), alice)
	call("d", "operation_get", D{"id": obj(applied["operation"])["id"], "detail": "full"}, alice)
	call("d", "machine_get", D{"machine": "db", "detail": "full"}, alice)
	call("d", "deployment_plan", obj(copyValue(spec)), alice)
	call("d", "deployment_apply", obj(copyValue(spec)), alice)

	// Rollback: a machine that fails to create, with a connection and a
	// publication.
	boom := D{
		"machines":     []any{D{"name": "boom"}},
		"connections":  []any{D{"from": "boom", "to": "db", "port": 8000}},
		"publications": []any{D{"machine": "boom", "protocol": "tcp", "port": 8001}},
	}
	failed := call("r", "deployment_apply", obj(copyValue(boom)), alice)
	call("r", "operation_get", D{"id": obj(failed["operation"])["id"], "detail": "full"}, alice)

	// Grants still being removed refuse reuse.
	g.p.Store.Put("ports", "1-20017-tcp", 1, D{"id": "1-20017-tcp", "tenant_n": 1, "vmid": web["vmid"], "ip": web["ip"], "public_port": 20017, "port": 7272, "proto": "tcp", "state": "deleting"})
	g.p.Store.Put("peers", "deleting00000001", 1, D{"id": "deleting00000001", "tenant_n": 1, "source": str(web["ip"]) + "/32", "target": db["ip"], "port": 7300, "proto": "tcp", "state": "deleting"})
	call("c", "port_open", D{"machine": "web", "port": 7272, "proto": "tcp"}, alice)
	call("c", "deployment_plan", D{"publications": []any{D{"machine": "web", "protocol": "tcp", "port": 7272}}}, alice)
	call("c", "peer_allow", D{"machine": "db", "port": 7300, "from_tenant": "alice", "from_machine": "web"}, alice)
	call("c", "deployment_apply", D{"connections": []any{D{"from": "web", "to": "db", "port": 7300}}}, alice)
	call("c", "machine_get", D{"machine": "db", "detail": "full"}, alice)
	g.p.Store.Remove("ports", "1-20017-tcp")
	g.p.Store.Remove("peers", "deleting00000001")

	// Deleting a machine removes the peers on both ends.
	call("x", "machine_delete", D{"machine": "client", "confirm": "client"}, bob)
	call("x", "machine_delete", D{"machine": "db", "confirm": "db"}, alice)
	call("x", "peer_list", D{}, alice)
	call("x", "port_list", D{}, alice)
	g.lines = append(g.lines, fmt.Sprintf("end machines=%d", len(g.p.Store.Objects("machines"))))
}

func domainScenario(g *goldenRun) {
	alice := person("alice", false)
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGoldenGoldenGoldenGoldenGoldenGoldenGold golden"
	call := g.call
	call("s", "ssh_key_add", D{"key": key}, alice)
	call("s", "machine_create", D{"name": "web"}, alice)
	call("s", "machine_create", D{"name": "api"}, alice)

	// Direct domains: preview, add, add again, retarget, list, remove.
	call("a", "domain_add", D{"machine": "web", "sub": "site", "target_port": 8080, "dry_run": true}, alice)
	call("a", "domain_add", D{"machine": "web", "sub": "site", "target_port": 8080}, alice)
	call("a", "domain_add", D{"machine": "web", "sub": "site", "target_port": 8080, "detail": "full"}, alice)
	call("a", "domain_add", D{"machine": "web", "sub": "site", "target_port": 9090}, alice)
	call("a", "domain_add", D{"machine": "api", "sub": "site", "target_port": 8080}, alice)
	call("a", "domain_add", D{"machine": "api", "sub": "docs", "target_port": 3000, "detail": "full"}, alice)
	call("a", "domain_list", D{}, alice)
	call("a", "machine_get", D{"machine": "web", "detail": "full"}, alice)
	call("a", "domain_remove", D{"name": "site.alice.winlab.tw", "dry_run": true}, alice)
	call("a", "domain_remove", D{"name": "missing.alice.winlab.tw"}, alice)

	// Publications: HTTPS through a deployment, reused by a second one.
	spec := D{"publications": []any{D{"machine": "api", "protocol": "https", "port": 3000, "sub": "docs"}, D{"machine": "web", "protocol": "https", "port": 8080, "sub": "shop"}}}
	call("p", "deployment_plan", obj(copyValue(spec)), alice)
	applied := call("p", "deployment_apply", obj(copyValue(spec)), alice)
	call("p", "operation_get", D{"id": obj(applied["operation"])["id"], "detail": "full"}, alice)
	call("p", "deployment_apply", obj(copyValue(spec)), alice)
	call("p", "domain_list", D{}, alice)

	// A publication whose job ended before its certificate was ready: the
	// maintenance pass routes it.
	web := machineRow(g, 1, "web")
	g.p.Store.Put("domains", "orphaned00000001", 1, D{"id": "orphaned00000001", "tenant_n": 1, "vmid": web["vmid"], "sub": "later", "slug": "alice", "name": "later.alice.winlab.tw", "target_port": 8080, "state": "queued", "ready_at": 1, "operation_id": "finished-job"})
	g.do("m", func() { g.p.execution(context.Background()).MaintainDomains() })
	call("m", "domain_list", D{}, alice)

	// A domain still being removed refuses reuse.
	g.p.Store.Put("domains", "deleting00000001", 1, D{"id": "deleting00000001", "tenant_n": 1, "vmid": web["vmid"], "sub": "gone", "slug": "alice", "name": "gone.alice.winlab.tw", "target_port": 8080, "state": "deleting", "ready_at": 1})
	call("c", "domain_add", D{"machine": "web", "sub": "gone", "target_port": 8080}, alice)
	call("c", "deployment_plan", D{"publications": []any{D{"machine": "web", "protocol": "https", "port": 8080, "sub": "gone"}}}, alice)
	g.p.Store.Remove("domains", "deleting00000001")

	// Deleting a machine drops its domains; removing the last one drops the
	// tenant's DNS record.
	call("x", "machine_delete", D{"machine": "web", "confirm": "web"}, alice)
	call("x", "domain_list", D{}, alice)
	for _, d := range g.p.Store.Objects("domains", 1) {
		call("x", "domain_remove", D{"name": d["name"]}, alice)
	}
	call("x", "domain_list", D{}, alice)

	// A catch-all: one domain for every other name of the tenant.
	call("w", "domain_add", D{"machine": "api", "sub": "*", "target_port": 80, "detail": "full"}, alice)
	call("w", "domain_add", D{"machine": "api", "sub": "named", "target_port": 8080}, alice)
	call("w", "domain_list", D{}, alice)
	call("w", "domain_remove", D{"name": "*.alice.winlab.tw", "detail": "full"}, alice)
	call("w", "domain_remove", D{"name": "named.alice.winlab.tw"}, alice)
}
