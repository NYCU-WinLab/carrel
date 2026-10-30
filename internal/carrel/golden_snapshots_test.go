package carrel

// TestGoldenSnapshots and TestGoldenSnapshotNodes were written for the
// review of #88. They record MCP results (also as the MCP SDK marshals
// structured content), adapter requests, snapshot rows after every step,
// operation rows, capacity per node and the final database: retries after
// adapter failures, older rows, rollbacks in every power state, orphaned
// snapshots and admission that snapshot reservations refuse.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// flakyBackend fails chosen adapter actions a set number of times.
type flakyBackend struct {
	*recorder
	fmu   sync.Mutex
	fails map[string]int
}

func (f *flakyBackend) Call(ctx context.Context, req D, target string) (any, error) {
	if req["op"] == "action" {
		key := str(req["action"]) + ":" + str(req["name"])
		f.fmu.Lock()
		if f.fails[key] > 0 {
			f.fails[key]--
			f.fmu.Unlock()
			f.recorder.mu.Lock()
			f.recorder.sent = append(f.recorder.sent, target+" FAILED "+normalize(encoded(req)))
			f.recorder.mu.Unlock()
			return nil, errors.New("adapter failure")
		}
		f.fmu.Unlock()
	}
	return f.recorder.Call(ctx, req, target)
}

func snapshotSetup(t *testing.T) (*goldenRun, *flakyBackend, *fakeBackend) {
	saved := randomSource
	randomSource = &seededReader{}
	t.Cleanup(func() { randomSource = saved })
	p, b, _ := originFixture(t)
	p.sshProbe = func(context.Context, D) bool { return true }
	p.Config.CloudflareToken = "test"
	crt, key := testPair(t, "*.alice.winlab.tw")
	p.execution(context.Background()).storeCertificate("alice", crt, key)
	p.Store.Put("certificates", "1", 1, D{"id": "1", "tenant_n": 1, "slug": "alice"})
	p.certificatePrepare = func(D) D { return D{"state": "ready"} }
	rec := &recorder{fakeBackend: b, p: p}
	fb := &flakyBackend{recorder: rec, fails: map[string]int{}}
	p.Backend = fb
	ctx, stop := context.WithCancel(context.Background())
	t.Cleanup(stop)
	go rec.guests(ctx)
	runQueue(p)
	return &goldenRun{t: t, p: p, app: NewApp(p, nil), rec: rec, tools: map[string]bool{}}, fb, b
}

var bootID = regexp.MustCompile(`"boot_id":"boot-[0-9a-f]+/[0-9]+"`)

func TestGoldenSnapshots(t *testing.T) {
	g, fb, b := snapshotSetup(t)
	snapshotScenario(g, fb, b)
	g.dump()
	// Which job's wait the guest simulator answers last depends on timing;
	// the boot ID it writes is the simulator's own.
	got := bootID.ReplaceAllString(strings.Join(g.lines, "\n")+"\n", `"boot_id":"boot-<job>"`)
	checkGolden(t, "snapshots.txt", got)
}

func snapshotScenario(g *goldenRun, fb *flakyBackend, b *fakeBackend) {
	alice, bob, admin := person("alice", false), person("bob", false), person("root", true)
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGoldenGoldenGoldenGoldenGoldenGoldenGold golden"
	rows := func(step string) {
		for _, data := range g.p.Store.objectData("snapshots") {
			g.lines = append(g.lines, step+" row "+normalize([]byte(data)))
		}
	}
	raw := func(step string, r D) {
		bs, err := json.Marshal(r)
		if err != nil {
			g.lines = append(g.lines, step+" raw-error "+err.Error())
			return
		}
		g.lines = append(g.lines, step+" raw "+normalize(bs))
	}
	call := func(step, tool string, a, who D) D {
		r := g.call(step, tool, a, who)
		raw(step, r)
		rows(step)
		return r
	}
	opID := func(r D) any { return obj(r["operation"])["id"] }
	full := func(step string, r D, who D) {
		if id := opID(r); id != nil {
			call(step, "operation_get", D{"id": id, "detail": "full"}, who)
			g.lines = append(g.lines, step+" oprow "+normalize(encoded(g.p.Store.Get("operations", str(id)))))
		}
	}
	fail := func(k string, n int) { fb.fmu.Lock(); fb.fails[k] = n; fb.fmu.Unlock() }
	observe := func(step string) {
		call(step, "quota_get", D{}, alice)
		call(step, "quota_get", D{}, bob)
		call(step, "capacity_get", D{}, alice)
		call(step, "usage_report", D{}, admin)
		e := g.p.execution(context.Background())
		g.lines = append(g.lines, step+" capacity-fresh "+normalize(encoded(e.Capacity(nil, false))))
		g.lines = append(g.lines, step+" usage1 "+normalize(encoded(e.Usage(g.p.Store.TenantN(1)))))
		g.lines = append(g.lines, step+" usage2 "+normalize(encoded(e.Usage(g.p.Store.TenantN(2)))))
	}

	call("s", "ssh_key_add", D{"key": key}, alice)
	call("s", "ssh_key_add", D{"key": key}, bob)
	call("s", "machine_create", D{"name": "web"}, alice)
	call("s", "machine_create", D{"name": "db", "disk_gb": 20}, alice)
	call("s", "machine_create", D{"name": "box", "kind": "ct"}, alice)
	call("s", "machine_create", D{"name": "bobvm"}, bob)
	call("s", "network_create", D{"name": "lab"}, alice)
	call("s", "machine_nic_attach", D{"machine": "web", "network": "lab"}, alice)
	web, db := machineRow(g, 1, "web"), machineRow(g, 1, "db")
	webID, dbID := integer(web["vmid"]), integer(db["vmid"])

	// Ordinary paths, with dry runs and full detail.
	call("c", "snapshot_create", D{"machine": "web", "name": "s1", "dry_run": true}, alice)
	call("c", "snapshot_create", D{"machine": "web", "name": "s1", "dry_run": true, "detail": "full"}, alice)
	r := call("c", "snapshot_create", D{"machine": "web", "name": "s1", "detail": "full"}, alice)
	full("c", r, alice)
	call("c", "snapshot_create", D{"machine": "web", "name": "s1"}, alice)
	call("c", "snapshot_create", D{"machine": "box", "name": "c1"}, alice)
	call("c", "snapshot_create", D{"machine": "bobvm", "name": "b1"}, bob)
	call("c", "snapshot_list", D{"machine": "web"}, alice)
	call("c", "snapshot_list", D{"machine": "box"}, alice)
	call("c", "snapshot_list", D{"machine": "db"}, alice)
	call("c", "snapshot_list", D{"machine": "bobvm"}, bob)
	observe("c")

	// A create whose adapter call fails, then the same operation retried:
	// the stored row is the running job's (found and owned).
	fail("snapshot:flaky", 1)
	r = call("r", "snapshot_create", D{"machine": "web", "name": "flaky"}, alice)
	full("r", r, alice)
	call("r", "snapshot_list", D{"machine": "web"}, alice)
	observe("r")
	call("r", "snapshot_create", D{"machine": "web", "name": "flaky"}, alice)
	call("r", "snapshot_create", D{"machine": "web", "name": "flaky", "dry_run": true}, alice)
	retried := call("r", "operation_retry", D{"id": opID(r)}, alice)
	full("r", retried, alice)
	// Delete and rollback that fail once, then retry.
	fail("delsnapshot:flaky", 1)
	r = call("r", "snapshot_delete", D{"machine": "web", "name": "flaky"}, alice)
	full("r", r, alice)
	retried = call("r", "operation_retry", D{"id": opID(r)}, alice)
	full("r", retried, alice)
	fail("rollback:s1", 1)
	r = call("r", "snapshot_rollback", D{"machine": "web", "name": "s1", "confirm": "s1"}, alice)
	full("r", r, alice)
	retried = call("r", "operation_retry", D{"id": opID(r)}, alice)
	full("r", retried, alice)
	// A create that fails twice: retried, failing again, retried.
	fail("snapshot:twice", 2)
	r = call("r", "snapshot_create", D{"machine": "db", "name": "twice"}, alice)
	call("r", "operation_retry", D{"id": opID(r)}, alice)
	retried = call("r", "operation_retry", D{"id": opID(r)}, alice)
	full("r", retried, alice)
	observe("r2")

	// Rows as older code or hand repair could leave them.
	webNow := machineRow(g, 1, "web")
	cfg := pick(webNow, "cpu", "memory_mb", "disk_gb", "nics")
	cfg["cpu"] = json.Number("1.0")
	cfg["memory_mb"] = json.Number("1024.0")
	put := func(id string, n int, row D) { g.p.Store.Put("snapshots", id, n, row) }
	put(fmt.Sprintf("%d-bare", webID), 1, D{"id": fmt.Sprintf("%d-bare", webID), "vmid": webID, "name": "bare", "disk_gb": 10})
	put(fmt.Sprintf("%d-match", webID), 1, D{"id": fmt.Sprintf("%d-match", webID), "vmid": webID, "name": "match", "disk_gb": 10, "configuration": cfg, "state": "ready"})
	put(fmt.Sprintf("%d-nonics", webID), 1, D{"id": fmt.Sprintf("%d-nonics", webID), "vmid": webID, "name": "nonics", "disk_gb": 10, "configuration": pick(webNow, "cpu", "memory_mb", "disk_gb"), "state": "ready", "operation_id": "0123"})
	put(fmt.Sprintf("%d-emptynics", dbID), 1, D{"id": fmt.Sprintf("%d-emptynics", dbID), "vmid": dbID, "name": "emptynics", "disk_gb": 20, "configuration": merge(pick(db, "cpu", "memory_mb", "disk_gb"), D{"nics": []any{}}), "state": "ready"})
	put(fmt.Sprintf("%d-plain", dbID), 1, D{"id": fmt.Sprintf("%d-plain", dbID), "vmid": dbID, "name": "plain", "disk_gb": 20, "configuration": pick(db, "cpu", "memory_mb", "disk_gb", "nics"), "state": "ready"})
	put("10999-orphan", 1, D{"id": "10999-orphan", "vmid": 10999, "name": "orphan", "disk_gb": 15, "state": "ready", "operation_id": "dead"})
	rows("l")
	call("l", "snapshot_list", D{"machine": "web"}, alice)
	call("l", "snapshot_list", D{"machine": "db"}, alice)
	observe("l")
	call("l", "snapshot_rollback", D{"machine": "web", "name": "bare", "confirm": "bare"}, alice)
	call("l", "snapshot_rollback", D{"machine": "web", "name": "nonics", "confirm": "nonics"}, alice)
	call("l", "snapshot_rollback", D{"machine": "web", "name": "match", "confirm": "match", "dry_run": true}, alice)
	r = call("l", "snapshot_rollback", D{"machine": "web", "name": "match", "confirm": "match", "detail": "full"}, alice)
	full("l", r, alice)
	call("l", "snapshot_rollback", D{"machine": "db", "name": "emptynics", "confirm": "emptynics"}, alice)
	call("l", "snapshot_rollback", D{"machine": "db", "name": "plain", "confirm": "plain", "dry_run": true}, alice)
	call("l", "snapshot_create", D{"machine": "web", "name": "bare"}, alice)
	call("l", "snapshot_create", D{"machine": "web", "name": "nonics"}, alice)
	call("l", "snapshot_delete", D{"machine": "web", "name": "bare", "dry_run": true}, alice)
	r = call("l", "snapshot_delete", D{"machine": "web", "name": "bare", "detail": "full"}, alice)
	full("l", r, alice)
	call("l", "snapshot_delete", D{"machine": "web", "name": "nonics"}, alice)

	// Power states around a rollback, and a resized disk (a float in the row).
	call("p", "machine_power", D{"machine": "web", "action": "shutdown"}, alice)
	call("p", "snapshot_rollback", D{"machine": "web", "name": "s1", "confirm": "s1"}, alice)
	call("p", "machine_power", D{"machine": "web", "action": "start"}, alice)
	call("p", "machine_power", D{"machine": "web", "action": "pause"}, alice)
	call("p", "snapshot_rollback", D{"machine": "web", "name": "s1", "confirm": "s1"}, alice)
	call("p", "machine_power", D{"machine": "web", "action": "resume"}, alice)
	call("p", "machine_resize", D{"machine": "db", "disk_gb": 30}, alice)
	call("p", "snapshot_rollback", D{"machine": "db", "name": "plain", "confirm": "plain"}, alice)
	call("p", "snapshot_delete", D{"machine": "db", "name": "plain", "dry_run": true}, alice)
	call("p", "quota_set", D{"tenant": "alice", "dimension": "snapshots", "amount": 20}, admin)
	call("p", "quota_set", D{"tenant": "alice", "dimension": "snapshot_gb", "amount": 400}, admin)
	r = call("p", "snapshot_create", D{"machine": "db", "name": "grown", "detail": "full"}, alice)
	full("p", r, alice)
	call("p", "snapshot_rollback", D{"machine": "db", "name": "grown", "confirm": "grown", "detail": "full"}, alice)
	observe("p")

	// Admission: storage sized so the stored snapshot reservations decide.
	reserved := 0.0
	for _, s := range g.p.Store.Objects("snapshots") {
		reserved += num(s["disk_gb"])
	}
	b.mu.Lock()
	storage := obj(b.inventory["storage"])
	// headroom = 0.8 * total - used - reserved: leave 25 GiB with them,
	// so a 30 GiB snapshot is refused and a 20 GiB one is not.
	storage["total"] = (25 + 10 + reserved) / 0.8 * GiB
	b.mu.Unlock()
	g.p.invalidateInventory()
	g.lines = append(g.lines, fmt.Sprintf("a reserved %v", reserved))
	call("a", "capacity_get", D{}, alice)
	call("a", "snapshot_create", D{"machine": "db", "name": "tight", "dry_run": true}, alice)
	call("a", "snapshot_create", D{"machine": "db", "name": "tight"}, alice)
	call("a", "snapshot_create", D{"machine": "web", "name": "fits"}, alice)
	call("a", "machine_create", D{"name": "big", "disk_gb": 200, "dry_run": true}, alice)
	call("a", "machine_resize", D{"machine": "web", "disk_gb": 60, "dry_run": true}, alice)
	b.mu.Lock()
	b.inventory = baseInventory()
	b.mu.Unlock()
	g.p.invalidateInventory()

	// Machine deletion drops snapshots through the D path.
	call("x", "machine_delete", D{"machine": "web", "confirm": "web", "dry_run": true}, alice)
	call("x", "machine_delete", D{"machine": "web", "confirm": "web"}, alice)
	call("x", "machine_delete", D{"machine": "db", "confirm": "db"}, alice)
	call("x", "snapshot_list", D{"machine": "box"}, alice)
	observe("x")
}

// TestGoldenSnapshotNodes: snapshot reservations on several nodes, orphans
// and machines on a node missing from the config.
func TestGoldenSnapshotNodes(t *testing.T) {
	p, _, _ := nodeFixture(t)
	lines := []string{}
	put := func(kind string, id any, n int, d D) { p.Store.Put(kind, id, n, d) }
	put("machines", 10100, 1, D{"vmid": 10100, "tenant_n": 1, "name": "a", "node": "carrel01", "cpu": 1, "memory_mb": 1024, "disk_gb": 10})
	put("machines", 10101, 1, D{"vmid": 10101, "tenant_n": 1, "name": "b", "node": "carrel02", "cpu": 1, "memory_mb": 1024, "disk_gb": 1000})
	put("machines", 10200, 2, D{"vmid": 10200, "tenant_n": 2, "name": "c", "node": "carrel03", "cpu": 1, "memory_mb": 1024, "disk_gb": 40})
	put("machines", 10201, 2, D{"vmid": 10201, "tenant_n": 2, "name": "d", "node": "carrel09", "cpu": 1, "memory_mb": 1024, "disk_gb": 40})
	snap := func(vmid, n int, name string, gb any) {
		id := fmt.Sprintf("%d-%s", vmid, name)
		put("snapshots", id, n, D{"id": id, "vmid": vmid, "name": name, "disk_gb": gb, "state": "ready", "configuration": D{"cpu": 1}})
	}
	snap(10100, 1, "a1", 10)
	snap(10101, 1, "b1", 1000)
	snap(10101, 1, "b2", 1000)
	snap(10200, 2, "c1", 40)
	snap(10201, 2, "d1", 40)
	snap(10999, 1, "orphan", 77)
	e := p.execution(context.Background())
	record := func(step string) {
		caps, unavailable := e.nodeCapacities(nil, false)
		for i, c := range caps {
			lines = append(lines, fmt.Sprintf("%s node%d %s", step, i, normalize(encoded(c))))
		}
		lines = append(lines, fmt.Sprintf("%s unavailable %d", step, unavailable))
		lines = append(lines, step+" capacity "+normalize(encoded(e.Capacity(nil, false))))
		for _, req := range [][3]float64{{1, 1024, 10}, {1, 1024, 300}, {1, 1024, 1500}} {
			var node nodeRef
			var adm D
			if f := attempt(func() { node, adm = e.Place(req[0], req[1], req[2]) }); f != nil {
				lines = append(lines, fmt.Sprintf("%s place %v failure %s", step, req, normalize(encoded(failureResult(f)))))
				continue
			}
			lines = append(lines, fmt.Sprintf("%s place %v %s %s", step, req, node.Name, normalize(encoded(adm))))
		}
		for _, name := range []string{"carrel01", "carrel02", "carrel03"} {
			for _, n := range p.Nodes() {
				if n.Name != name {
					continue
				}
				for _, gb := range []float64{10, 500} {
					f := attempt(func() { e.Admission(n, 0, 0, gb, nil, true) })
					lines = append(lines, fmt.Sprintf("%s snapshot-admission %s %v %s", step, name, gb, normalize(encoded(failureResult(f)))))
				}
			}
		}
		for _, n := range []int{1, 2} {
			lines = append(lines, fmt.Sprintf("%s usage%d %s", step, n, normalize(encoded(e.Usage(p.Store.TenantN(n))))))
		}
	}
	record("n")
	p.Store.Remove("snapshots", "10101-b2")
	p.Store.Remove("snapshots", "10999-orphan")
	record("n2")
	checkGolden(t, "snapshot-nodes.txt", strings.Join(lines, "\n")+"\n")
}
