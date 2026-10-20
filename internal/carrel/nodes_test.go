package carrel

import (
	"context"
	"sync"
	"testing"
	"time"
)

// nodeFixture runs three nodes. Each runs one unmanaged guest that commits
// memory: 100 GiB on carrel01, 20 on carrel02 and 60 on carrel03.
func nodeFixture(t *testing.T) (*Platform, *fakeBackend, *sync.Map) {
	t.Helper()
	p, b := fixture(t)
	p.Config["nodes"] = []any{
		D{"name": "carrel01", "target": "node-01"},
		D{"name": "carrel02", "target": "node-02"},
		D{"name": "carrel03", "target": "node-03"},
	}
	used := map[string]float64{"node-01": 100, "node-02": 20, "node-03": 60}
	targets := &sync.Map{}
	b.call = func(r D, target string) (any, error) {
		if m, ok := r["machine"].(map[string]any); ok {
			targets.Store(str(r["op"])+":"+str(m["name"]), target)
		}
		switch r["op"] {
		case "inventory":
			inventory := baseInventory()
			name := map[string]string{"node-01": "carrel01", "node-02": "carrel02", "node-03": "carrel03"}[target]
			obj(inventory["status"])["memory"] = D{"total": 192 * GiB, "used": used[target] * GiB}
			inventory["node"] = name
			inventory["resources"] = []D{{"type": "qemu", "vmid": 900, "node": name, "status": "running", "maxcpu": 1, "maxmem": used[target] * GiB, "maxdisk": 10 * GiB}}
			return inventory, nil
		case "storage_usage":
			out := []D{}
			for _, m := range dicts(r["machines"]) {
				out = append(out, D{"tenant_n": m["tenant_n"], "available": true, "retained_snapshot_bytes": 1, "unique_total_bytes": 10, "node": target})
			}
			return out, nil
		}
		return D{"status": "running"}, nil
	}
	return p, b, targets
}

func TestValidateNodes(t *testing.T) {
	for _, tc := range []struct {
		nodes []any
		ok    bool
	}{
		{nil, false},
		{[]any{}, false},
		{[]any{D{"name": "carrel01", "target": "carrel-node"}, D{"name": "carrel02", "target": "node-02"}}, true},
		{[]any{D{"name": "carrel01", "target": "a"}, D{"name": "carrel01", "target": "b"}}, false},
		{[]any{D{"name": "carrel01", "target": "a"}, D{"name": "carrel02", "target": "a"}}, false},
		{[]any{D{"name": "../x", "target": "a"}}, false},
		{[]any{D{"name": "carrel01"}}, false},
		{[]any{"carrel01"}, false},
	} {
		if err := ValidateNodes(D{"nodes": tc.nodes, "public_address": "140.113.60.184", "origin": "https://carrel.winlab.tw"}); (err == nil) != tc.ok {
			t.Fatalf("%v: %v", tc.nodes, err)
		}
	}
}

func TestPlacementPicksTheNodeWithTheMostMemoryThatAdmits(t *testing.T) {
	p, b, _ := nodeFixture(t)
	e := p.execution(context.Background())
	if node, _ := e.Place(1, 1024, 10); node.Name != "carrel02" {
		t.Fatalf("placed on %s", node.Name)
	}
	// carrel02 cannot hold 128 vCPU (32 CPUs x 4); neither can the others.
	if err := attempt(func() { e.Place(129, 1024, 10) }); err == nil || obj(failureResult(err)["error"])["code"] != "capacity_exhausted" {
		t.Fatalf("expected capacity_exhausted: %v", err)
	}
	// Memory admission is (192 - 8) * 0.9 = 165.6 GiB per node. A stopped
	// 150 GiB machine still holds its memory on carrel02, so carrel03 wins.
	p.Store.Put("machines", 10199, 1, D{"vmid": 10199, "tenant_n": 1, "name": "big", "node": "carrel02", "cpu": 1, "memory_mb": 150 * 1024, "disk_gb": 10})
	if node, _ := e.Place(1, 1024, 10); node.Name != "carrel03" {
		t.Fatalf("placed on %s", node.Name)
	}
	// 110 GiB fits on no node: 100 + 110 and 60 + 110 exceed 165.6, carrel02 is full.
	if err := attempt(func() { e.Place(1, 110*1024, 10) }); err == nil {
		t.Fatal("placed a machine no node admits")
	}
	_ = b
}

func TestMachinesRunAndAreAskedOnTheirNode(t *testing.T) {
	p, _, targets := nodeFixture(t)
	p.wg.Add(1)
	go p.Operations.Loop()
	who := person("alice", false)
	r := p.Execute(context.Background(), "machine_create", D{"name": "web", "ssh_keys": []any{"ssh-ed25519 AAAA test"}, "wait_seconds": 0}, who)
	assertOK(t, r)
	deadline := time.Now().Add(3 * time.Second)
	for {
		if v, ok := targets.Load("create:web"); ok {
			if v != "node-02" {
				t.Fatalf("created on %v", v)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("create not applied")
		}
		time.Sleep(10 * time.Millisecond)
	}
	p.writer.Lock()
	m := p.Store.Objects("machines", 1)[0]
	p.writer.Unlock()
	if m["node"] != "carrel02" {
		t.Fatalf("stored node %v", m["node"])
	}
	e := p.execution(context.Background())
	e.Call(D{"op": "status", "machine": m})
	if v, _ := targets.Load("status:web"); v != "node-02" {
		t.Fatalf("status asked %v", v)
	}
	if _, ok := e.PublicMachine(m, nil)["node"]; ok {
		t.Fatal("members see the physical node")
	}
}

func TestCapacityCombinesNodesAndReportsTheLargestSingleNode(t *testing.T) {
	p, _, _ := nodeFixture(t)
	c := p.execution(context.Background()).Capacity(nil, true)
	if num(obj(obj(c["physical"])["cpu"])["logical_cpus"]) != 96 || c["node_count"] != 3 {
		t.Fatal(encoded(c))
	}
	vcpu := obj(obj(c["allocatable"])["vcpu"])
	// Each node runs one 1-vCPU guest: 128 - 1 left on the best node.
	if num(vcpu["limit"]) != 384 || num(vcpu["largest_node_remaining"]) != 127 {
		t.Fatal(encoded(vcpu))
	}
	if total := num(obj(obj(c["physical"])["memory"])["used"]); total != 180 {
		t.Fatalf("memory used %v", total)
	}
}

func TestStorageUsageAsksEachNodeAboutItsMachines(t *testing.T) {
	p, b, _ := nodeFixture(t)
	for i, node := range []string{"carrel01", "carrel02", "carrel01"} {
		p.Store.Put("machines", 10100+i, 1, D{"vmid": 10100 + i, "tenant_n": 1, "name": "m", "node": node})
	}
	p.execution(context.Background()).RefreshStorage()
	sample := p.Store.Get("storage_usage", "1")
	// carrel01 holds two machines, carrel02 one: three samples.
	if num(sample["unique_total_bytes"]) != 30 || num(sample["retained_snapshot_bytes"]) != 3 {
		t.Fatal(encoded(sample))
	}
	if b.count("storage_usage") != 3 {
		t.Fatalf("asked %d nodes", b.count("storage_usage"))
	}
}

func TestNodeListShowsEveryNode(t *testing.T) {
	p, _, _ := nodeFixture(t)
	nodes := dicts(p.execution(context.Background()).Admin("node_list", D{}, person("admin", true))["nodes"])
	if len(nodes) != 3 || nodes[2]["name"] != "carrel03" || obj(nodes[2]["inventory"])["node"] != "carrel03" {
		t.Fatal(encoded(nodes))
	}
}

func TestUnknownNodeRecordsAndUnreachableNodesDoNotStopObservations(t *testing.T) {
	p, b, _ := nodeFixture(t)
	p.Store.Put("machines", 10150, 1, D{"vmid": 10150, "tenant_n": 1, "name": "gone", "node": "carrel09", "cpu": 1, "memory_mb": 1024, "disk_gb": 10})
	e := p.execution(context.Background())
	if node, _ := e.Place(1, 1024, 10); node.Name != "carrel02" {
		t.Fatalf("placed on %s", node.Name)
	}
	if err := attempt(func() { p.nodeOf(D{"node": "carrel09"}) }); err == nil {
		t.Fatal("requests for a machine on an unconfigured node must still fail")
	}
	inner := b.call
	b.call = func(r D, target string) (any, error) {
		if target == "node-03" {
			// SSHBackend reports an unreachable adapter as backend_unavailable.
			return nil, Failure{D{"ok": false, "error": D{"code": "backend_unavailable", "message": "unreachable"}}}
		}
		return inner(r, target)
	}
	c := e.Capacity(nil, true)
	if c["unavailable_nodes"] != 1 || c["node_count"] != 2 {
		t.Fatal(encoded(c))
	}
	if err := attempt(func() { e.Capacity(nil, false) }); err == nil {
		t.Fatal("a fresh read skipped an unreachable node")
	}
	if node, _ := e.Place(1, 1024, 10); node.Name != "carrel02" {
		t.Fatalf("placed on %s", node.Name)
	}
	if err := ValidateNodes(D{"nodes": "carrel01"}); err == nil {
		t.Fatal("accepted a node list that is not a list")
	}
}
func TestReconcileRunsOnEveryNodeFirstNodeFirst(t *testing.T) {
	p, b, _ := nodeFixture(t)
	var mu sync.Mutex
	order := []string{}
	inner := b.call
	b.call = func(r D, target string) (any, error) {
		if r["op"] == "reconcile" {
			mu.Lock()
			order = append(order, target)
			mu.Unlock()
			return D{"changed": []any{}}, nil
		}
		return inner(r, target)
	}
	r := p.execution(context.Background()).Reconcile()
	// The first node goes first; the others reconcile at once after it.
	if len(order) != 3 || order[0] != "node-01" || !sameStrings(order[1:], []string{"node-02", "node-03"}) {
		t.Fatalf("order %v", order)
	}
	if len(obj(r["nodes"])) != 3 || r["node"] == nil {
		t.Fatal(encoded(r))
	}
}

// sameStrings compares two lists as sets of distinct strings.
func sameStrings(a, b []string) bool {
	seen := map[string]bool{}
	for _, v := range a {
		seen[v] = true
	}
	for _, v := range b {
		if !seen[v] {
			return false
		}
	}
	return len(a) == len(b)
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestReconcileContinuesPastAnUnreachableNode(t *testing.T) {
	p, b, _ := nodeFixture(t)
	calls := []string{}
	var mu sync.Mutex
	inner := b.call
	b.call = func(r D, target string) (any, error) {
		if r["op"] == "reconcile" {
			mu.Lock()
			calls = append(calls, target)
			mu.Unlock()
			if target == "node-02" {
				return nil, Failure{D{"ok": false, "error": D{"code": "backend_unavailable"}}}
			}
			return D{}, nil
		}
		return inner(r, target)
	}
	r := p.execution(context.Background()).Reconcile()
	if len(calls) != 3 || calls[0] != "node-01" || !sameStrings(calls[1:], []string{"node-02", "node-03"}) {
		t.Fatalf("calls %v", calls)
	}
	if !equal(r["unreachable_nodes"], []any{"carrel02"}) {
		t.Fatal(encoded(r))
	}
	b.call = func(r D, target string) (any, error) {
		if r["op"] == "reconcile" && target == "node-01" {
			return nil, Failure{D{"ok": false, "error": D{"code": "backend_unavailable"}}}
		}
		return inner(r, target)
	}
	if err := attempt(func() { p.execution(context.Background()).Reconcile() }); err == nil {
		t.Fatal("the gateway node may not be skipped")
	}
}

func TestValidateNodesNeedsTheSiteAddressAndOrigin(t *testing.T) {
	nodes := []any{D{"name": "carrel01", "target": "carrel-node"}}
	if err := ValidateNodes(D{"nodes": nodes, "public_address": "140.113.60.184", "origin": "https://carrel.winlab.tw"}); err != nil {
		t.Fatal(err)
	}
	for _, c := range []D{{"nodes": nodes, "origin": "https://carrel.winlab.tw"}, {"nodes": nodes, "public_address": "fe80::1", "origin": "https://carrel.winlab.tw"}, {"nodes": nodes, "public_address": "x", "origin": "https://carrel.winlab.tw"}, {"nodes": nodes, "public_address": "140.113.60.184"}} {
		if err := ValidateNodes(c); err == nil {
			t.Fatalf("accepted %v", c)
		}
	}
}

func TestCertificatesGoOnlyToTheGateway(t *testing.T) {
	p, b, _ := nodeFixture(t)
	sent := map[string]D{}
	var mu sync.Mutex
	inner := b.call
	gateway := 0
	b.call = func(r D, target string) (any, error) {
		if r["op"] == "sync" && target == "carrel-gateway" {
			mu.Lock()
			gateway++
			mu.Unlock()
			return D{}, nil
		}
		if r["op"] == "reconcile" {
			mu.Lock()
			sent[target] = obj(r["state"])
			mu.Unlock()
			return D{}, nil
		}
		return inner(r, target)
	}
	p.execution(context.Background()).Reconcile()
	// Private keys go to the gateway only, never through a node.
	for node, state := range sent {
		if _, ok := state["certificates"]; ok || state["origin_certificate"] != nil {
			t.Fatalf("%s received certificates", node)
		}
	}
	if len(sent) != 3 || gateway != 1 {
		t.Fatal(len(sent), gateway)
	}
}

func TestUnplacedMachinesAreNamed(t *testing.T) {
	p, _ := fixture(t)
	seedMachine(p, "placed", 10100)
	p.Store.Put("machines", 10101, 1, D{"vmid": 10101, "tenant_n": 1, "name": "nameless"})
	p.Store.Put("machines", 10102, 1, D{"vmid": 10102, "tenant_n": 1, "name": "gone", "node": "carrel09"})
	if got := UnplacedMachines(p.Store, p.Config); !equalStrings(got, []string{"nameless", "gone"}) {
		t.Fatal(got)
	}
}

func TestPlacementReadsEveryNodeAtOnceAndSkipsADownNode(t *testing.T) {
	p, b, _ := nodeFixture(t)
	inner := b.call
	var mu sync.Mutex
	inFlight, most := 0, 0
	b.call = func(r D, target string) (any, error) {
		if r["op"] == "inventory" {
			mu.Lock()
			inFlight++
			most = max(most, inFlight)
			mu.Unlock()
			time.Sleep(50 * time.Millisecond)
			mu.Lock()
			inFlight--
			mu.Unlock()
			if target == "node-02" {
				return nil, Failure{D{"ok": false, "error": D{"code": "backend_unavailable"}}}
			}
		}
		return inner(r, target)
	}
	node, admission := p.execution(context.Background()).Place(1, 1024, 10)
	if most < 2 || node.Name == "carrel02" || !boolean(admission["accepted"]) {
		t.Fatalf("most in flight %d, placed on %s", most, node.Name)
	}
}

func TestAdapterTimeoutsFollowTheOperation(t *testing.T) {
	if adapterTimeout("inventory") != time.Minute || adapterTimeout("reconcile") != 5*time.Minute || adapterTimeout("create") != 15*time.Minute {
		t.Fatal("adapter timeouts")
	}
}

func TestPlacementSkipsANodeThatCannotRouteTenantTraffic(t *testing.T) {
	p, b, _ := nodeFixture(t)
	inner := b.call
	route := map[string]bool{"node-01": true, "node-02": false, "node-03": true}
	b.call = func(r D, target string) (any, error) {
		v, err := inner(r, target)
		if r["op"] == "inventory" && err == nil {
			v = merge(obj(v), D{"tenant_route": route[target]})
		}
		return v, err
	}
	// node-02 has the most memory left, but its guests could not get out.
	if node, _ := p.execution(context.Background()).Place(1, 1024, 10); node.Name == "carrel02" {
		t.Fatal("placed a machine on a node without a tenant route")
	}
	route["node-01"], route["node-03"] = false, false
	if attempt(func() { p.execution(context.Background()).Place(1, 1024, 10) }) == nil {
		t.Fatal("placed a machine although no node routes tenant traffic")
	}
}
