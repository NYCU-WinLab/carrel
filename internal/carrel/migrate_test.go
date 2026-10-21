package carrel

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestMachineMigrateMovesTheRecordAfterTheNodesAgree(t *testing.T) {
	p, b, _ := nodeFixture(t)
	inner := b.call
	var steps []string
	files := D{"user": "#cloud-config\n{}", "network": "{}"}
	b.call = func(r D, target string) (any, error) {
		switch r["op"] {
		case "migrate_prepare", "migrate", "migrate_finish", "cloud_init_remove":
			steps = append(steps, str(r["op"])+"@"+target)
			if r["op"] == "migrate_prepare" && !equal(r["cloud_init"], files) {
				t.Error("the target must get the stored files", r["cloud_init"])
			}
			return D{"state": "done"}, nil
		case "cloud_init_read":
			return D{"cloud_init": files}, nil
		}
		return inner(r, target)
	}
	seedMachine(p, "web", 10100)
	runQueue(p)
	ctx, admin := context.Background(), person("root", true)
	r := p.Execute(ctx, "machine_migrate", D{"tenant": "alice", "machine": "web", "node": "carrel02"}, admin)
	op := obj(r["operation"])
	if op["state"] != "succeeded" {
		t.Fatal(r)
	}
	want := []string{"migrate_prepare@node-02", "migrate@node-01", "migrate_finish@node-02", "cloud_init_remove@node-01"}
	if !equal(steps, want) {
		t.Fatal(steps)
	}
	if p.Store.Get("machines", "10100")["node"] != "carrel02" {
		t.Fatal("record still on the old node")
	}
	// Admins follow the job in the machine's tenant.
	got := p.Execute(ctx, "operation_get", D{"id": op["id"], "wait_seconds": 0}, admin)
	if ops := dicts(got["operations"]); len(ops) != 1 || ops[0]["state"] != "succeeded" {
		t.Fatal(got)
	}
	for name, args := range map[string]D{
		"same node":    {"tenant": "alice", "machine": "web", "node": "carrel02"},
		"unknown node": {"tenant": "alice", "machine": "web", "node": "carrel09"},
		"no tenant":    {"tenant": "nobody", "machine": "web", "node": "carrel01"},
	} {
		r := p.Execute(ctx, "machine_migrate", args, admin)
		if r["ok"] == true && obj(r["operation"])["state"] == "succeeded" {
			t.Fatalf("%s accepted: %v", name, r)
		}
	}
	if r := p.Execute(ctx, "machine_migrate", D{"tenant": "alice", "machine": "web", "node": "carrel01"}, person("alice", false)); r["ok"] == true {
		t.Fatal("a member moved a machine", r)
	}
	p.Store.Put("snapshots", "s1", 1, D{"id": "s1", "name": "s1", "vmid": 10100, "disk_gb": 10})
	r = p.Execute(ctx, "machine_migrate", D{"tenant": "alice", "machine": "web", "node": "carrel01"}, admin)
	if obj(obj(r["operation"])["error"])["recovery"] != "resolve_prerequisite" {
		t.Fatal("moved a machine with snapshots", r)
	}
}

func TestAMoveThatFailsAfterTheMigrationKeepsTheNewNode(t *testing.T) {
	p, b, _ := nodeFixture(t)
	inner := b.call
	b.call = func(r D, target string) (any, error) {
		switch r["op"] {
		case "migrate_finish":
			return nil, errors.New("disk move failed")
		case "migrate_prepare", "migrate":
			return D{"state": "done"}, nil
		case "cloud_init_read":
			return D{"cloud_init": D{"user": "u", "network": "n"}}, nil
		}
		return inner(r, target)
	}
	seedMachine(p, "web", 10100)
	runQueue(p)
	r := p.Execute(context.Background(), "machine_migrate", D{"tenant": "alice", "machine": "web", "node": "carrel02"}, person("root", true))
	if obj(r["operation"])["state"] != "failed" || p.Store.Get("machines", "10100")["node"] != "carrel02" {
		t.Fatal("the record must follow the machine once it runs on the target", r)
	}
}

func TestOtherJobsOnAMachineWaitWhileItMoves(t *testing.T) {
	p, b, _ := nodeFixture(t)
	inner := b.call
	release := make(chan struct{})
	var actions []string
	var mu sync.Mutex
	b.call = func(r D, target string) (any, error) {
		switch r["op"] {
		case "migrate":
			<-release
			return D{"state": "moved"}, nil
		case "migrate_prepare", "migrate_finish", "cloud_init_remove":
			return D{"state": "done"}, nil
		case "cloud_init_read":
			return D{"cloud_init": D{"user": "u", "network": "n"}}, nil
		case "action":
			mu.Lock()
			actions = append(actions, str(r["action"]))
			mu.Unlock()
			return D{"power_state": "stopped", "changed": true}, nil
		}
		return inner(r, target)
	}
	seedMachine(p, "web", 10100)
	runQueue(p)
	ctx := context.Background()
	move := p.Execute(ctx, "machine_migrate", D{"tenant": "alice", "machine": "web", "node": "carrel02", "wait_seconds": 0}, person("root", true))
	awaitState(t, p, str(obj(move["operation"])["id"]), "moving_machine")
	stop := p.Execute(ctx, "machine_power", D{"machine": "web", "action": "shutdown", "wait_seconds": 0}, person("alice", false))
	awaitState(t, p, str(obj(stop["operation"])["id"]), "waiting_for_machine_operation")
	mu.Lock()
	sent := len(actions)
	mu.Unlock()
	if sent != 0 {
		t.Fatal("a power action reached a node during the move")
	}
	close(release)
	awaitState(t, p, str(obj(move["operation"])["id"]), "succeeded")
	awaitState(t, p, str(obj(stop["operation"])["id"]), "succeeded")
}

func TestNodeDrainMovesEveryMachineOneAtATime(t *testing.T) {
	p, b, _ := nodeFixture(t)
	inner := b.call
	var mu sync.Mutex
	running, most := 0, 0
	b.call = func(r D, target string) (any, error) {
		switch r["op"] {
		case "migrate":
			mu.Lock()
			running++
			most = max(most, running)
			mu.Unlock()
			time.Sleep(50 * time.Millisecond)
			mu.Lock()
			running--
			mu.Unlock()
			return D{"state": "moved"}, nil
		case "migrate_prepare", "migrate_finish", "cloud_init_remove":
			return D{"state": "done"}, nil
		case "cloud_init_read":
			return D{"cloud_init": D{"user": "u", "network": "n"}}, nil
		}
		return inner(r, target)
	}
	p.Config["migration_slot_retry_seconds"] = 0.1
	a := seedMachine(p, "a", 10100)
	b2 := seedMachine(p, "b", 10101)
	b2["ip"], b2["host"], b2["mac"] = "10.200.1.11", 11, "02:ca:01:01:00:01"
	p.Store.Put("machines", 10101, 1, b2)
	_ = a
	runQueue(p)
	ctx, admin := context.Background(), person("root", true)
	r := p.Execute(ctx, "node_drain", D{"node": "carrel01"}, admin)
	moves := dicts(r["moves"])
	if len(moves) != 2 || r["drained"] != true {
		t.Fatal(r)
	}
	for _, m := range moves {
		awaitStateWithin(t, p, str(m["operation"]), "succeeded", 10*time.Second)
	}
	for _, id := range []string{"10100", "10101"} {
		if node := p.Store.Get("machines", id)["node"]; node == "carrel01" || node == nil {
			t.Fatal("machine left on the drained node", id, node)
		}
	}
	if most != 1 {
		t.Fatal("moves overlapped", most)
	}
	e := p.execution(ctx)
	if n, _ := e.Place(1, 1024, 10); n.Name == "carrel01" {
		t.Fatal("placed on a drained node")
	}
	p.Execute(ctx, "node_undrain", D{"node": "carrel01"}, admin)
	if e.drained("carrel01") {
		t.Fatal("undrain did not reopen the node")
	}
}

func awaitStateWithin(t *testing.T, p *Platform, id, state string, limit time.Duration) D {
	t.Helper()
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if op := p.Store.Get("operations", id); op["state"] == state {
			return op
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("operation %s never reached %s: %v", id, state, p.Store.Get("operations", id))
	return nil
}

func TestDrainingTwiceMovesEachMachineOnce(t *testing.T) {
	p, b, _ := nodeFixture(t)
	p.Config["migration_slot_retry_seconds"] = 0.1
	inner := b.call
	var mu sync.Mutex
	moved := map[string]int{}
	b.call = func(r D, target string) (any, error) {
		switch r["op"] {
		case "migrate":
			mu.Lock()
			moved[str(obj(r["machine"])["name"])]++
			mu.Unlock()
			time.Sleep(30 * time.Millisecond)
			return D{"state": "moved"}, nil
		case "migrate_prepare", "migrate_finish", "cloud_init_remove":
			return D{"state": "done"}, nil
		case "cloud_init_read":
			return D{"cloud_init": D{"user": "u", "network": "n"}}, nil
		}
		return inner(r, target)
	}
	seedMachine(p, "a", 10100)
	runQueue(p)
	ctx, admin := context.Background(), person("root", true)
	first := dicts(p.Execute(ctx, "node_drain", D{"node": "carrel01"}, admin)["moves"])
	second := dicts(p.Execute(ctx, "node_drain", D{"node": "carrel01"}, admin)["moves"])
	if len(first) != 1 || len(second) != 1 || first[0]["operation"] != second[0]["operation"] {
		t.Fatal("a second drain queued another move", first, second)
	}
	awaitStateWithin(t, p, str(first[0]["operation"]), "succeeded", 10*time.Second)
	// After the move, a stale request for the same drain does nothing.
	r := p.Execute(ctx, "machine_migrate", D{"tenant": "alice", "machine": "a", "from": "carrel01"}, admin)
	if obj(obj(r["operation"])["result"])["state"] != "moved" || moved["a"] != 1 {
		t.Fatal("moved twice", moved, r)
	}
	// The last open node cannot be drained.
	p.Execute(ctx, "node_drain", D{"node": "carrel02"}, admin)
	if f := p.Execute(ctx, "node_drain", D{"node": "carrel03"}, admin); f["ok"] != false {
		t.Fatal("drained every node", f)
	}
}
