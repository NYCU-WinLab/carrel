package carrel

import (
	"context"
	"errors"
	"sync"
	"testing"
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
