package carrel

import (
	"context"
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
