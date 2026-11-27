package carrel

import (
	"context"
	"encoding/json"
	"testing"
)

const copySchema = `{"type":"object","properties":{"machine":{"type":"string"},"name":{"type":"string"}},"required":["machine","name"],"additionalProperties":false}`

// copyPlugin declares object kind "copy": one counts 1 against copies and
// its machine's disk against copy_gb, and holds what holds names.
func copyPlugin(holds ...string) []PluginInfo {
	return []PluginInfo{{Name: "copies", Version: "1.0.0", Contract: 1, Supported: true,
		Quota: []PluginQuota{{Name: "copies", DefaultLimit: 2}, {Name: "copy_gb", DefaultLimit: 100, Unit: "GiB"}},
		Objects: []PluginObjectKind{{Name: "copy", Holds: holds, Disk: true,
			Charges: []PluginCharge{{Dimension: "copies", Amount: 1}, {Dimension: "copy_gb", Amount: 1, Per: "disk_gb"}}}},
		Operations: []PluginOperation{
			{Name: "take", Member: true, DryRun: true, ObjectKind: "copy", ObjectEffect: "create", ObjectParam: "name", Params: json.RawMessage(copySchema)},
			{Name: "drop", Member: true, ObjectKind: "copy", ObjectEffect: "delete", ObjectParam: "name", Params: json.RawMessage(copySchema)},
		}}}
}

func withCopyPlugin(t *testing.T, holds ...string) (*Platform, *fakePlugins) {
	t.Helper()
	p, b := fixture(t)
	f := withPlugin(t, p, b)
	b.call = func(r D, target string) (any, error) {
		if r["op"] == "inventory" {
			return baseInventory(), nil
		}
		return f.call(r, target)
	}
	reportPlugins(p, copyPlugin(holds...))
	runQueue(p)
	seedMachine(p, "web", 10100)
	return p, f
}

func copyRow(p *Platform, name string) (pluginObject, bool) {
	return rowOf[pluginObject](p.Store, pluginObjectRows, "copies/copy/10100/"+name)
}

func quotaUsed(p *Platform, dim string) any {
	return obj(obj(member(p, "quota_get", D{})["quota"])["used"])[dim]
}

// A create is checked, charged and reserved before the plugin starts, and
// the plugin gets the reservation; a delete frees it.
func TestAPluginObjectIsChargedReservedAndFreed(t *testing.T) {
	p, f := withCopyPlugin(t, "freeze")

	r := member(p, "copies_take", D{"machine": "web", "name": "a", "dry_run": true})
	if !boolean(r["dry_run"]) || obj(obj(r["object"])["charge"])["copy_gb"] != float64(20) || r["quota_after"] == nil {
		t.Fatalf("dry run: %s", encoded(r))
	}
	if _, ok := copyRow(p, "a"); ok {
		t.Fatal("a dry run reserved a record")
	}

	r = member(p, "copies_take", D{"machine": "web", "name": "a", "wait_seconds": 5})
	op := obj(r["operation"])
	row, ok := copyRow(p, "a")
	if op["state"] != "succeeded" || !ok || row.State != "ready" || row.Charge["copy_gb"] != 20 || row.OperationID != op["id"] {
		t.Fatalf("take: %s, row %+v", encoded(r), row)
	}
	if obj(obj(op["result"])["object"])["state"] != "ready" {
		t.Fatalf("result: %s", encoded(op["result"]))
	}
	if start := f.starts[len(f.starts)-1]; start["reservation"] != "copies/copy/10100/a" {
		t.Fatalf("the plugin got no reservation: %v", start)
	}
	if num(quotaUsed(p, "copies")) != 1 || num(quotaUsed(p, "copy_gb")) != 20 {
		t.Fatalf("usage: %v", member(p, "quota_get", D{}))
	}

	// The same name again is refused, and the record stays the first one's.
	r = member(p, "copies_take", D{"machine": "web", "name": "a", "wait_seconds": 5})
	if failure(r)["code"] != "conflict" {
		t.Fatalf("again: %s", encoded(r))
	}
	if row, _ := copyRow(p, "a"); row.OperationID != op["id"] || row.State != "ready" {
		t.Fatalf("the record changed: %+v", row)
	}
	member(p, "copies_take", D{"machine": "web", "name": "b", "wait_seconds": 5})
	starts := len(f.starts)
	r = member(p, "copies_take", D{"machine": "web", "name": "c", "wait_seconds": 5})
	if failure(r)["code"] != "quota_exceeded" || len(f.starts) != starts {
		t.Fatalf("over the limit: %s", encoded(r))
	}
	if _, ok := copyRow(p, "c"); ok {
		t.Fatal("a refused create left a record")
	}

	r = member(p, "copies_drop", D{"machine": "web", "name": "a", "wait_seconds": 5})
	if obj(r["operation"])["state"] != "succeeded" || obj(obj(obj(r["operation"])["result"])["object"])["state"] != "deleted" {
		t.Fatalf("drop: %s", encoded(r))
	}
	if _, ok := copyRow(p, "a"); ok || num(quotaUsed(p, "copies")) != 1 {
		t.Fatalf("drop left the record or the charge: %v", quotaUsed(p, "copies"))
	}
	if r := member(p, "copies_drop", D{"machine": "web", "name": "a", "wait_seconds": 5}); failure(r)["code"] != "not_found" {
		t.Fatalf("drop of nothing: %s", encoded(r))
	}
}

// A record goes only on proof the object does not exist: a refused first
// start, or a delete the plugin answers not_found. A run that failed any
// other way keeps it charged, and a delete clears it.
func TestAPluginObjectGoesOnlyOnProof(t *testing.T) {
	p, f := withCopyPlugin(t)
	set := func(fail, outcome string, failure D) {
		f.mu.Lock()
		f.fail, f.outcome, f.failure = fail, outcome, failure
		f.mu.Unlock()
	}

	set("plugin_refused", "", nil)
	if r := member(p, "copies_take", D{"machine": "web", "name": "x", "wait_seconds": 5}); obj(r["operation"])["state"] != "failed" {
		t.Fatalf("refused: %s", encoded(r))
	}
	if _, ok := copyRow(p, "x"); ok {
		t.Fatal("a refused first start kept its record")
	}

	set("", "failed", nil)
	if r := member(p, "copies_take", D{"machine": "web", "name": "y", "wait_seconds": 5}); obj(r["operation"])["state"] != "failed" {
		t.Fatalf("failed run: %s", encoded(r))
	}
	if row, ok := copyRow(p, "y"); !ok || row.State != "creating" || num(quotaUsed(p, "copies")) != 1 {
		t.Fatalf("a run that may have made the copy lost its record: %+v", row)
	}

	// A retry whose new run is refused proves nothing of the first run,
	// which may have made the copy.
	set("plugin_refused", "", nil)
	var first D
	for _, o := range p.Store.Objects("operations") {
		if obj(o["plugin"])["object_name"] == "y" {
			first = o
		}
	}
	if r := p.Operations.Retry(p.Store.TenantN(1), str(first["id"]), person("alice", false)); r["operation"] == nil {
		t.Fatalf("retry: %v", r)
	}
	awaitState(t, p, str(first["id"]), "failed")
	if row, ok := copyRow(p, "y"); !ok || row.State != "creating" {
		t.Fatal("a refused retry dropped the record of the first run")
	}

	// A refused delete leaves the record as it was.
	set("plugin_refused", "", nil)
	member(p, "copies_drop", D{"machine": "web", "name": "y", "wait_seconds": 5})
	if row, _ := copyRow(p, "y"); row.State != "creating" || row.DeletingBy != "" {
		t.Fatalf("after a refused delete: %+v", row)
	}

	set("", "failed", D{"error_code": "not_found"})
	r := member(p, "copies_drop", D{"machine": "web", "name": "y", "wait_seconds": 5})
	if failure(r)["code"] != "not_found" {
		t.Fatalf("drop: %s", encoded(r))
	}
	if _, ok := copyRow(p, "y"); ok || num(quotaUsed(p, "copies")) != 0 {
		t.Fatal("a delete the plugin answered not_found kept the record")
	}
}

func putCopy(p *Platform, vmid int, holds ...string) {
	id := pluginObjectID("copies", "copy", vmid, "kept")
	p.Store.Put(pluginObjectRows, id, 1, D{"id": id, "plugin": "copies", "kind": "copy", "name": "kept", "vmid": vmid,
		"state": "ready", "holds": holds, "charge": D{"copies": 1}, "disk_gb": 20})
}

// The records hold the machine whether or not the plugin is reported: no
// node reports it in these.
func TestPluginObjectsHoldTheirMachine(t *testing.T) {
	t.Run("freeze", func(t *testing.T) {
		p, _, _ := freezeSite(t)
		putCopy(p, 10100, "freeze")
		r := member(p, "machine_freeze", D{"machine": "box", "confirm": "box", "wait_seconds": 5})
		if failure(r)["code"] != "conflict" || len(dicts(failure(r)["plugin_objects"])) != 1 {
			t.Fatalf("freeze: %s", encoded(r))
		}
	})
	t.Run("delete", func(t *testing.T) {
		p, _ := fixture(t)
		runQueue(p)
		seedMachine(p, "web", 10100)
		putCopy(p, 10100, "delete")
		if r := member(p, "machine_delete", D{"machine": "web", "confirm": "web", "wait_seconds": 5}); failure(r)["code"] != "conflict" {
			t.Fatalf("held delete: %s", encoded(r))
		}
		// A kind that does not hold the delete dies with its machine.
		putCopy(p, 10100, "freeze")
		r := member(p, "machine_delete", D{"machine": "web", "confirm": "web", "dry_run": true})
		if num(obj(obj(r["quota_after"])["used"])["copies"]) != 0 {
			t.Fatalf("the delete does not free the charge: %s", encoded(r))
		}
		if r := member(p, "machine_delete", D{"machine": "web", "confirm": "web", "wait_seconds": 5}); obj(r["operation"])["state"] != "succeeded" {
			t.Fatalf("delete: %s", encoded(r))
		}
		if len(p.Store.Objects(pluginObjectRows)) != 0 {
			t.Fatal("the machine's records outlived it")
		}
	})
	t.Run("frozen delete", func(t *testing.T) {
		p, _, _ := freezeSite(t)
		putCopy(p, 10100, "delete")
		if r := member(p, "machine_freeze", D{"machine": "box", "confirm": "box", "wait_seconds": 5}); obj(r["operation"])["state"] != "succeeded" {
			t.Fatalf("freeze: %s", encoded(r))
		}
		if r := member(p, "machine_delete", D{"machine": "box", "confirm": "box", "wait_seconds": 5}); failure(r)["code"] != "conflict" {
			t.Fatalf("frozen delete: %s", encoded(r))
		}
		if len(p.Store.Objects(pluginObjectRows)) != 1 {
			t.Fatal("the frozen delete dropped the record")
		}
	})
	t.Run("sweep", func(t *testing.T) {
		// A VM that vanished is swept, but an object that outlives its
		// machine keeps its record.
		p, _ := fixture(t)
		m := seedMachine(p, "web", 10100)
		putCopy(p, 10100, "delete")
		p.execution(context.Background()).removeMachineRecord(1, m)
		if len(p.Store.Objects(pluginObjectRows)) != 1 || p.Store.Get("machines", "10100") != nil {
			t.Fatal("the sweep dropped a record that outlives its machine")
		}
	})
	t.Run("migrate and drain", func(t *testing.T) {
		p, _, _ := nodeFixture(t)
		seedMachine(p, "web", 10100)
		runQueue(p)
		putCopy(p, 10100, "migrate")
		ctx, admin := context.Background(), person("root", true)
		r := p.Execute(ctx, "machine_migrate", D{"tenant": "alice", "machine": "web", "node": "carrel02", "wait_seconds": 5}, admin)
		if failure(r)["code"] != "conflict" {
			t.Fatalf("migrate: %s", encoded(r))
		}
		r = p.Execute(ctx, "node_drain", D{"node": "carrel01", "dry_run": true}, admin)
		if staying := dicts(r["staying"]); len(staying) != 1 || staying[0]["reason"] != "has_plugin_objects" {
			t.Fatalf("drain: %s", encoded(r))
		}
	})
}

// A plugin's dimensions keep their limits while it is not reported, an
// admin sets them as any other, and a plugin cannot claim carrel's own.
func TestPluginQuotaDimensionsOutliveTheReport(t *testing.T) {
	p, _ := withCopyPlugin(t)
	member(p, "copies_take", D{"machine": "web", "name": "a", "wait_seconds": 5})
	reportPlugins(p, nil)
	q := obj(member(p, "quota_get", D{})["quota"])
	if obj(q["limit"])["copies"] != float64(2) || obj(q["units"])["copy_gb"] != "GiB" || len(arr(q["over_limit"])) != 0 {
		t.Fatalf("unreported: %s", encoded(q))
	}
	root := person("root", true)
	if r := p.Execute(context.Background(), "quota_set", D{"tenant": "alice", "dimension": "copies", "amount": 5}, root); !boolean(r["ok"]) {
		t.Fatalf("quota_set: %s", encoded(r))
	}
	if r := p.Execute(context.Background(), "quota_set", D{"tenant": "alice", "dimension": "nothing", "amount": 5}, root); failure(r)["code"] != "invalid" {
		t.Fatalf("quota_set of an unknown dimension: %s", encoded(r))
	}

	claim := copyPlugin()
	claim[0].Quota[1].Name = "snapshot_gb"
	claim[0].Objects[0].Charges[1].Dimension = "snapshot_gb"
	reportPlugins(p, claim)
	tools, left := p.pluginRegistry()
	if tools["copies_take"] != nil || left["copies_take"] != "quota dimension snapshot_gb is one carrel counts itself" {
		t.Fatalf("a core dimension: %v", left)
	}
}
