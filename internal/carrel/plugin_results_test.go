package carrel

import (
	"encoding/json"
	"testing"
	"time"
)

// measuredCopies is copyPlugin with copy_gb measured, a list and a restore
// that rewinds the disk, as a snapshot plugin declares them.
func measuredCopies() []PluginInfo {
	pl := copyPlugin("freeze", "migrate", "backfill")
	pl[0].Quota[1].Measured = true
	pl[0].Operations = append(pl[0].Operations,
		PluginOperation{Name: "list", Member: true, ReadOnly: true, ObjectKind: "copy", ObjectEffect: "list",
			Params: json.RawMessage(`{"type":"object","properties":{"machine":{"type":"string"}},"required":["machine"]}`)},
		PluginOperation{Name: "restore", Member: true, Stopped: true, Rewinds: true, ObjectKind: "copy", ObjectEffect: "use", ObjectParam: "name",
			Params: json.RawMessage(copySchema)})
	return pl
}

func withMeasuredCopies(t *testing.T) *Platform {
	t.Helper()
	p, _ := withCopyPlugin(t)
	reportPlugins(p, measuredCopies())
	return p
}

// An object operation answers as a core action does: the record, the
// quota delta and the storage the tenant's disk objects hold.
func TestAnObjectOperationAnswersAsACoreActionDoes(t *testing.T) {
	p := withMeasuredCopies(t)
	r := member(p, "copies_take", D{"machine": "web", "name": "a", "dry_run": true})
	delta, copy, storage := obj(r["delta"]), obj(r["copy"]), obj(r["copy_storage"])
	if num(delta["copies"]) != 1 || num(delta["copy_gb"]) != 20 || copy["state"] != "planned" || copy["machine"] != "web" || num(copy["disk_gb"]) != 20 {
		t.Fatalf("dry take: %s", encoded(r))
	}
	if storage["copy_gb_counts"] != "declared" || storage["accounting"] != "pending_sample" || r["quota_before"] == nil {
		t.Fatalf("dry take storage: %s", encoded(r))
	}

	r = member(p, "copies_take", D{"machine": "web", "name": "a", "wait_seconds": 5, "detail": "full"})
	result := obj(obj(r["operation"])["result"])
	copy = obj(result["copy"])
	if copy["id"] != "10100-a" || copy["state"] != "ready" || copy["configuration"] == nil || num(obj(result["delta"])["copies"]) != 1 {
		t.Fatalf("take: %s", encoded(result))
	}

	r = member(p, "copies_list", D{"machine": "web"})
	if list := dicts(r["copys"]); len(list) != 1 || list[0]["name"] != "a" || r["copy_storage"] == nil {
		t.Fatalf("list: %s", encoded(r))
	}

	r = member(p, "copies_take", D{"machine": "web", "name": "a", "wait_seconds": 5})
	if f := failure(r); f["code"] != "conflict" || f["message"] != "Copy exists" {
		t.Fatalf("again: %s", encoded(r))
	}
	if f := failure(member(p, "copies_drop", D{"machine": "web", "name": "b", "dry_run": true})); f["message"] != "Copy not found" {
		t.Fatalf("missing: %s", encoded(f))
	}

	r = member(p, "copies_drop", D{"machine": "web", "name": "a", "wait_seconds": 5, "detail": "full"})
	result = obj(obj(r["operation"])["result"])
	if obj(result["copy"])["state"] != "deleted" || num(obj(result["delta"])["copy_gb"]) != -20 {
		t.Fatalf("drop: %s", encoded(result))
	}
}

// Sampled, a measured dimension counts what is held: a new object adds
// nothing yet, and a tenant over its limit gets no more.
func TestAMeasuredDimensionCountsWhatIsHeld(t *testing.T) {
	p := withMeasuredCopies(t)
	member(p, "copies_take", D{"machine": "web", "name": "a", "wait_seconds": 5})
	sampleSnapshots(p, 3, time.Minute, true)
	if used := num(quotaUsed(p, "copy_gb")); used != 3 {
		t.Fatalf("held %v", used)
	}
	r := member(p, "copies_take", D{"machine": "web", "name": "b", "dry_run": true})
	if _, counted := obj(r["delta"])["copy_gb"]; counted || obj(r["copy_storage"])["copy_gb_counts"] != "held" {
		t.Fatalf("sampled take: %s", encoded(r))
	}
	sampleSnapshots(p, 150, time.Minute, true)
	if f := failure(member(p, "copies_take", D{"machine": "web", "name": "b", "dry_run": true})); f["code"] != "quota_exceeded" || f["dimension"] != "copy_gb" {
		t.Fatalf("over: %s", encoded(f))
	}
	// The tenant's last object frees all that is held.
	sampleSnapshots(p, 3, time.Minute, true)
	r = member(p, "copies_drop", D{"machine": "web", "name": "a", "dry_run": true})
	if num(obj(r["delta"])["copy_gb"]) != -3 {
		t.Fatalf("last drop: %s", encoded(r))
	}
	// A stale sample counts what was charged.
	sampleSnapshots(p, 3, time.Hour, true)
	if used := num(quotaUsed(p, "copy_gb")); used != 20 {
		t.Fatalf("stale %v", used)
	}
}

// A rewind to an object is refused once the machine's resources changed.
func TestARewindRefusesAChangedMachine(t *testing.T) {
	p := withMeasuredCopies(t)
	member(p, "copies_take", D{"machine": "web", "name": "a", "wait_seconds": 5})
	m := p.Store.Get("machines", "10100")
	m["cpu"] = num(m["cpu"]) + 1
	p.Store.Put("machines", 10100, 1, m)
	r := member(p, "copies_restore", D{"machine": "web", "name": "a", "dry_run": true})
	if f := failure(r); f["code"] != "conflict" || f["message"] != "Resources or NICs changed since this copy; administrator review required" {
		t.Fatalf("restore: %s", encoded(r))
	}
	// A record made without the configuration is refused as well.
	m["cpu"] = num(m["cpu"]) - 1
	p.Store.Put("machines", 10100, 1, m)
	row, _ := copyRow(p, "a")
	row.Configuration = nil
	p.Store.Put(pluginObjectRows, row.ID, 1, decode(string(encoded(row))))
	if f := failure(member(p, "copies_restore", D{"machine": "web", "name": "a", "dry_run": true})); f["code"] != "conflict" {
		t.Fatalf("no configuration: %s", encoded(f))
	}
}

// A kind whose result keys would be carrel's is not a tool.
func TestAKindCannotTakeCarrelsResultKeys(t *testing.T) {
	pl := copyPlugin()
	pl[0].Objects[0].Name = "machine"
	for i := range pl[0].Operations {
		pl[0].Operations[i].ObjectKind = "machine"
	}
	if problem := pluginObjectProblem(pl[0], pl[0].Operations[0]); problem != "object kind machine would name the result key machine, which is carrel's" {
		t.Fatal(problem)
	}
	list := measuredCopies()[0]
	bad := list.Operations[2]
	bad.ReadOnly = false
	if problem := pluginObjectProblem(list, bad); problem != "a list of objects is read_only and names no object_param" {
		t.Fatal(problem)
	}
}
