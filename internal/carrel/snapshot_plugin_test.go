package carrel

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/NYCU-WinLab/carrel/plugins/snapshot"
)

// snapshotPluginInfo is the snapshot plugin's Describe as an agent reports it.
func snapshotPluginInfo() PluginInfo {
	d := snapshot.Describe()
	pl := PluginInfo{Name: d.Name, Version: d.Version, Contract: d.Contract, Supported: true}
	for _, op := range d.Operations {
		pl.Operations = append(pl.Operations, PluginOperation{Name: op.Name, Description: op.Description, Params: json.RawMessage(op.ParamsSchema),
			Member: op.Member, ReadOnly: op.ReadOnly, Destructive: op.Destructive, Idempotent: op.Idempotent, Toolset: op.Toolset, DryRun: op.DryRun,
			ObjectKind: op.ObjectKind, ObjectEffect: op.ObjectEffect, ObjectParam: op.ObjectParam, Stopped: op.Stopped, Rewinds: op.Rewinds, Confirm: op.Confirm})
	}
	for _, q := range d.Quota {
		pl.Quota = append(pl.Quota, PluginQuota{Name: q.Name, DefaultLimit: q.DefaultLimit, Unit: q.Unit, Measured: q.Measured})
	}
	for _, k := range d.Objects {
		kind := PluginObjectKind{Name: k.Name, Disk: k.Disk, Holds: k.Holds}
		for _, c := range k.Charges {
			kind.Charges = append(kind.Charges, PluginCharge{Dimension: c.Dimension, Amount: c.Amount, Per: c.Per})
		}
		pl.Objects = append(pl.Objects, kind)
	}
	return pl
}

// The snapshot plugin's 4 operations are all tools, under the names and
// with the default limits the core snapshot tools had (#663).
func TestTheSnapshotPluginDeclaresTheSnapshotTools(t *testing.T) {
	pl := snapshotPluginInfo()
	if len(pl.Operations) != 4 {
		t.Fatalf("operations: %+v", pl.Operations)
	}
	for _, op := range pl.Operations {
		for _, p := range []string{pluginSchemaProblem(op), pluginPowerProblem(op), pluginObjectProblem(pl, op)} {
			if p != "" {
				t.Errorf("%s: %s", op.Name, p)
			}
		}
	}
	for _, q := range pl.Quota {
		if want := map[string]float64{"snapshots": 4, "snapshot_gb": 200}[q.Name]; q.DefaultLimit != want {
			t.Errorf("%s: default %v, want %v", q.Name, q.DefaultLimit, want)
		}
	}
	for _, dim := range []string{"snapshots", "snapshot_gb"} {
		if _, ok := DefaultQuota[dim]; ok {
			t.Errorf("carrel still counts %s itself", dim)
		}
	}
	p, b := fixture(t)
	withPlugin(t, p, b)
	reportPlugins(p, []PluginInfo{pl})
	tools, left := p.pluginRegistry()
	for _, name := range []string{"snapshot_create", "snapshot_delete", "snapshot_rollback", "snapshot_list"} {
		if tools[name] == nil {
			t.Errorf("%s: left out, %q", name, left[name])
		}
	}
}

// A confirm repeats the object's name, checked before anything changes.
func TestAConfirmRepeatsTheObjectName(t *testing.T) {
	p := withMeasuredCopies(t)
	pl := measuredCopies()
	restore := &pl[0].Operations[3]
	restore.Confirm = true
	restore.Params = json.RawMessage(`{"type":"object","properties":{"machine":{"type":"string"},"name":{"type":"string"},"confirm":{"type":"string"}},"required":["machine","name","confirm"]}`)
	reportPlugins(p, pl)
	member(p, "copies_take", D{"machine": "web", "name": "a", "wait_seconds": 5})
	if f := failure(member(p, "copies_restore", D{"machine": "web", "name": "a", "confirm": "b", "dry_run": true})); f["code"] != "invalid" || f["message"] != "confirm must equal copy name" {
		t.Fatalf("a wrong confirm: %s", encoded(f))
	}
	if r := member(p, "copies_restore", D{"machine": "web", "name": "a", "confirm": "a", "dry_run": true}); r["ok"] != true {
		t.Fatalf("confirmed: %s", encoded(r))
	}
	restore.Params = json.RawMessage(copySchema)
	if problem := pluginObjectProblem(pl[0], *restore); problem != `an operation that asks to confirm must name its object and require a string "confirm"` {
		t.Fatal(problem)
	}
}

// putSnapshotRecord writes a snapshot plugin record as the migration does
// (#663); state "" is ready.
func putSnapshotRecord(p *Platform, n, vmid int, name string, gb int, state string, configuration D) {
	if state == "" {
		state = "ready"
	}
	id := pluginObjectID("snapshot", "snapshot", vmid, name)
	row := D{"id": id, "plugin": "snapshot", "kind": "snapshot", "name": name, "vmid": vmid, "state": state,
		"charge": D{"snapshots": 1, "snapshot_gb": gb}, "holds": []string{"freeze", "migrate", "backfill"}, "disk_gb": gb}
	if configuration != nil {
		row["configuration"] = configuration
	}
	p.Store.Put(pluginObjectRows, id, n, row)
}

// reportSnapshotPlugin makes node carrel01 report the snapshot plugin; the
// returned fake answers its runs when a backend relays them to it.
func reportSnapshotPlugin(t *testing.T, p *Platform) *fakePlugins {
	t.Helper()
	pluginPoll, pluginRecheck = 5*time.Millisecond, 0.05
	t.Cleanup(func() { pluginPoll, pluginRecheck = 2*time.Second, 10 })
	reportPlugins(p, []PluginInfo{snapshotPluginInfo()})
	return &fakePlugins{ops: map[string]D{}, gets: map[string]int{}}
}

// withSnapshotPlugin is a site whose node reports the snapshot plugin and
// answers its runs; call, when set, answers every other request, else the
// backend answers as it does with no call.
func withSnapshotPlugin(t *testing.T, p *Platform, b *fakeBackend, call func(D, string) (any, error)) *fakePlugins {
	t.Helper()
	f := reportSnapshotPlugin(t, p)
	b.call = func(r D, target string) (any, error) {
		switch {
		case r["op"] == "plugin":
			return f.call(r, target)
		case call != nil:
			return call(r, target)
		case r["op"] == "inventory":
			b.mu.Lock()
			defer b.mu.Unlock()
			return clone(b.inventory), nil
		case r["op"] == "storage_usage":
			return []D{}, nil
		}
		return D{"status": "running"}, nil
	}
	return f
}
