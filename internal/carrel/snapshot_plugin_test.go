package carrel

import (
	"encoding/json"
	"testing"

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

// The snapshot plugin declares what the core snapshot tools do. Until the
// switch (#663 PR 5) the core tools keep their names and carrel counts the
// dimensions itself, so the plugin's tools are left out for that alone.
func TestTheSnapshotPluginDeclaresTheCoreSnapshotTools(t *testing.T) {
	pl := snapshotPluginInfo()
	if len(pl.Operations) != 4 {
		t.Fatalf("operations: %+v", pl.Operations)
	}
	for _, op := range pl.Operations {
		if p := pluginSchemaProblem(op); p != "" {
			t.Errorf("%s: %s", op.Name, p)
		}
		if p := pluginPowerProblem(op); p != "" {
			t.Errorf("%s: %s", op.Name, p)
		}
		if p := pluginObjectProblem(pl, op); p != "quota dimension snapshots is one carrel counts itself" {
			t.Errorf("%s: %q", op.Name, p)
		}
	}
	// With the core dimensions gone, every operation is a tool.
	saved := DefaultQuota
	DefaultQuota = without(DefaultQuota, "snapshots", "snapshot_gb")
	defer func() { DefaultQuota = saved }()
	for _, op := range pl.Operations {
		if p := pluginObjectProblem(pl, op); p != "" {
			t.Errorf("%s after the switch: %s", op.Name, p)
		}
	}
	// The plugin asks for what the core quota holds.
	for _, q := range pl.Quota {
		if num(saved[q.Name]) != q.DefaultLimit {
			t.Errorf("%s: default %v, core %v", q.Name, q.DefaultLimit, saved[q.Name])
		}
	}

	p, b := fixture(t)
	withPlugin(t, p, b)
	reportPlugins(p, []PluginInfo{pl})
	_, left := p.pluginRegistry()
	for _, name := range []string{"snapshot_create", "snapshot_delete", "snapshot_rollback", "snapshot_list"} {
		if left[name] != "a core tool has this name" {
			t.Errorf("%s: %q", name, left[name])
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

// The plugin's tools read as the core snapshot tools do: the same
// descriptions, machine and confirm arguments and hints. The name pattern
// differs on purpose: PVE refuses a one-character name.
func TestTheSnapshotPluginToolsReadAsTheCoreOnes(t *testing.T) {
	core := map[string]D{}
	for _, d := range dicts(Contract["tools"]) {
		core[str(d["name"])] = d
	}
	for _, op := range snapshotPluginInfo().Operations {
		c := core["snapshot_"+op.Name]
		if c == nil {
			t.Fatalf("%s: no core tool", op.Name)
		}
		// The rollback says it shuts a running guest down gracefully, and
		// carrel adds the operation sentence to every plugin tool.
		want := str(c["description"])
		if op.Name == "rollback" {
			want = "Roll back disk contents; later changes are lost. Confirm snapshot name. A running machine is shut down gracefully first. " +
				"Restores the previous power state and checks guest readiness. Brief downtime is expected."
		}
		if op.Description != want {
			t.Errorf("%s: description %q, want %q", op.Name, op.Description, want)
		}
		var params D
		must(json.Unmarshal(op.Params, &params))
		props, coreProps := obj(params["properties"]), obj(obj(c["inputSchema"])["properties"])
		for _, key := range []string{"machine"} {
			if !equal(props[key], coreProps[key]) {
				t.Errorf("%s.%s: %s, core %s", op.Name, key, encoded(props[key]), encoded(coreProps[key]))
			}
		}
		if !equal(params["required"], obj(c["inputSchema"])["required"]) {
			t.Errorf("%s: required %v, core %v", op.Name, params["required"], obj(c["inputSchema"])["required"])
		}
		a := obj(c["annotations"])
		if op.ReadOnly != boolean(a["readOnlyHint"]) || op.Destructive != boolean(a["destructiveHint"]) || op.Idempotent != boolean(a["idempotentHint"]) {
			t.Errorf("%s: hints read_only %v destructive %v idempotent %v, core %s", op.Name, op.ReadOnly, op.Destructive, op.Idempotent, encoded(a))
		}
	}
}
