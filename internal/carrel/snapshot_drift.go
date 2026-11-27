package carrel

import (
	"encoding/json"
	"log/slog"
	"slices"
)

// SweepMissingSnapshots drops the snapshot records whose PVE snapshot is gone
// (#738). A record can outlive its snapshot (#736): quota still charges it and
// nothing shows it. For each machine with ready snapshot records it asks the
// snapshot plugin's list operation, and drops a record only when that call
// succeeded and its answer is well formed and lacks the record's name. A
// plugin error, a timeout, a plugin no node reports, a missing or malformed
// result, a machine that is changing, and a record that is not ready (a create
// or delete may be in flight) all keep the record: an unknown answer never
// deletes. Removing the row releases its quota, as a delete does.
func (e *Execution) SweepMissingSnapshots() []D {
	byMachine := map[int][]pluginObject{}
	tenants := map[string]int{}
	for _, r := range e.S.Rows("SELECT tenant, data FROM objects WHERE kind=? ORDER BY id", pluginObjectRows) {
		var o pluginObject
		if json.Unmarshal([]byte(str(r["data"])), &o) != nil || o.Plugin != "snapshot" || o.Kind != "snapshot" || o.State != "ready" {
			continue
		}
		byMachine[o.VMID] = append(byMachine[o.VMID], o)
		tenants[o.ID] = integer(r["tenant"])
	}
	dropped := []D{}
	for _, vmid := range slices.Sorted(mapKeys(byMachine)) {
		var names []string
		var m D
		listed := false
		if err := attempt(func() { m, names, listed = e.listMachineSnapshots(vmid) }); err != nil || !listed {
			if err != nil {
				slog.Warn("snapshot_list_failed", "vmid", vmid, "error", describe(err))
			}
			continue
		}
		for _, o := range byMachine[vmid] {
			if slices.Contains(names, o.Name) {
				continue
			}
			n := tenants[o.ID]
			removed := false
			e.Transaction(func(tx *Execution) {
				// Read again under the writer: a delete or a new create of
				// the name since the list makes the answer stale.
				cur, ok := rowOf[pluginObject](tx.S, pluginObjectRows, o.ID)
				if !ok || cur.State != "ready" || cur.OperationID != o.OperationID || cur.Run != o.Run {
					return
				}
				tx.S.Remove(pluginObjectRows, o.ID)
				removed = true
			})
			if removed {
				slog.Info("snapshot_record_dropped", "machine", m["name"], "vmid", vmid, "name", o.Name, "tenant", n)
				dropped = append(dropped, D{"machine": m["name"], "vmid": vmid, "name": o.Name, "tenant_n": n})
			}
		}
	}
	return dropped
}

func mapKeys[V any](m map[int]V) func(func(int) bool) {
	return func(yield func(int) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}

// listMachineSnapshots asks the plugin for the machine's snapshot names. It
// reports listed only for a successful, well formed answer.
func (e *Execution) listMachineSnapshots(vmid int) (m D, names []string, listed bool) {
	m = e.S.Get("machines", str(vmid))
	if m == nil || contains(stopBlocked, m["state"]) {
		return nil, nil, false
	}
	node := e.P.nodeOf(m).Name
	pl, ok := e.P.pluginInfo(node, "snapshot")
	if !ok {
		return nil, nil, false
	}
	op, ok := e.P.pluginOperation(node, "snapshot", "list")
	if !ok || !op.ReadOnly {
		return nil, nil, false
	}
	job := D{"op": "plugin", "plugin": "snapshot", "operation": "list", "call": "start",
		"idempotency_key": "inline-" + randomID(), "params": D{"machine": str(vmid)},
		"machine": pluginMachineFacts(m), "operation_spec": PluginOperationSpec(pl, op)}
	r := obj(e.Call(job, e.P.nodeTarget(node)))
	if !boolean(r["done"]) || r["state"] != "succeeded" {
		return m, nil, false
	}
	names, listed = snapshotNames(r["result"])
	return m, names, listed
}

// snapshotNames reads the list result: an object, or its JSON text, with a
// "snapshots" array of strings. Anything else is not an answer.
func snapshotNames(v any) ([]string, bool) {
	if s, ok := v.(string); ok {
		var parsed D
		if json.Unmarshal([]byte(s), &parsed) != nil {
			return nil, false
		}
		v = parsed
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, false
	}
	list, ok := m["snapshots"].([]any)
	if !ok {
		return nil, false
	}
	names := make([]string, 0, len(list))
	for _, x := range list {
		s, ok := x.(string)
		if !ok {
			return nil, false
		}
		names = append(names, s)
	}
	return names, true
}
