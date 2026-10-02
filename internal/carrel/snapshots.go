package carrel

import "fmt"

func (e *Execution) SnapshotAction(tool string, a, t D) D {
	dry, n := boolean(a["dry_run"]), integer(t["n"])
	m := e.Machine(t, a["machine"])
	if m["resize_from"] != nil && (tool == "snapshot_create" || tool == "snapshot_rollback") {
		fail("conflict", "Finish the pending machine_resize before snapshot operations", D{"recovery": "resolve_prerequisite"})
	}
	snaps := filter(e.S.Objects("snapshots", n), func(s D) bool { return integer(s["vmid"]) == integer(m["vmid"]) })
	if tool == "snapshot_list" {
		return D{"snapshots": snaps, "snapshot_storage": e.SnapshotUsage(t)}
	}
	id := fmt.Sprintf("%d-%s", integer(m["vmid"]), str(a["name"]))
	snap := find(snaps, func(s D) bool { return s["name"] == a["name"] })
	var delta D
	configuration := pick(m, "cpu", "memory_mb", "disk_gb", "nics")
	if tool == "snapshot_create" {
		if snap != nil && !e.sameOperation(snap) {
			fail("conflict", "Snapshot exists", D{"recovery": "revise_request"})
		}
		delta = D{}
		if snap == nil {
			delta = D{"snapshots": 1, "snapshot_gb": m["disk_gb"]}
		}
		e.Quota(t, delta)
		if snap == nil {
			e.Admission(0, 0, num(m["disk_gb"]), nil, true)
			snap = D{"id": id, "vmid": m["vmid"], "name": a["name"], "disk_gb": m["disk_gb"], "configuration": configuration}
		}
	} else if snap == nil {
		fail("not_found", "Snapshot not found")
	} else if tool == "snapshot_delete" {
		delta = D{"snapshots": -1, "snapshot_gb": -num(snap["disk_gb"])}
	}
	effects := D{}
	if tool == "snapshot_rollback" {
		if !equal(snap["configuration"], configuration) {
			fail("conflict", "Resources or NICs changed since this snapshot; administrator review required")
		}
		if a["confirm"] != a["name"] {
			fail("invalid", "confirm must equal snapshot name")
		}
		effects = D{"power_state": "restored_to_previous", "downtime_expected": true}
	}
	if !dry {
		var restore D
		if tool == "snapshot_rollback" {
			restore = obj(e.Op["rollback_restore"])
			if len(restore) == 0 {
				status := obj(e.Call(D{"op": "status", "machine": m}))
				if powerState(status) == "paused" {
					fail("conflict", "Resume or shut down the VM before disk rollback; rollback cannot preserve paused memory", D{"recovery": "resolve_prerequisite"})
				}
				report := obj(e.S.Get("guest_reports", str(m["vmid"])))
				restore = D{"running": powerState(status) == "running", "boot_id": report["boot_id"]}
				e.Op["rollback_restore"] = restore
				e.P.Operations.Save(e.Op)
			}
		}
		if tool == "snapshot_create" {
			snap["state"] = "creating"
			e.Put("snapshots", id, n, snap)
		}
		action := map[string]string{"snapshot_create": "snapshot", "snapshot_delete": "delsnapshot", "snapshot_rollback": "rollback"}[tool]
		e.Call(D{"op": "action", "machine": m, "name": a["name"], "action": action})
		if tool == "snapshot_create" {
			snap["state"] = "ready"
			e.Put("snapshots", id, n, snap)
		} else if tool == "snapshot_delete" {
			e.S.Remove("snapshots", id)
			snap["state"] = "deleted"
		} else {
			state := "stopped"
			m["ssh_ready"] = false
			if boolean(restore["running"]) {
				e.Call(D{"op": "action", "machine": m, "action": "start"})
				m["state"] = "initializing"
				state = "running"
			} else {
				m["state"] = "stopped"
			}
			m["power_state"] = state
			e.Put("machines", m["vmid"], n, m)
			effects = D{"power_state": state, "power_state_restored": true}
		}
		e.P.inventory.Invalidate()
		e.RefreshStorage()
	}
	if dry && tool == "snapshot_create" {
		snap = D{"name": snap["name"], "machine": m["name"], "disk_gb": m["disk_gb"], "state": "planned"}
	}
	q := e.Quota(t)
	if dry {
		q = e.Quota(t, delta)
	}
	r := merge(D{"snapshot": snap, "snapshot_storage": e.SnapshotUsage(t), "dry_run": dry, "quota_after": q}, effects)
	if !dry && tool == "snapshot_rollback" {
		r["machine"] = e.PublicMachine(m, e.S.Objects("ports", n))
	}
	return r
}
