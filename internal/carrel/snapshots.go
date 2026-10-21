package carrel

import "fmt"

func (e *Execution) SnapshotAction(tool string, a, t D) D {
	dry, n := boolean(a["dry_run"]), integer(t["n"])
	m := e.Machine(t, a["machine"])
	if m["resize_from"] != nil && (tool == "snapshot_create" || tool == "snapshot_rollback") {
		fail("conflict", "Finish the pending machine_resize before snapshot operations", D{"recovery": "resolve_prerequisite"})
	}
	snaps := []snapshotRecord{}
	for _, s := range e.snapshots(n) {
		if s.VMID == integer(m["vmid"]) {
			snaps = append(snaps, s)
		}
	}
	if tool == "snapshot_list" {
		return D{"snapshots": snaps, "snapshot_storage": e.SnapshotUsage(t)}
	}
	id := fmt.Sprintf("%d-%s", integer(m["vmid"]), str(a["name"]))
	var snap snapshotRecord
	found := false
	for _, s := range snaps {
		if s.Name == a["name"] {
			snap, found = s, true
			break
		}
	}
	var delta D
	configuration := pick(m, "cpu", "memory_mb", "disk_gb", "nics")
	if tool == "snapshot_create" {
		if found && !e.ownedBy(snap.OperationID) {
			fail("conflict", "Snapshot exists", D{"recovery": "revise_request"})
		}
		delta = D{}
		if !found {
			delta = D{"snapshots": 1, "snapshot_gb": m["disk_gb"]}
		}
		e.Quota(t, delta)
		if !found {
			e.Admission(e.P.nodeOf(m), 0, 0, num(m["disk_gb"]), nil, true)
			snap = snapshotRecord{ID: id, VMID: integer(m["vmid"]), Name: str(a["name"]), DiskGB: integer(m["disk_gb"]), Configuration: configuration}
		}
	} else if !found {
		fail("not_found", "Snapshot not found")
	} else if tool == "snapshot_delete" {
		delta = D{"snapshots": -1, "snapshot_gb": -float64(snap.DiskGB)}
	}
	effects := D{}
	if tool == "snapshot_rollback" {
		if !equal(snap.Configuration, configuration) {
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
				restore = D{"running": powerState(status) == "running", "boot_id": e.S.guestReport(m["vmid"]).BootID}
				e.Op["rollback_restore"] = restore
				e.P.Operations.Save(e.Op)
			}
		}
		if tool == "snapshot_create" {
			snap.State = "creating"
			e.Put("snapshots", id, n, snap)
		}
		action := map[string]string{"snapshot_create": "snapshot", "snapshot_delete": "delsnapshot", "snapshot_rollback": "rollback"}[tool]
		e.Call(D{"op": "action", "machine": m, "name": a["name"], "action": action})
		if tool == "snapshot_create" {
			snap.State = "ready"
			e.Put("snapshots", id, n, snap)
		} else if tool == "snapshot_delete" {
			e.S.Remove("snapshots", id)
			snap.State = "deleted"
		} else {
			state := "stopped"
			m["ssh_ready"] = false
			if boolean(restore["running"]) {
				e.Call(D{"op": "action", "machine": m, "action": "start"})
				m["state"] = bootState(m)
				state = "running"
			} else {
				m["state"] = "stopped"
			}
			m["power_state"] = state
			e.Put("machines", m["vmid"], n, m)
			effects = D{"power_state": state, "power_state_restored": true}
		}
		e.P.invalidateInventory()
		e.RefreshStorage()
	}
	var shown any = snap
	if dry && tool == "snapshot_create" {
		shown = D{"name": snap.Name, "machine": m["name"], "disk_gb": m["disk_gb"], "state": "planned"}
	}
	q := e.Quota(t)
	if dry {
		q = e.Quota(t, delta)
	}
	r := merge(D{"snapshot": shown, "snapshot_storage": e.SnapshotUsage(t), "dry_run": dry, "quota_after": q}, effects)
	if !dry && tool == "snapshot_rollback" {
		r["machine"] = e.PublicMachine(m, e.ports(n))
	}
	return r
}
