package carrel

// Power is the observed execution state. PVE reports a paused QEMU process as
// status=running, with the actual execution state in qmpstatus.
func powerState(status D) string {
	if contains([]string{"paused", "suspended", "prelaunch"}, status["qmpstatus"]) {
		return "paused"
	}
	return str(fallback(status, "power_state", fallback(status, "status", fallback(status, "state", "unknown"))))
}

func observePower(machine, status D) {
	state := powerState(status)
	old := machine["power_state"]
	machine["power_state"] = state
	machine["runtime"] = D{"power_state": state, "uptime_seconds": status["uptime"], "observed_at": stamp()}
	r := obj(machine["readiness"])
	if machine["kind"] == "vm" && state == "running" && r["reported_at"] != nil && status["uptime"] != nil && num(r["reported_at"]) < now()-num(status["uptime"])-5 {
		r["freshness"] = "previous_boot"
		unknownReport(r)
	}
	if state != "running" || old != "running" {
		machine["ssh_ready"] = false
		obj(machine["readiness"])["ssh_ready"] = false
		if state != "running" || !contains([]string{"initializing", "provisioning"}, machine["state"]) {
			machine["state"] = state
		}
	}
}

func (e *Execution) PowerMachine(m, a, t D) D {
	action := str(a["action"])
	if !contains([]string{"start", "shutdown", "stop", "reboot", "pause", "resume"}, action) {
		fail("invalid", "Unknown power action")
	}
	if (action == "pause" || action == "resume") && m["kind"] != "vm" {
		fail("invalid", "Pause and resume require a VM. CT checkpoint/hibernation is unsupported; shutdown is a different operation that loses running processes.")
	}
	if boolean(a["dry_run"]) {
		return D{"dry_run": true, "quota_after": e.Quota(t)}
	}
	// Persist the old boot before sending the mutation. An adapter receipt can be
	// replayed after a restart, but the new report must not become its own baseline.
	if e.Op != nil && e.Op["power_restore"] == nil {
		previous := ""
		if action == "start" || action == "reboot" {
			previous = str(obj(e.S.Get("guest_reports", str(m["vmid"])))["boot_id"])
		}
		e.Op["power_restore"] = D{"boot_id": previous}
		e.P.Operations.Save(e.Op)
	}
	result := obj(e.Call(D{"op": "action", "machine": m, "action": action}))
	state := powerState(result)
	want := "running"
	if action == "pause" {
		want = "paused"
	} else if action == "shutdown" || action == "stop" {
		want = "stopped"
	}
	if state != want {
		fail("conflict", "Power transition was not confirmed", D{"expected": want, "observed": state})
	}
	if e.Op != nil {
		restore := obj(e.Op["power_restore"])
		restore["reported_after"] = 0
		if boolean(result["boot_changed"]) {
			// A retry can follow a partially successful earlier reboot. Require a
			// report after this confirmed transition, not that intermediate boot.
			restore["reported_after"] = now()
		} else {
			restore["boot_id"] = ""
		}
		e.P.Operations.Save(e.Op)
	}
	m["state"], m["power_state"], m["ssh_ready"] = state, state, false
	if state == "running" {
		m["state"] = "initializing"
	}
	e.Put("machines", m["vmid"], integer(t["n"]), m)
	e.P.inventory.Invalidate()
	r := D{"action": action, "changed": boolean(result["changed"]), "resource_changes": boolean(result["changed"]), "machine": e.PublicMachine(m, e.S.Objects("ports", integer(t["n"]))), "quota_after": e.Quota(t)}
	if state == "paused" {
		r["pause"] = D{"mode": "memory", "survives_host_restart": false}
	}
	if state != "running" {
		r["quota_released"] = false
	}
	return r
}
