package carrel

// Machine context and power for plugin operations (#663). A plugin gets the
// facts of the machine it acts on. An operation that declares stopped runs
// on a stopped guest: carrel shuts a running one down before the start and,
// once the run is known to have ended, starts it again and waits until it
// is ready. A run whose fate is unknown leaves the guest stopped, so it is
// never started under a plugin that may still be writing its disk; a retry
// of the operation brings it back.
//
// The power record (plug["power"]) is written before the stop and kept until
// the guest is restored. While it exists, status is never read again: a
// second read would say "stopped" and the guest would never come back.

import (
	"fmt"
	"log/slog"
)

// pluginMachineFacts are what a plugin learns of the machine it acts on.
func pluginMachineFacts(m D) D {
	return D{"vmid": integer(m["vmid"]), "kind": m["kind"], "node": m["node"], "cpu": m["cpu"], "memory_mb": m["memory_mb"],
		"disk_gb": m["disk_gb"], "power_state": fallback(m, "power_state", m["state"]),
		"configuration": digest(string(encoded(pick(m, "cpu", "memory_mb", "disk_gb", "nics", "iso_volume"))))}
}

// stopBlocked are the machine states a stopping operation does not run in,
// as a freeze does not.
var stopBlocked = []string{"provisioning", "deleting", "migrating", "needs_owner_fix"}

// preparePluginStop records, under the writer and before anything changes,
// whether the guest runs, and refuses one that cannot be stopped.
func (e *Execution) preparePluginStop(op PluginOperation, m D) {
	plug := obj(e.Op["plugin"])
	if !op.Stopped || plug["power"] != nil {
		return
	}
	if state := str(m["state"]); contains(stopBlocked, state) || m["resize_from"] != nil {
		fail("conflict", fmt.Sprintf("The machine is %s; run this once that has finished", fallback(m, "state", "resizing")), D{"recovery": "resolve_prerequisite"})
	}
	status := obj(e.Call(D{"op": "status", "machine": m}))
	state := powerState(status)
	if state == "paused" {
		fail("conflict", "Resume or shut down the machine first: a paused guest cannot be stopped without losing its memory", D{"recovery": "resolve_prerequisite"})
	}
	if state != "running" && state != "stopped" {
		fail("conflict", "The machine's power state is "+state, D{"recovery": "retry_infrastructure"})
	}
	pw := D{"running": state == "running", "boot_id": e.S.guestReport(m["vmid"]).BootID}
	if state == "stopped" && boolean(plug["power_owed"]) {
		// An earlier run stopped it and could not start it again.
		pw["running"], pw["stopping"], pw["stopped"] = true, true, true
	}
	delete(plug, "power_owed")
	plug["power"] = pw
	if op.Rewinds && m["ca_sync"] != nil {
		// Saved before the disk goes back: if a later step fails, the
		// older principals file it may hold is shown as pending.
		e.caRestored(m, false)
		e.Put("machines", m["vmid"], integer(e.Op["tenant_n"]), m)
	}
	e.P.Operations.Save(e.Op)
}

// resetPower drops a power record the guest was brought back by, so the
// run reads its power again; a new run drops any. A guest the last run
// stopped and could not start again is still owed its start.
func (e *Execution) resetPower(newRun bool) {
	plug := obj(e.Op["plugin"])
	prev := obj(plug["power"])
	if plug["power"] == nil || !newRun && !boolean(prev["restored"]) {
		return
	}
	delete(plug, "power")
	if !boolean(prev["restored"]) && boolean(prev["running"]) && boolean(prev["stopping"]) {
		plug["power_owed"] = true
	}
}

// stopForPlugin shuts the guest down gracefully, outside the writer.
func (e *Execution) stopForPlugin() {
	plug := obj(e.Op["plugin"])
	pw := obj(plug["power"])
	if plug["power"] == nil || !boolean(pw["running"]) || boolean(pw["stopped"]) {
		return
	}
	// Marked before the shutdown is sent: from here the guest may be down,
	// so a failure restores it.
	e.P.writer.Lock()
	pw["stopping"] = true
	e.P.Operations.Save(e.Op)
	e.P.writer.Unlock()
	m := e.S.Get("machines", str(obj(e.Op["machine_target"])["vmid"]))
	if m == nil {
		fail("not_found", "The operation's original machine no longer exists")
	}
	result := obj(e.Call(D{"op": "action", "machine": m, "action": "shutdown"}))
	if state := powerState(result); state != "stopped" {
		fail("conflict", "The machine did not shut down", D{"expected": "stopped", "observed": state, "recovery": "retry"})
	}
	e.P.writer.Lock()
	defer e.P.writer.Unlock()
	pw["stopped"] = true
	if m = e.S.Get("machines", str(m["vmid"])); m != nil {
		m["state"], m["power_state"], m["ssh_ready"] = "stopped", "stopped", false
		e.Put("machines", m["vmid"], integer(e.Op["tenant_n"]), m)
	}
	e.P.invalidateInventory()
	e.P.Operations.Save(e.Op)
}

// restorePluginPower starts a guest the operation stopped and waits until it
// is ready, outside the writer. It may run again: a restored guest is left.
func (e *Execution) restorePluginPower() {
	plug := obj(e.Op["plugin"])
	pw := obj(plug["power"])
	if plug["power"] == nil || boolean(pw["restored"]) {
		return
	}
	finish := func() {
		e.P.writer.Lock()
		pw["restored"] = true
		if m := e.S.Get("machines", str(obj(e.Op["machine_target"])["vmid"])); m != nil && m["plugin_fence"] == e.Op["id"] {
			delete(m, "plugin_fence")
			e.Put("machines", m["vmid"], integer(e.Op["tenant_n"]), m)
		}
		e.P.Operations.Save(e.Op)
		e.P.writer.Unlock()
	}
	if !boolean(pw["running"]) || !boolean(pw["stopping"]) {
		finish()
		return
	}
	m := e.S.Get("machines", str(obj(e.Op["machine_target"])["vmid"]))
	if m == nil {
		fail("not_found", "The operation's original machine no longer exists")
	}
	request := D{"op": "action", "machine": m, "action": "start"}
	if files := e.cloudInitFiles(m); files != nil {
		request["cloud_init"] = files
	}
	result := obj(e.Call(request))
	if state := powerState(result); state != "running" {
		fail("conflict", "The machine was not started again", D{"expected": "running", "observed": state, "recovery": "retry"})
	}
	e.P.writer.Lock()
	m = e.S.Get("machines", str(m["vmid"]))
	if m != nil {
		m["state"], m["power_state"], m["ssh_ready"] = bootState(m), "running", false
		if boolean(plug["rewinds"]) || m["ca_sync"] == "push" && !equal(m["ca_applied"], caPrincipals(m)) {
			e.caRestored(m, true)
		}
		e.Put("machines", m["vmid"], integer(e.Op["tenant_n"]), m)
	}
	// A report from before the stop cannot count, even with no boot id.
	pw["reported_after"] = now()
	e.P.invalidateInventory()
	e.P.Operations.Save(e.Op)
	e.P.writer.Unlock()
	if m != nil && contains([]string{"initializing", "provisioning", "needs_owner_fix"}, m["state"]) {
		e.WaitReady(m, str(pw["boot_id"]))
	}
	finish()
}

// restoreAfterFailure brings the guest back when a run failed, if the run is
// known to have ended or never began; any other failure leaves it stopped.
func (e *Execution) restoreAfterFailure() {
	plug := obj(e.Op["plugin"])
	if plug["power"] == nil || e.Ctx.Err() != nil {
		return
	}
	if !boolean(plug["ended"]) && boolean(plug["start_sent"]) {
		// The run may go on: the machine is fenced until a retry of this
		// operation learns how it ended.
		e.P.writer.Lock()
		defer e.P.writer.Unlock()
		obj(plug["power"])["left_stopped"] = true
		if m := e.S.Get("machines", str(obj(e.Op["machine_target"])["vmid"])); m != nil {
			m["plugin_fence"] = e.Op["id"]
			e.Put("machines", m["vmid"], integer(e.Op["tenant_n"]), m)
		}
		e.P.Operations.Save(e.Op)
		return
	}
	if err := attempt(e.restorePluginPower); err != nil {
		slog.Warn("plugin_power_restore_failed", "operation", e.Op["id"], "error", describe(err))
	}
}

// pluginPowerResult is what a stopping operation reports of the guest.
func (e *Execution) pluginPowerResult(r D) {
	plug := obj(e.Op["plugin"])
	if plug["power"] == nil {
		return
	}
	m := e.S.Get("machines", str(obj(e.Op["machine_target"])["vmid"]))
	state := "stopped"
	if boolean(obj(plug["power"])["running"]) {
		state = "running"
	}
	r["power_state"], r["power_state_restored"] = state, true
	if m != nil {
		r["machine"] = D{"name": m["name"]}
	}
}
