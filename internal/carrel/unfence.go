package carrel

import "fmt"

// UnfenceMachine clears a machine's plugin fence (#682). A fence stays while
// a plugin run of unknown fate may still write the guest's disk, and no
// plugin answer can prove the run ended. An admin clears it here once the
// node shows neither a guest lock nor an active task on the guest. It runs
// under the writer lock, so nothing starts on the machine in between.
func (e *Execution) UnfenceMachine(a D) D {
	t := find(e.S.Tenants(), func(t D) bool { return t["slug"] == a["tenant"] })
	if t == nil {
		fail("not_found", "Tenant not found")
	}
	m := e.Machine(t, a["machine"])
	if a["confirm"] != m["name"] {
		fail("invalid", "confirm must equal the machine name", D{"recovery": "revise_request"})
	}
	fence := str(m["plugin_fence"])
	if fence == "" {
		fail("conflict", "The machine is not fenced", D{"recovery": "revise_request"})
	}
	for _, op := range e.S.ActiveOperations() {
		if op["id"] == fence {
			fail("conflict", "The fenced operation is running again; wait for it to end", D{"recovery": "retry", "operation": fence})
		}
	}
	node := e.P.nodeOf(m).Name
	status := obj(e.Call(D{"op": "status", "machine": m}))
	tasks := []D{}
	for _, task := range dicts(e.Call(D{"op": "guest_tasks", "machine": m})) {
		tasks = append(tasks, pick(task, "upid", "type", "user", "starttime", "status"))
	}
	out := D{"machine": m["name"], "node": node, "operation": fence, "lock": status["lock"], "active_tasks": tasks}
	if len(tasks) > 0 {
		fail("conflict", "A Proxmox task on the machine is still running; wait for it to end and run this again", merge(out, D{"recovery": "retry"}))
	}
	if lock := str(status["lock"]); lock != "" {
		command := "qm unlock"
		if m["kind"] == "ct" {
			command = "pct unlock"
		}
		fail("conflict", fmt.Sprintf("The guest holds a %s lock with no task running; check the guest, run %s %d on %s, then run this again", lock, command, integer(m["vmid"]), node),
			merge(out, D{"recovery": "resolve_prerequisite"}))
	}
	if boolean(a["dry_run"]) {
		return merge(out, D{"dry_run": true, "fenced": true})
	}
	delete(m, "plugin_fence")
	e.Put("machines", m["vmid"], integer(t["n"]), m)
	return merge(out, D{"dry_run": false, "fenced": false})
}
