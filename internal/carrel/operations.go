package carrel

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"sort"
	"sync"
	"time"
)

var terminal = []string{"succeeded", "failed", "rolled_back", "cleanup_failed"}

func publicOperation(o D) D {
	r := pick(o, "id", "tool", "state", "phase", "created_at", "updated_at", "attempts", "result", "error", "reserved", "resource_changes", "cleanup", "current_resource", "ready_at")
	if contains(terminal, o["state"]) {
		r["poll_after_seconds"] = nil
	} else {
		r["poll_after_seconds"] = max(5, min(60, int(num(o["ready_at"])-now())))
	}
	r["next_action"] = "operation_get"
	if o["state"] == "succeeded" {
		r["next_action"] = "use_result"
	} else if contains(terminal, o["state"]) {
		r["next_action"], r["next_action_detail"] = recoveryAction(o)
		if len(arr(o["recovery_machines"])) > 0 {
			r["machines"] = o["recovery_machines"]
		}
	}
	return r
}

type jobTask struct{ done chan struct{} }
type Operations struct {
	p     *Platform
	mu    sync.Mutex
	tasks map[string]*jobTask
	queue chan string
}

func NewOperations(p *Platform) *Operations {
	return &Operations{p: p, tasks: map[string]*jobTask{}, queue: make(chan string, 512)}
}
func (o *Operations) Save(op D) {
	op["updated_at"] = now()
	o.p.Store.Put("operations", op["id"], integer(op["tenant_n"]), op)
}
func (o *Operations) Find(t D, id string) D {
	op := o.p.Store.Get("operations", id)
	if op == nil || integer(op["tenant_n"]) != integer(t["n"]) {
		fail("not_found", "Operation not found in this tenant")
	}
	return op
}
func (o *Operations) CheckQueue(t D, tool string) {
	pending := o.p.Store.ActiveOperations()
	mine := filter(pending, func(v D) bool { return integer(v["tenant_n"]) == integer(t["n"]) })
	if tool != "tenant_suspend" && (len(pending) >= intAt(o.p.Config, "max_pending_operations", 256) || len(mine) >= intAt(o.p.Config, "max_tenant_pending_operations", 16)) {
		fail("conflict", "Operation queue is full; wait for an existing operation", D{"retryable": true})
	}
}
func (o *Operations) Submit(tool string, a, w, t D) D {
	args := without(a, "dry_run", "idempotency_key", "wait_seconds", "detail")
	fingerprint := digest(string(encoded([]any{tool, args})))
	key := str(a["idempotency_key"])
	if old := o.p.Store.OperationByKey(integer(t["n"]), key); key != "" && old != nil {
		if old["fingerprint"] != fingerprint {
			fail("conflict", "Idempotency key was already used for different arguments")
		}
		return publicOperation(old)
	}
	if tool == "tenant_suspend" {
		if old := find(o.p.Store.ActiveOperations(integer(t["n"])), func(v D) bool { return v["tool"] == tool }); old != nil {
			return publicOperation(old)
		}
	}
	o.CheckQueue(t, tool)
	var k any
	if key != "" {
		k = key
	}
	op := D{"id": randomID(), "tenant_n": t["n"], "tool": tool, "args": args, "who": clone(w), "fingerprint": fingerprint, "idempotency_key": k, "state": "queued", "phase": "awaiting_capacity_check", "reserved": false, "resource_changes": false, "created_at": now(), "queued_at": now(), "attempts": 0, "generation": 0}
	o.Save(op)
	o.start(str(op["id"]))
	return publicOperation(op)
}
func (o *Operations) start(id string) {
	o.mu.Lock()
	if o.tasks[id] != nil {
		o.mu.Unlock()
		return
	}
	o.tasks[id] = &jobTask{make(chan struct{})}
	o.mu.Unlock()
	select {
	case o.queue <- id:
	case <-o.p.ctx.Done():
	}
}
func (o *Operations) Recover() {
	ops := o.p.Store.ActiveOperations()
	sort.Slice(ops, func(i, j int) bool {
		return num(fallback(ops[i], "queued_at", ops[i]["created_at"])) < num(fallback(ops[j], "queued_at", ops[j]["created_at"]))
	})
	for _, op := range ops {
		o.start(str(op["id"]))
	}
}
func (o *Operations) Loop() {
	defer o.p.wg.Done()
	for {
		select {
		case <-o.p.ctx.Done():
			return
		case id := <-o.queue:
			o.apply(id)
		}
	}
}
func (o *Operations) finish(id string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if task := o.tasks[id]; task != nil {
		close(task.done)
		delete(o.tasks, id)
	}
}
func (o *Operations) later(id string, at float64) {
	o.p.wg.Add(1)
	go func() {
		defer o.p.wg.Done()
		if sleep(o.p.ctx, time.Duration(max(0, at-now())*float64(time.Second))) {
			select {
			case o.queue <- id:
			case <-o.p.ctx.Done():
			}
		}
	}()
}
func (o *Operations) Wait(ctx context.Context, t D, id string, seconds int) D {
	o.Find(t, id)
	o.mu.Lock()
	task := o.tasks[id]
	o.mu.Unlock()
	if task != nil && seconds > 0 {
		timer := time.NewTimer(time.Duration(seconds) * time.Second)
		defer timer.Stop()
		select {
		case <-ctx.Done():
		case <-task.done:
		case <-timer.C:
		}
	}
	return publicOperation(o.Find(t, id))
}
func (o *Operations) Retry(t D, id string, w D) D {
	o.p.writer.Lock()
	defer o.p.writer.Unlock()
	op := o.Find(t, id)
	if contains(terminal, op["state"]) && op["state"] != "succeeded" {
		if next, _ := recoveryAction(op); next == "revise_request" {
			return D{"operation": publicOperation(op)}
		}
		o.CheckQueue(t, str(op["tool"]))
		if op["state"] == "cleanup_failed" {
			op["resume_cleanup"] = true
		}
		if op["state"] == "rolled_back" {
			op["generation"] = integer(op["generation"]) + 1
			delete(op, "deployment")
		}
		delete(op, "prepared_result")
		op = merge(op, D{"state": "queued", "phase": "retry_queued", "who": w, "queued_at": now()})
		for _, k := range []string{"error", "result", "ready_at", "readiness_deadlines", "recovery_machines"} {
			delete(op, k)
		}
		o.Save(op)
		o.start(id)
	}
	return D{"operation": publicOperation(op)}
}

// The FIFO writer applies durable changes. Guest readiness runs outside this writer.
// A restarted job resumes from its persisted result, without repeating PVE actions.
func (o *Operations) apply(id string) {
	o.p.writer.Lock()
	op := o.p.Store.Get("operations", id)
	if op == nil || contains(terminal, op["state"]) {
		o.p.writer.Unlock()
		o.finish(id)
		return
	}
	if op["state"] == "waiting" && num(op["ready_at"]) > now() {
		o.p.writer.Unlock()
		o.later(id, num(op["ready_at"]))
		return
	}
	e := o.p.execution(o.p.ctx)
	e.Op = op
	var result D
	complete := false
	err := attempt(func() {
		if op["tool"] != "tenant_suspend" && find(e.S.ActiveOperations(), func(v D) bool { return v["tool"] == "tenant_suspend" }) != nil {
			panic(Waiting{"waiting_for_priority_operation", now() + 0.05})
		}
		t := e.S.TenantN(integer(op["tenant_n"]))
		cleanup := op["state"] == "cleaning_up" || boolean(op["resume_cleanup"])
		delete(op, "resume_cleanup")
		op["state"] = "running"
		op["phase"] = "applying"
		op["attempts"] = integer(op["attempts"]) + 1
		o.Save(op)
		if t["status"] != "active" && op["tool"] != "tenant_suspend" && !cleanup {
			fail("forbidden", "Tenant is suspended")
		}
		if cleanup {
			e.CleanupOutcome()
			complete = true
			return
		}
		if e.BindMachine(t) || e.BindObject(t) {
			e.Reconcile()
			op["result"] = D{"ok": true, "already_deleted": true}
			op["state"] = "succeeded"
			op["phase"] = "complete"
			complete = true
			return
		}
		e.CheckBusy(t)
		if saved, ok := op["prepared_result"]; ok {
			result = obj(saved)
		} else {
			result, _ = e.Dispatch(str(op["tool"]), obj(op["args"]), obj(op["who"]))
			op["prepared_result"] = result
		}
		op["phase"] = "waiting_for_guest"
		o.Save(op)
	})
	if err != nil {
		o.handleError(e, err)
		complete = true
	}
	if complete {
		o.saveOutcome(e)
		o.p.writer.Unlock()
		if op["state"] == "waiting" {
			o.later(id, num(op["ready_at"]))
		} else {
			o.finish(id)
		}
		return
	}
	o.p.writer.Unlock()
	o.p.wg.Add(1)
	go func() {
		defer o.p.wg.Done()
		problem := attempt(func() {
			t := e.S.TenantN(integer(op["tenant_n"]))
			machines := filter(e.S.Objects("machines", integer(t["n"])), func(m D) bool { return m["operation_id"] == id })
			// Existing machines with attached NICs and snapshot restores also need readiness.
			ids := []any{}
			if target := obj(op["machine_target"])["vmid"]; target != nil {
				ids = append(ids, target)
			}
			for _, nic := range dicts(obj(op["deployment"])["nics"]) {
				ids = append(ids, nic["vmid"])
			}
			for _, vmid := range ids {
				if m := e.S.Get("machines", str(vmid)); m != nil && find(machines, func(v D) bool { return integer(v["vmid"]) == integer(vmid) }) == nil {
					machines = append(machines, m)
				}
			}
			if pub := obj(result["machine"]); pub["name"] != nil {
				m := e.Machine(t, pub["name"])
				machines = filter(machines, func(v D) bool { return integer(v["vmid"]) != integer(m["vmid"]) })
				machines = append(machines, m)
			}
			for _, m := range machines {
				if contains([]string{"initializing", "provisioning", "needs_owner_fix"}, m["state"]) {
					previous := ""
					if op["tool"] == "snapshot_rollback" {
						previous = str(obj(op["rollback_restore"])["boot_id"])
					} else if op["tool"] == "machine_power" {
						previous = str(obj(op["power_restore"])["boot_id"])
					}
					e.WaitReady(m, previous)
				}
			}
			e.PreparePublication()
		})
		o.p.writer.Lock()
		defer o.p.writer.Unlock()
		if o.p.ctx.Err() != nil {
			return
		}
		if problem == nil {
			problem = attempt(func() {
				t := e.S.TenantN(integer(op["tenant_n"]))
				if op["tool"] == "domain_add" {
					result = merge(result, e.DomainAction("domain_add", obj(op["args"]), t))
				}
				if op["tool"] == "deployment_apply" {
					e.PublishDeployment(t, obj(op["args"]), obj(op["who"]))
					result = merge(result, e.AccessResult(t, obj(op["args"])))
					machines := []D{}
					for _, vmid := range arr(obj(op["deployment"])["machines"]) {
						machines = append(machines, e.PublicMachine(e.Machine(t, vmid), e.ports(integer(t["n"]))))
					}
					result["machines"] = machines
					updated := []D{}
					bindings := slices.Collect(maps.Keys(obj(obj(op["deployment"])["bindings"])))
					sort.Slice(bindings, func(i, j int) bool { return integer(bindings[i]) < integer(bindings[j]) })
					for _, id := range bindings {
						if find(machines, func(m D) bool { return integer(m["vmid"]) == integer(id) }) == nil {
							updated = append(updated, e.PublicMachine(e.Machine(t, id), e.ports(integer(t["n"]))))
						}
					}
					result["updated_machines"] = updated
				}
				if pub := obj(result["machine"]); pub["name"] != nil {
					result["machine"] = e.PublicMachine(e.Machine(t, pub["name"]), e.ports(integer(t["n"])))
				}
				op["result"] = merge(D{"ok": true}, result)
				op["state"] = "succeeded"
				op["phase"] = "complete"
				op["resource_changes"] = fallback(result, "resource_changes", true)
				delete(op, "ready_at")
				delete(op, "prepared_result")
			})
		}
		if problem != nil {
			o.handleError(e, problem)
		}
		o.saveOutcome(e)
		if op["state"] == "waiting" {
			o.later(id, num(op["ready_at"]))
		} else {
			o.finish(id)
		}
	}()
}
func (o *Operations) handleError(e *Execution, err any) {
	if o.p.ctx.Err() != nil {
		return
	}
	op := e.Op
	if w, ok := err.(Waiting); ok {
		op["state"] = "waiting"
		op["phase"] = w.Phase
		op["ready_at"] = w.ReadyAt
		return
	}
	op["state"] = "failed"
	op["phase"] = "failed"
	op["error"] = failureResult(err)["error"]
	slog.Error("operation_failed", "operation", op["id"], "error_type", fmt.Sprintf("%T", err))
	if op["tool"] == "deployment_apply" && textAt(obj(op["args"]), "on_failure", "rollback") == "rollback" {
		op["state"] = "cleaning_up"
		op["phase"] = "removing_new_resources"
		o.Save(op)
		e.CleanupOutcome()
	}
}
func (o *Operations) saveOutcome(e *Execution) {
	if o.p.ctx.Err() != nil {
		return
	}
	op := e.Op
	reserved := false
	for _, kind := range []string{"machines", "networks", "snapshots", "ports", "domains", "peers"} {
		for _, v := range e.S.Objects(kind, integer(op["tenant_n"])) {
			reserved = reserved || v["operation_id"] == op["id"]
		}
	}
	op["reserved"] = reserved
	if contains(terminal, op["state"]) && op["state"] != "succeeded" {
		machines := []D{}
		for _, m := range e.S.Objects("machines", integer(op["tenant_n"])) {
			bound := obj(op["machine_target"])
			if m["operation_id"] == op["id"] || equal(machineIdentity(m), obj(obj(op["deployment"])["bindings"])[str(m["vmid"])]) || (integer(m["vmid"]) == integer(bound["vmid"]) && equal(machineIdentity(m), bound["identity"])) {
				machines = append(machines, machineSummary(e.PublicMachine(m, e.ports(integer(op["tenant_n"])))))
			}
		}
		op["recovery_machines"] = machines
	}
	o.Save(op)
	event := "operation_waiting"
	if contains(terminal, op["state"]) {
		event = "operation_finished"
	}
	e.S.Log(str(obj(op["who"])["sub"]), op["tenant_n"], event, D{"operation": op["id"], "tool": op["tool"]}, str(op["state"]))
}
func (e *Execution) BindMachine(t D) bool {
	op, a := e.Op, obj(e.Op["args"])
	if a["machine"] == nil {
		return false
	}
	bound := obj(op["machine_target"])
	var m D
	if len(bound) > 0 {
		m = find(e.S.Objects("machines", integer(t["n"])), func(m D) bool { return integer(m["vmid"]) == integer(bound["vmid"]) })
		if m == nil {
			if op["tool"] == "machine_delete" {
				return true
			}
			fail("not_found", "The operation's original machine no longer exists")
		}
		if !equal(machineIdentity(m), bound["identity"]) {
			fail("conflict", "VMID now belongs to a different allocation; retry refused", D{"recovery": "revise_request"})
		}
		a["machine"] = str(bound["vmid"])
	} else {
		m = e.Machine(t, a["machine"])
		op["machine_target"] = D{"vmid": m["vmid"], "identity": machineIdentity(m)}
		e.P.Operations.Save(op)
	}
	if op["tool"] == "machine_nic_detach" {
		nic := find(dicts(m["nics"]), func(n D) bool { return integer(n["index"]) == integer(a["nic"]) })
		var identity any
		if nic != nil {
			identity = []any{nic["network"], nic["mac"], nic["operation_id"]}
		}
		if target, ok := op["nic_target"]; ok {
			if nic == nil {
				return true
			}
			if !equal(identity, target) {
				fail("conflict", "NIC index belongs to a different attachment; retry refused", D{"recovery": "revise_request"})
			}
		} else if nic != nil {
			op["nic_target"] = identity
			e.P.Operations.Save(op)
		}
	}
	return false
}
func (e *Execution) BindObject(t D) bool {
	selectors := map[string][3]string{"machine_nic_attach": {"networks", "network", "name"}, "network_delete": {"networks", "network", "name"}, "port_close": {"ports", "id", "id"}, "domain_remove": {"domains", "name", "name"}, "peer_revoke": {"peers", "id", "id"}, "snapshot_delete": {"snapshots", "name", "name"}, "snapshot_rollback": {"snapshots", "name", "name"}}
	op, a := e.Op, obj(e.Op["args"])
	spec, ok := selectors[str(op["tool"])]
	if !ok {
		return false
	}
	kind, arg, field := spec[0], spec[1], spec[2]
	objects := e.S.Objects(kind, integer(t["n"]))
	bound := obj(op["object_target"])
	if len(bound) > 0 {
		o := find(objects, func(o D) bool { return o["id"] == bound["id"] })
		if o == nil {
			if op["tool"] != "snapshot_rollback" && op["tool"] != "machine_nic_attach" {
				return true
			}
			fail("not_found", "The operation's original resource no longer exists")
		}
		if !equal(o["operation_id"], bound["operation_id"]) {
			fail("conflict", "Resource identifier belongs to a different allocation; retry refused", D{"recovery": "revise_request"})
		}
	} else {
		o := find(objects, func(o D) bool {
			return (a[arg] == o["id"] || a[arg] == o[field]) && (kind != "snapshots" || integer(o["vmid"]) == integer(obj(op["machine_target"])["vmid"]))
		})
		if o != nil {
			op["object_target"] = D{"id": o["id"], "operation_id": o["operation_id"]}
			e.P.Operations.Save(op)
		}
	}
	return false
}

// Keep edits of a machine ordered while its boot is being verified. Other allocations can proceed.
func (e *Execution) CheckBusy(t D) {
	if e.Op["tool"] == "tenant_suspend" {
		return
	}
	targets := map[int]bool{}
	if e.Op["tool"] == "domain_remove" {
		if d := e.S.Get("domains", str(obj(e.Op["object_target"])["id"])); d != nil {
			targets[integer(d["vmid"])] = true
		}
	}
	if id := obj(e.Op["machine_target"])["vmid"]; id != nil {
		targets[integer(id)] = true
	}
	if e.Op["tool"] == "deployment_apply" {
		args := obj(e.Op["args"])
		refs := []any{}
		for _, a := range append(dicts(args["attachments"]), dicts(args["access"])...) {
			refs = append(refs, a["machine"])
		}
		for _, p := range dicts(args["publications"]) {
			refs = append(refs, p["machine"])
		}
		for _, c := range dicts(args["connections"]) {
			refs = append(refs, c["from"], c["to"])
		}
		for _, m := range e.S.Objects("machines", integer(t["n"])) {
			for _, ref := range refs {
				if str(ref) == str(m["name"]) || str(ref) == str(m["vmid"]) {
					targets[integer(m["vmid"])] = true
				}
			}
		}
	}
	for _, other := range e.S.ActiveOperations() {
		if other["id"] == e.Op["id"] || !contains([]string{"waiting_for_guest", "preparing_publication", "publishing"}, other["phase"]) {
			continue
		}
		ids := arr(obj(other["deployment"])["machines"])
		if id := obj(other["machine_target"])["vmid"]; id != nil {
			ids = append(ids, id)
		}
		for vmid := range obj(obj(other["deployment"])["bindings"]) {
			ids = append(ids, vmid)
		}
		for _, m := range e.S.Objects("machines", integer(t["n"])) {
			if m["operation_id"] == other["id"] {
				ids = append(ids, m["vmid"])
			}
		}
		for _, id := range ids {
			if targets[integer(id)] {
				panic(Waiting{"waiting_for_machine_operation", now() + 1})
			}
		}
	}
}
