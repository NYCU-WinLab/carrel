package carrel

import (
	"sort"
	"strings"
	"sync"
	"time"
)

// PlatformPower shuts down or starts every tenant machine at once, for a
// planned outage or maintenance. The nodes and the infra CTs stay up, so the
// control plane and its gateway keep answering and the same tool starts the
// machines again.
//
// The double check: a dry run lists the machines and issues a confirm code
// for that admin, that action and that exact list. The real call spends the
// code once, within platformConfirmTTL, and only while the list is the same.
//
// A shutdown adds its machines to the restore list in the site table before
// any of them stops; a start removes each machine once it runs again. An
// owner's own power action or a replaced machine takes it off the list.
func (e *Execution) PlatformPower(a, w D) D {
	action := str(a["action"])
	dry := boolean(a["dry_run"])
	if action == "check" {
		return D{"action": "check", "dry_run": dry, "nodes": e.platformCheck(!dry)}
	}
	if action != "shutdown" && action != "start" {
		fail("invalid", "Unknown platform power action")
	}
	targets, unknown := e.platformTargets(action)
	listed := []D{}
	for _, t := range targets {
		listed = append(listed, t.public())
	}
	if dry {
		r := D{"dry_run": true, "action": action, "count": len(targets), "machines": listed, "unknown": unknown}
		if action == "shutdown" && len(unknown) > 0 {
			// A machine whose node does not answer may still be running.
			r["requirements"] = []any{"every machine's power must be readable: fix the node, then run the dry run again"}
			return r
		}
		r["confirm"] = e.P.platformIssue(w, action, platformDigest(action, targets))
		r["confirm_expires_in_seconds"] = int(platformConfirmTTL.Seconds())
		return r
	}
	e.P.platformSpend(str(a["confirm"]), w, action, platformDigest(action, targets))
	if action == "shutdown" && len(unknown) > 0 {
		fail("conflict", "Some machines' power could not be read", D{"unknown": unknown})
	}
	plan := []any{}
	for _, t := range targets {
		r := t.record()
		if action == "start" {
			// Saved before the start is sent, so the old boot's report cannot
			// pass for the new one.
			r["boot_id"] = e.S.guestReport(t.m["vmid"]).BootID
		}
		plan = append(plan, r)
	}
	if action == "shutdown" {
		// Saved before any machine stops: a restart or a second shutdown
		// keeps what is still to be restored.
		e.platformRemember(plan, w)
	}
	e.Op["platform"] = D{"action": action, "targets": plan, "done": []any{}, "failed": []any{}, "skipped": []any{}}
	return D{"action": action, "planned": len(plan), "machines": listed}
}

const platformConfirmTTL = 10 * time.Minute

type platformTarget struct {
	m     D
	n     int
	slug  string
	state string
}

func (t platformTarget) public() D {
	return D{"tenant": t.slug, "machine": t.m["name"], "vmid": t.m["vmid"], "power_state": t.state}
}

func (t platformTarget) record() D {
	return D{"vmid": t.m["vmid"], "tenant_n": t.n, "tenant": t.slug, "machine": t.m["name"], "identity": machineIdentity(t.m)}
}

// platformTargets reads each machine's power from its node: a shutdown takes
// the running and paused ones, a start the stopped ones on the restore list.
// Suspended tenants are left alone. Machines whose power cannot be read are
// returned apart.
func (e *Execution) platformTargets(action string) ([]platformTarget, []D) {
	slugs := map[int]string{}
	for _, t := range e.S.Tenants() {
		if t["status"] == "active" {
			slugs[integer(t["n"])] = str(t["slug"])
		}
	}
	restore := map[string]bool{}
	for _, r := range dicts(obj(e.S.SiteGet("platform", "power"))["restore"]) {
		restore[platformKey(r)] = true
	}
	candidates := []platformTarget{}
	for _, n := range sortedKeys(slugs) {
		for _, m := range e.S.Objects("machines", n) {
			if action == "start" && !restore[platformKey(D{"vmid": m["vmid"], "identity": machineIdentity(m)})] {
				continue
			}
			candidates = append(candidates, platformTarget{m: m, n: n, slug: slugs[n]})
		}
	}
	var wg sync.WaitGroup
	for i := range candidates {
		wg.Add(1)
		go func() {
			defer wg.Done()
			candidates[i].state = "unknown"
			_ = attempt(func() { candidates[i].state = powerState(obj(e.Call(D{"op": "status", "machine": candidates[i].m}))) })
		}()
	}
	wg.Wait()
	want := map[string]bool{"running": action == "shutdown", "paused": action == "shutdown", "stopped": action == "start"}
	out, unknown := []platformTarget{}, []D{}
	for _, t := range candidates {
		if t.state == "unknown" {
			unknown = append(unknown, t.public())
		} else if want[t.state] {
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool { return integer(out[i].m["vmid"]) < integer(out[j].m["vmid"]) })
	return out, unknown
}

func sortedKeys(m map[int]string) []int {
	keys := []int{}
	for k := range m {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	return keys
}

func platformDigest(action string, targets []platformTarget) string {
	ids := []string{}
	for _, t := range targets {
		ids = append(ids, str(t.m["vmid"])+":"+t.state+":"+string(encoded(machineIdentity(t.m))))
	}
	return digest(action + "|" + strings.Join(ids, ","))
}

// platformIssue keeps a confirm code in memory: a control plane restart
// forgets it, and the dry run is simply made again.
func (p *Platform) platformIssue(w D, action, plan string) string {
	p.platformMu.Lock()
	defer p.platformMu.Unlock()
	if p.platformCodes == nil {
		p.platformCodes = map[string]D{}
	}
	for code, c := range p.platformCodes {
		if num(c["expires"]) < now() {
			delete(p.platformCodes, code)
		}
	}
	code := action + "-" + randomID()[:12]
	p.platformCodes[code] = D{"sub": w["sub"], "action": action, "plan": plan, "expires": now() + platformConfirmTTL.Seconds()}
	return code
}

func (p *Platform) platformSpend(code string, w D, action, plan string) {
	p.platformMu.Lock()
	defer p.platformMu.Unlock()
	c := p.platformCodes[code]
	delete(p.platformCodes, code)
	if c == nil || c["sub"] != w["sub"] || c["action"] != action || num(c["expires"]) < now() {
		fail("invalid", "confirm must be a code from your own dry run of this action in the last 10 minutes, used once", D{"recovery": "revise_request"})
	}
	if c["plan"] != plan {
		fail("conflict", "The machine list changed since the dry run: run it again", D{"recovery": "revise_request"})
	}
}

func platformKey(r D) string { return str(r["vmid"]) + "|" + string(encoded(r["identity"])) }

func (e *Execution) platformRemember(plan []any, w D) {
	power := obj(e.S.SiteGet("platform", "power"))
	restore := dicts(power["restore"])
	seen := map[string]bool{}
	for _, r := range restore {
		seen[platformKey(r)] = true
	}
	for _, r := range plan {
		if !seen[platformKey(obj(r))] {
			restore = append(restore, obj(r))
		}
	}
	e.S.SitePut("platform", "power", D{"state": "off", "restore": restore, "at": now(), "by": w["sub"], "operation": e.Op["id"]})
}

// platformForget takes a machine off the restore list: its owner acted on it
// after the shutdown, it is gone, or a start brought it back. The caller
// holds the writer.
func (e *Execution) platformForget(vmid any) {
	power := e.S.SiteGet("platform", "power")
	if power == nil {
		return
	}
	restore := []D{}
	for _, r := range dicts(power["restore"]) {
		if str(r["vmid"]) != str(vmid) {
			restore = append(restore, r)
		}
	}
	if len(restore) == len(dicts(power["restore"])) {
		return
	}
	power["restore"] = restore
	if len(restore) == 0 {
		power["state"] = "on"
	}
	e.S.SitePut("platform", "power", power)
}

func (e *Execution) platformListed(r D) bool {
	for _, x := range dicts(obj(e.S.SiteGet("platform", "power"))["restore"]) {
		if platformKey(x) == platformKey(r) {
			return true
		}
	}
	return false
}

// PerformPlatformPower sends the planned actions without the writer lock:
// a node takes one action at a time, nodes run side by side, and each answer
// is recorded at once under the writer. A job that restarts runs the rest; a
// machine already in the wanted state is a no-op on its node.
func (e *Execution) PerformPlatformPower() {
	if e.Op["tool"] != "platform_power" || e.Op["platform"] == nil {
		return
	}
	plan := obj(e.Op["platform"])
	action := str(plan["action"])
	want := map[string]string{"shutdown": "stopped", "start": "running"}[action]
	finished := map[string]bool{}
	for _, list := range []string{"done", "failed", "skipped"} {
		for _, r := range dicts(plan[list]) {
			finished[platformKey(r)] = true
		}
	}
	byNode := map[string][]D{}
	for _, r := range dicts(plan["targets"]) {
		if finished[platformKey(r)] {
			continue
		}
		node := ""
		if m := e.S.Get("machines", str(r["vmid"])); m != nil {
			node = e.P.nodeOf(m).Target
		}
		byNode[node] = append(byNode[node], r)
	}
	// The workers send with their own copy of the job's identity: e.Op
	// changes under the writer while the others still send.
	call := &Execution{P: e.P, S: e.S, Ctx: e.Ctx, Op: D{"id": e.Op["id"], "generation": e.Op["generation"]}}
	record := func(list string, r D, extra D) {
		e.P.writer.Lock()
		defer e.P.writer.Unlock()
		plan[list] = append(arr(plan[list]), merge(r, extra))
		e.P.Operations.Save(e.Op)
	}
	var wg sync.WaitGroup
	for _, list := range byNode {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, r := range list {
				m := e.S.Get("machines", str(r["vmid"]))
				t := e.S.TenantN(integer(r["tenant_n"]))
				switch {
				case m == nil || string(encoded(machineIdentity(m))) != string(encoded(r["identity"])):
					record("skipped", r, D{"reason": "the machine was deleted or replaced"})
					continue
				case t == nil || t["status"] != "active":
					record("skipped", r, D{"reason": "the tenant is suspended"})
					continue
				case action == "start" && !e.platformListed(r):
					record("skipped", r, D{"reason": "its owner acted on it after the shutdown"})
					continue
				}
				request := D{"op": "action", "machine": m, "action": action}
				if action == "start" {
					if files := e.cloudInitFiles(m); files != nil {
						request["cloud_init"] = files
					}
				}
				var state string
				err := attempt(func() { state = powerState(obj(call.Call(request))) })
				if err != nil || state != want {
					extra := D{"observed": state}
					if err != nil {
						extra["error"] = describe(err)
					}
					record("failed", r, extra)
					continue
				}
				func() {
					e.P.writer.Lock()
					defer e.P.writer.Unlock()
					if current := e.S.Get("machines", str(r["vmid"])); current != nil {
						// The node agent sets onboot the same way: only running keeps it.
						current["onboot"] = want == "running"
						current["state"], current["power_state"], current["ssh_ready"] = want, want, false
						if want == "running" {
							current["state"] = bootState(current)
						}
						e.Put("machines", current["vmid"], integer(r["tenant_n"]), current)
						e.P.notifyReport(integer(current["vmid"]))
						e.P.invalidateInventory()
					}
					if action == "start" {
						e.platformForget(r["vmid"])
					}
					plan["done"] = append(arr(plan["done"]), merge(r, D{"power_state": want}))
					e.P.Operations.Save(e.Op)
				}()
			}
		}()
	}
	wg.Wait()
	if action == "start" {
		e.platformAwaitReady(plan)
		nodes := e.platformCheck(true)
		e.P.writer.Lock()
		plan["nodes"] = nodes
		e.P.Operations.Save(e.Op)
		e.P.writer.Unlock()
	}
}

// platformAwaitReady waits, as machine_power does, for each started machine
// to report from its new boot. The clocks start together, so the machines
// boot side by side and one slow guest does not delay the deadline of the
// others. A guest that does not become ready is listed, not failed.
func (e *Execution) platformAwaitReady(plan D) {
	waiting := []D{}
	e.P.writer.Lock()
	for _, r := range dicts(plan["done"]) {
		m := e.S.Get("machines", str(r["vmid"]))
		if m != nil && equal(machineIdentity(m), r["identity"]) && contains([]string{"initializing", "provisioning"}, m["state"]) {
			e.readinessDeadline(str(r["vmid"]), "guest", intAt(e.P.Config, "guest_ready_timeout", 900))
			waiting = append(waiting, r)
		}
	}
	e.P.writer.Unlock()
	for _, r := range waiting {
		m := e.S.Get("machines", str(r["vmid"]))
		if m == nil {
			continue
		}
		if err := attempt(func() { e.WaitReady(m, str(r["boot_id"])) }); err != nil {
			e.P.writer.Lock()
			plan["not_ready"] = append(arr(plan["not_ready"]), merge(pick(r, "vmid", "tenant", "machine"), D{"error": describe(err)}))
			e.P.Operations.Save(e.Op)
			e.P.writer.Unlock()
		}
	}
}

// FinishPlatformPower runs under the writer once every action has answered.
func (e *Execution) FinishPlatformPower() D {
	plan := obj(e.Op["platform"])
	failed := arr(plan["failed"])
	r := D{"action": plan["action"], "done": arr(plan["done"]), "failed": failed, "skipped": arr(plan["skipped"]), "complete": len(failed) == 0}
	if plan["nodes"] != nil {
		r["nodes"] = plan["nodes"]
	}
	if plan["not_ready"] != nil {
		r["not_ready"] = plan["not_ready"]
	}
	if len(failed) > 0 {
		r["next_action"] = "run the dry run of the same action again: it lists what is left"
	}
	return r
}

// platformCheck asks every node to check, and with repair to fix, what a
// node boot can lose.
func (e *Execution) platformCheck(repair bool) []D {
	nodes := e.P.Nodes()
	out := make([]D, len(nodes))
	var wg sync.WaitGroup
	for i, n := range nodes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out[i] = D{"node": n.Name}
			if err := attempt(func() {
				out[i] = merge(obj(e.Call(D{"op": "platform_check", "repair": repair}, n.Target)), D{"node": n.Name})
			}); err != nil {
				out[i]["problems"] = []any{"check failed: " + describe(err)}
			}
		}()
	}
	wg.Wait()
	return out
}
