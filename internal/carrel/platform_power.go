package carrel

import (
	"sort"
	"strings"
	"sync"
)

// PlatformPower shuts down or starts every tenant machine at once, for a
// planned outage or maintenance. The nodes and the infra CTs stay up, so the
// control plane and its gateway keep answering and the same tool starts the
// machines again. A dry run lists the machines and returns a confirm code; the
// real call must repeat that code, and the code changes whenever the list
// does, so a second look at the plan is required (the double check).
func (e *Execution) PlatformPower(a, w D) D {
	action := str(a["action"])
	if action == "check" {
		return D{"action": "check", "nodes": e.platformCheck()}
	}
	if action != "shutdown" && action != "start" {
		fail("invalid", "Unknown platform power action")
	}
	targets := e.platformTargets(action)
	code := platformCode(action, targets)
	listed := []D{}
	for _, t := range targets {
		listed = append(listed, t.public())
	}
	if boolean(a["dry_run"]) {
		return D{"dry_run": true, "action": action, "count": len(targets), "machines": listed, "confirm": code}
	}
	if str(a["confirm"]) != code {
		fail("invalid", "confirm must equal the code of a dry run of this action; run the dry run again, the machine list may have changed", D{"recovery": "revise_request"})
	}
	done, failed := e.platformApply(action, targets)
	r := D{"dry_run": false, "action": action, "done": done, "failed": failed}
	if action == "shutdown" {
		// The start brings back exactly these: machines their owners had
		// already shut down stay down.
		vmids := []any{}
		for _, t := range targets {
			vmids = append(vmids, t.m["vmid"])
		}
		e.S.SitePut("platform", "power", D{"state": "off", "vmids": vmids, "at": now(), "by": w["sub"]})
	} else {
		e.S.SitePut("platform", "power", D{"state": "on", "at": now(), "by": w["sub"]})
		r["nodes"] = e.platformCheck()
	}
	return r
}

type platformTarget struct {
	m     D
	n     int
	slug  string
	state string
}

func (t platformTarget) public() D {
	return D{"tenant": t.slug, "machine": t.m["name"], "vmid": t.m["vmid"], "power_state": t.state}
}

// platformTargets reads each machine's power from its node: a shutdown takes
// the running and paused ones, a start the ones the last shutdown stopped that
// are still stopped. Suspended tenants are left alone either way.
func (e *Execution) platformTargets(action string) []platformTarget {
	slugs := map[int]string{}
	for _, t := range e.S.Tenants() {
		if t["status"] == "active" {
			slugs[integer(t["n"])] = str(t["slug"])
		}
	}
	stopped := map[string]bool{}
	if action == "start" {
		power := e.S.SiteGet("platform", "power")
		if power == nil || power["state"] != "off" {
			return []platformTarget{}
		}
		for _, v := range arr(power["vmids"]) {
			stopped[str(v)] = true
		}
	}
	candidates := []platformTarget{}
	for _, n := range sortedKeys(slugs) {
		for _, m := range e.S.Objects("machines", n) {
			if action == "start" && !stopped[str(m["vmid"])] {
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
	out := []platformTarget{}
	for _, t := range candidates {
		if want[t.state] {
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool { return integer(out[i].m["vmid"]) < integer(out[j].m["vmid"]) })
	return out
}

func sortedKeys(m map[int]string) []int {
	keys := []int{}
	for k := range m {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	return keys
}

func platformCode(action string, targets []platformTarget) string {
	ids := []string{}
	for _, t := range targets {
		ids = append(ids, str(t.m["vmid"])+":"+t.state)
	}
	return action + "-" + digest(action + "|" + strings.Join(ids, ","))[:12]
}

// platformApply runs one node's machines in turn (its agent takes one action
// at a time) and the nodes side by side. Records change after all answers,
// as one writer.
func (e *Execution) platformApply(action string, targets []platformTarget) ([]D, []D) {
	byNode := map[string][]int{}
	for i, t := range targets {
		node := e.P.nodeOf(t.m).Target
		byNode[node] = append(byNode[node], i)
	}
	files := make([]D, len(targets))
	if action == "start" {
		for i, t := range targets {
			files[i] = e.cloudInitFiles(t.m)
		}
	}
	states := make([]string, len(targets))
	errs := make([]any, len(targets))
	var wg sync.WaitGroup
	for _, list := range byNode {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, i := range list {
				errs[i] = attempt(func() {
					request := D{"op": "action", "machine": targets[i].m, "action": action}
					if files[i] != nil {
						request["cloud_init"] = files[i]
					}
					states[i] = powerState(obj(e.Call(request)))
				})
			}
		}()
	}
	wg.Wait()
	want := "stopped"
	if action == "start" {
		want = "running"
	}
	done, failed := []D{}, []D{}
	for i, t := range targets {
		if errs[i] != nil || states[i] != want {
			f := merge(t.public(), D{"observed": states[i]})
			if errs[i] != nil {
				f["error"] = describe(errs[i])
			}
			failed = append(failed, f)
			continue
		}
		m := t.m
		// The node agent sets onboot the same way: only running keeps it.
		m["onboot"] = want == "running"
		m["state"], m["power_state"], m["ssh_ready"] = want, want, false
		if want == "running" {
			m["state"] = bootState(m)
		}
		e.Put("machines", m["vmid"], t.n, m)
		e.P.notifyReport(integer(m["vmid"]))
		done = append(done, merge(t.public(), D{"power_state": want}))
	}
	e.P.invalidateInventory()
	return done, failed
}

func (e *Execution) platformCheck() []D {
	nodes := e.P.Nodes()
	out := make([]D, len(nodes))
	var wg sync.WaitGroup
	for i, n := range nodes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out[i] = D{"node": n.Name}
			if err := attempt(func() { out[i] = merge(obj(e.Call(D{"op": "platform_check"}, n.Target)), D{"node": n.Name}) }); err != nil {
				out[i]["problems"] = []any{"check failed: " + describe(err)}
			}
		}()
	}
	wg.Wait()
	return out
}
