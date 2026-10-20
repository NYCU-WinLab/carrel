package carrel

import (
	"fmt"
	"time"
)

func (e *Execution) PlanAccess(t, a D, machines map[string]D) ([]D, []D, D) {
	connections, publications := []D{}, []D{}
	seen := map[string]bool{}
	delta := D{"public_ports": 0, "domains": 0}
	machine := func(ref any) D {
		m := machines[str(ref)]
		if m == nil {
			fail("not_found", "Connection or publication must reference a machine in this tenant", D{"machine": ref})
		}
		return m
	}
	for _, r := range dicts(a["connections"]) {
		source, target := machine(r["from"]), machine(r["to"])
		if source["name"] == target["name"] {
			fail("invalid", "Connection source and destination must differ")
		}
		if textAt(target, "network_access", "tenant") != "restricted" {
			fail("invalid", "Use network_access=restricted on the destination to enforce declared connections", D{"machine": target["name"]})
		}
		proto := textAt(r, "protocol", "tcp")
		key := string(encoded([]any{source["name"], target["name"], r["port"], proto}))
		if seen[key] {
			fail("conflict", "Duplicate connection", D{"recovery": "revise_request"})
		}
		seen[key] = true
		connections = append(connections, D{"from": source["name"], "to": target["name"], "port": r["port"], "protocol": proto})
	}
	seen = map[string]bool{}
	for _, r := range dicts(a["publications"]) {
		m := machine(r["machine"])
		proto, port := str(r["protocol"]), integer(r["port"])
		pub := D{"machine": m["name"], "protocol": proto, "port": port}
		key := ""
		if proto == "https" {
			if str(r["sub"]) == "" {
				fail("invalid", "HTTPS publication requires sub")
			}
			name := str(r["sub"]) + "." + str(t["slug"]) + ".winlab.tw"
			key = "https:" + name
			old := find(e.S.Objects("domains", integer(t["n"])), func(d D) bool { return d["name"] == name })
			if old != nil && (integer(old["vmid"]) != integer(m["vmid"]) || integer(old["target_port"]) != port || old["state"] != "ready") {
				fail("conflict", "Domain already belongs to another or incomplete publication", D{"name": name})
			}
			pub = merge(pub, D{"sub": r["sub"], "url": "https://" + name, "reused": old != nil})
			if old == nil {
				delta["domains"] = num(delta["domains"]) + 1
			}
		} else {
			if r["sub"] != nil {
				fail("invalid", "sub is only valid for HTTPS")
			}
			key = string(encoded([]any{m["name"], proto, port}))
			old := find(e.S.Objects("ports", integer(t["n"])), func(p D) bool {
				return integer(p["vmid"]) == integer(m["vmid"]) && integer(p["port"]) == port && p["proto"] == proto
			})
			if old != nil && old["state"] == "deleting" {
				fail("conflict", "Finish removing this port before reusing it", D{"recovery": "finish_cleanup"})
			}
			reused := old != nil || (m["vmid"] == nil && proto == "tcp" && port == 22)
			pub["reused"] = reused
			if !reused {
				delta["public_ports"] = num(delta["public_ports"]) + 1
			}
		}
		if seen[key] {
			fail("conflict", "Duplicate publication", D{"recovery": "revise_request"})
		}
		seen[key] = true
		publications = append(publications, pub)
	}
	for k, v := range delta {
		if num(v) == 0 {
			delete(delta, k)
		}
	}
	return connections, publications, delta
}
func (e *Execution) DeploymentPlan(t, a D) D {
	machines, networks, attachments := []D{}, []D{}, []D{}
	existingM, existingN := e.S.Objects("machines", integer(t["n"])), e.S.Objects("networks", integer(t["n"]))
	simN := append([]D{}, existingN...)
	byMachine, byNetwork := map[string]D{}, map[string]D{}
	for _, m := range existingM {
		byMachine[str(m["name"])] = m
		byMachine[str(m["vmid"])] = m
	}
	for _, n := range existingN {
		byNetwork[str(n["name"])] = n
		byNetwork[str(n["id"])] = n
	}
	delta := D{}
	for _, r := range dicts(a["machines"]) {
		if byMachine[str(r["name"])] != nil {
			fail("conflict", "Duplicate or existing machine name", D{"name": r["name"], "recovery": "revise_request"})
		}
		m := e.MachineSpec(t, r, true)
		machines = append(machines, m)
		byMachine[str(m["name"])] = m
		for k, v := range machineDelta(m) {
			delta[k] = num(delta[k]) + num(v)
		}
	}
	for _, r := range dicts(a["networks"]) {
		if byNetwork[str(r["name"])] != nil {
			fail("conflict", "Duplicate or existing network name", D{"name": r["name"], "recovery": "revise_request"})
		}
		n := e.NetworkSpec(t, r, simN)
		simN = append(simN, n)
		networks = append(networks, merge(without(n, "id", "serial", "tenant_n"), D{"state": "planned"}))
		byNetwork[str(n["name"])] = n
	}
	if len(networks) > 0 {
		delta["networks"] = len(networks)
	}
	access, accessRequirements := e.PlanPolicy(a, byMachine)
	nonempty := false
	for _, k := range []string{"machines", "networks", "attachments", "connections", "publications", "access"} {
		nonempty = nonempty || len(arr(a[k])) > 0
	}
	if !nonempty {
		fail("invalid", "Plan must contain machines, networks, connections or publications")
	}
	if len(existingM)+len(machines) > 100 || len(existingN)+len(networks) > 99 {
		fail("quota_exceeded", "Plan exceeds tenant address slots")
	}
	if len(e.S.Objects("ports", integer(t["n"])))+len(machines) > 10 {
		fail("quota_exceeded", "Public port block is full", D{"dimension": "public_ports"})
	}
	for _, r := range dicts(a["attachments"]) {
		m, network := byMachine[str(r["machine"])], byNetwork[str(r["network"])]
		if m == nil || network == nil {
			fail("not_found", "Attachment must reference this tenant's existing or planned resources")
		}
		ref := fallback(network, "id", network["name"])
		nics := dicts(m["nics"])
		if find(nics, func(n D) bool { return n["network"] == ref }) != nil {
			fail("conflict", "Machine already attached to this network", D{"recovery": "revise_request"})
		}
		index := nextNIC(nics)
		if index == 0 {
			fail("quota_exceeded", "Machine already has 8 NICs")
		}
		m["nics"] = append(nics, D{"index": index, "network": ref})
		attachments = append(attachments, D{"machine": m["name"], "network": network["name"], "nic": index, "state": "planned"})
	}
	connections, publications, accessDelta := e.PlanAccess(t, a, byMachine)
	for k, v := range accessDelta {
		delta[k] = num(delta[k]) + num(v)
	}
	if len(e.S.Objects("ports", integer(t["n"])))+integer(delta["public_ports"]) > 10 {
		fail("quota_exceeded", "Public port block is full", D{"dimension": "public_ports"})
	}
	before, after := e.Quota(t), e.Quota(t, delta)
	admission := D{"accepted": true, "reserved": false, "reason": "no_compute_or_storage_growth"}
	if len(machines) > 0 {
		// A deployment's new machines share one node, so their connections stay local.
		e.placement, admission = e.Place(num(delta["vcpu"]), num(delta["memory_mb"]), num(delta["disk_gb"]))
	}
	planned, requirements := []D{}, accessRequirements
	for _, m := range machines {
		pm := plannedMachine(m)
		planned = append(planned, pm)
		for _, r := range arr(pm["requirements"]) {
			requirements = append(requirements, D{"machine": pm["name"], "requirement": r})
		}
	}
	next, detail := "deployment_apply", "When execution is authorized, submit the same specification once with deployment_apply. This is already the complete preview."
	if len(requirements) > 0 {
		next = "provide_requirements"
		detail = "Supply the listed requirements, then preview the updated specification."
	}
	return mutationResult(before, D{"machines": planned, "access": access, "networks": networks, "attachments": attachments, "connections": connections, "publications": publications, "quota_after": after, "admission": admission, "requirements": requirements, "units": Units, "apply_tool": "deployment_apply", "next_action": next, "next_action_detail": detail, "limitations": []string{"No IDs, addresses or ports are reserved; apply rechecks capacity and quota.", "Guest boot, package commands and SSH connectivity are checked only after creation.", "Managed networks configure private IPs automatically; raw_l2 requires owner configuration.", "network_access=tenant allows all same-tenant primary traffic. Use restricted and connections for service isolation.", "Publication success confirms routing and TLS configuration; end-to-end application responses require an external check."}}, true)
}
func (e *Execution) ReserveAccess(t, plan D) (D, D, []any) {
	created := D{"ports": []any{}, "domains": []any{}, "peers": []any{}}
	bindings := D{}
	references := []any{}
	n := integer(t["n"])
	machine := func(ref any) D { m := e.Machine(t, ref); bindings[str(m["vmid"])] = machineIdentity(m); return m }
	add := func(kind string, g D) {
		e.Put(kind, g["id"], n, g)
		created[kind] = append(arr(created[kind]), g["id"])
	}
	for _, c := range dicts(plan["connections"]) {
		source, target := machine(c["from"]), machine(c["to"])
		old := find(e.S.Objects("peers", n), func(p D) bool {
			return p["source"] == str(source["ip"])+"/32" && p["target"] == target["ip"] && num(p["port"]) == num(c["port"]) && textAt(p, "proto", "tcp") == str(c["protocol"])
		})
		if old != nil {
			if old["state"] == "deleting" {
				fail("conflict", "Finish removing this connection before reusing it", D{"recovery": "finish_cleanup"})
			}
			references = append(references, []any{"peers", old["id"], old["operation_id"]})
			continue
		}
		add("peers", D{"id": randomID()[:16], "tenant_n": n, "source": str(source["ip"]) + "/32", "target": target["ip"], "port": c["port"], "proto": c["protocol"], "from_machine": source["name"], "machine": target["name"]})
	}
	for _, p := range dicts(plan["publications"]) {
		m := machine(p["machine"])
		kind := "ports"
		if p["protocol"] == "https" {
			kind = "domains"
		}
		if boolean(p["reused"]) {
			old := find(e.S.Objects(kind, n), func(g D) bool {
				if integer(g["vmid"]) != integer(m["vmid"]) {
					return false
				}
				if kind == "domains" {
					return g["name"] == str(p["sub"])+"."+str(t["slug"])+".winlab.tw"
				}
				return num(g["port"]) == num(p["port"]) && g["proto"] == p["protocol"]
			})
			if old == nil {
				fail("conflict", "Reused publication disappeared")
			}
			references = append(references, []any{kind, old["id"], old["operation_id"]})
			continue
		}
		if kind == "domains" {
			add(kind, D{"id": randomID()[:16], "tenant_n": n, "vmid": m["vmid"], "slug": t["slug"], "sub": p["sub"], "name": str(p["sub"]) + "." + str(t["slug"]) + ".winlab.tw", "target_port": p["port"], "state": "queued", "ready_at": time.Now().Unix()})
		} else {
			port := e.AllocatePort(t)
			add(kind, D{"id": fmt.Sprintf("%d-%d-%s", n, port, str(p["protocol"])), "tenant_n": n, "vmid": m["vmid"], "ip": m["ip"], "public_port": port, "port": p["port"], "proto": p["protocol"]})
		}
	}
	return created, bindings, references
}
func (e *Execution) CheckBindings(t, deployment D) {
	e.CheckPolicy(deployment)
	for vmid, identity := range obj(deployment["bindings"]) {
		if !equal(machineIdentity(e.Machine(t, vmid)), identity) {
			fail("conflict", "A referenced machine was replaced; retry refused", D{"recovery": "revise_request"})
		}
	}
	for id, owner := range obj(deployment["network_bindings"]) {
		network := e.S.Get("networks", id)
		if network == nil || integer(network["tenant_n"]) != integer(t["n"]) || !equal(network["operation_id"], owner) {
			fail("conflict", "A referenced network was removed or replaced; retry refused", D{"recovery": "revise_request"})
		}
	}
	for kind, ids := range obj(deployment["grants"]) {
		for _, id := range arr(ids) {
			o := e.S.Get(kind, str(id))
			if o == nil || !e.sameOperation(o) {
				fail("conflict", "A deployment grant was removed or replaced; retry refused", D{"recovery": "revise_request"})
			}
		}
	}
	for _, v := range arr(deployment["references"]) {
		ref := arr(v)
		if len(ref) != 3 {
			fail("conflict", "Invalid saved resource reference")
		}
		o := e.S.Get(str(ref[0]), str(ref[1]))
		if o == nil || !equal(o["operation_id"], ref[2]) {
			fail("conflict", "A reused permission or publication was removed or replaced; retry refused", D{"recovery": "revise_request"})
		}
	}
}
func (e *Execution) DeploymentApply(t, a, w D) D {
	if e.Op == nil {
		fail("invalid", "Deployment apply requires the background operation worker")
	}
	op := e.Op
	n := integer(t["n"])
	if op["deployment"] == nil {
		plan := e.DeploymentPlan(t, a)
		if !boolean(plan["ready_to_apply"]) {
			fail("invalid", "Deployment requires the listed keys or ingress-change confirmation", D{"requirements": plan["requirements"]})
		}
		e.Transaction(func(tx *Execution) {
			ms, ns, nics := []any{}, []any{}, []D{}
			for _, r := range dicts(a["networks"]) {
				network := tx.NetworkSpec(t, r, nil)
				tx.Put("networks", network["id"], n, network)
				ns = append(ns, network["id"])
			}
			for _, r := range dicts(a["machines"]) {
				m, _ := tx.AllocateMachine(t, e.placement.record(tx.MachineSpec(t, r, false)))
				ms = append(ms, m["vmid"])
			}
			for _, r := range dicts(a["attachments"]) {
				m := tx.Machine(t, r["machine"])
				network := find(tx.S.Objects("networks", n), func(x D) bool { return x["name"] == r["network"] || x["id"] == r["network"] })
				nic := tx.NICSpec(m, network, nextNIC(dicts(m["nics"])))
				m["nics"] = append(dicts(m["nics"]), nic)
				tx.Put("machines", m["vmid"], n, m)
				nics = append(nics, D{"vmid": m["vmid"], "index": nic["index"], "network": network["id"]})
			}
			grants, bindings, refs := tx.ReserveAccess(t, plan)
			access := tx.ReservePolicy(t, plan, bindings)
			networkIDs := append([]any{}, ns...)
			for _, vmid := range ms {
				m := tx.Machine(t, vmid)
				bindings[str(vmid)] = machineIdentity(m)
			}
			for _, nic := range nics {
				m := tx.Machine(t, nic["vmid"])
				bindings[str(m["vmid"])] = machineIdentity(m)
				networkIDs = append(networkIDs, nic["network"])
			}
			nb := D{}
			for _, network := range tx.S.Objects("networks", n) {
				if contains(networkIDs, network["id"]) {
					nb[str(network["id"])] = network["operation_id"]
				}
			}
			op["deployment"] = D{"machines": ms, "networks": ns, "nics": nics, "access": access, "grants": grants, "bindings": bindings, "references": refs, "network_bindings": nb}
			op["reserved"] = true
			op["resource_changes"] = true
			op["phase"] = "resources_reserved"
			tx.S.Put("operations", op["id"], n, op)
		})
		e.P.invalidateInventory()
	}
	deployment := obj(op["deployment"])
	e.CheckBindings(t, deployment)
	e.Reconcile()
	for _, vmid := range arr(deployment["machines"]) {
		m := e.Machine(t, vmid)
		if m["state"] != "ready" && m["state"] != "initializing" {
			e.Provision(m, true)
		}
	}
	for _, attachment := range dicts(deployment["nics"]) {
		if contains(deployment["machines"], attachment["vmid"]) {
			continue
		}
		m := e.Machine(t, attachment["vmid"])
		nic := find(dicts(m["nics"]), func(n D) bool { return integer(n["index"]) == integer(attachment["index"]) })
		network := e.S.Get("networks", str(nic["network"]))
		e.Call(D{"op": "action", "action": "nic_attach", "machine": m, "index": nic["index"], "serial": network["serial"], "nic": nic})
		e.NICReadiness(m, nic)
	}
	return D{"deployment": deployment, "quota_after": e.Quota(t)}
}
func (e *Execution) PublishDeployment(t, a, w D) {
	deployment := obj(e.Op["deployment"])
	e.CheckBindings(t, deployment)
	for _, id := range arr(obj(deployment["grants"])["domains"]) {
		e.RequireActive(integer(t["n"]))
		d := e.S.Get("domains", str(id))
		if d == nil || !e.sameOperation(d) {
			fail("conflict", "Deployment publication was removed or replaced; retry refused", D{"recovery": "revise_request"})
		}
		e.Op["phase"] = "publishing"
		e.Op["current_resource"] = d["name"]
		e.P.Operations.Save(e.Op)
		e.DomainAction("domain_add", D{"machine": str(d["vmid"]), "sub": d["sub"], "target_port": d["target_port"]}, t)
	}
}
func (e *Execution) AccessResult(t, a D) D {
	endpoints := []D{}
	for _, p := range dicts(a["publications"]) {
		m := e.Machine(t, p["machine"])
		if p["protocol"] == "https" {
			name := str(p["sub"]) + "." + str(t["slug"]) + ".winlab.tw"
			d := find(e.S.Objects("domains", integer(t["n"])), func(d D) bool { return d["name"] == name })
			endpoints = append(endpoints, D{"machine": m["name"], "url": "https://" + name, "state": d["state"], "verification": "routing_configured"})
		} else {
			g := find(e.S.Objects("ports", integer(t["n"])), func(g D) bool {
				return integer(g["vmid"]) == integer(m["vmid"]) && num(g["port"]) == num(p["port"]) && g["proto"] == p["protocol"]
			})
			endpoints = append(endpoints, D{"machine": m["name"], "host": "carrel.winlab.tw", "port": g["public_port"], "protocol": g["proto"], "verification": "routing_configured"})
		}
	}
	return D{"connections": arr(a["connections"]), "endpoints": endpoints}
}
func (e *Execution) CleanupOutcome() {
	failures := e.CleanupDeployment()
	state := "rolled_back"
	if len(failures) > 0 {
		state = "cleanup_failed"
	}
	e.Op["cleanup"] = failures
	e.Op["state"] = state
	e.Op["phase"] = state
	e.Op["reserved"] = len(failures) > 0
	delete(e.Op, "prepared_result")
}
func (e *Execution) CleanupDeployment() []D {
	t := e.S.TenantN(integer(e.Op["tenant_n"]))
	n := integer(t["n"])
	failures := []D{}
	run := func(tool string, a, description D) {
		if err := attempt(func() { e.Member(tool, a, obj(e.Op["who"]), t) }); err != nil {
			failures = append(failures, description)
		}
	}
	for _, spec := range [][3]string{{"domains", "domain_remove", "name"}, {"ports", "port_close", "id"}, {"peers", "peer_revoke", "id"}} {
		for _, g := range e.S.Objects(spec[0], n) {
			if e.sameOperation(g) {
				run(spec[1], D{spec[2]: g[spec[2]]}, D{"kind": spec[0], "id": g["id"]})
			}
		}
	}
	for _, m := range e.S.Objects("machines", n) {
		if e.sameOperation(m) {
			run("machine_delete", D{"machine": m["name"], "confirm": m["name"]}, D{"kind": "machine", "name": m["name"]})
		} else {
			for _, nic := range dicts(m["nics"]) {
				if e.sameOperation(nic) {
					run("machine_nic_detach", D{"machine": m["name"], "nic": nic["index"]}, D{"kind": "nic", "machine": m["name"], "nic": nic["index"]})
				}
			}
		}
	}
	for _, network := range e.S.Objects("networks", n) {
		if e.sameOperation(network) {
			run("network_delete", D{"network": network["id"], "confirm": network["name"]}, D{"kind": "network", "name": network["name"]})
		}
	}
	failures = append(failures, e.RestorePolicy()...)
	return filter(failures, func(f D) bool { return f["id"] == nil || e.S.Get(str(f["kind"]), str(f["id"])) != nil })
}
