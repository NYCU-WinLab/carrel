package carrel

// Existing-machine ingress changes share the deployment receipt and allocation
// bindings. Rollback may restore only the policy still owned by this operation.
func (e *Execution) PlanPolicy(a D, machines map[string]D) ([]D, []D) {
	changes, requirements := []D{}, []D{}
	seen := map[string]bool{}
	for _, request := range dicts(a["access"]) {
		m := machines[str(request["machine"])]
		if m == nil || m["vmid"] == nil {
			fail("not_found", "Access changes require an existing machine in this tenant")
		}
		name := str(m["name"])
		if seen[name] {
			fail("invalid", "Duplicate access change", D{"machine": name})
		}
		seen[name] = true
		mode := str(request["network_access"])
		if mode != "tenant" && mode != "restricted" {
			fail("invalid", "Unknown network access mode")
		}
		if mode == "restricted" && len(arr(m["nics"])) > 0 {
			fail("invalid", "Detach experiment NICs before restricting primary ingress", D{"machine": name, "recovery": "revise_request"})
		}
		before := textAt(m, "network_access", "tenant")
		changed := before != mode
		if changed && request["confirm"] != name {
			requirements = append(requirements, D{"machine": name, "requirement": "Set access.confirm to the machine name to authorize this ingress change"})
		}
		impact := "unchanged"
		if changed && mode == "restricted" {
			impact = "Same-tenant primary ingress will require an explicit connection grant"
		}
		if changed && mode == "tenant" {
			impact = "All same-tenant machines will gain primary ingress"
		}
		changes = append(changes, D{"machine": name, "before": before, "network_access": mode, "changed": changed, "impact": impact, "preserved": []string{"SSH route", "publications", "existing explicit peer grants"}})
		m["network_access"] = mode
	}
	return changes, requirements
}

func (e *Execution) ReservePolicy(t, plan, bindings D) []D {
	changes := []D{}
	for _, change := range dicts(plan["access"]) {
		m := e.Machine(t, change["machine"])
		bindings[str(m["vmid"])] = machineIdentity(m)
		if !boolean(change["changed"]) {
			continue
		}
		changes = append(changes, D{"vmid": m["vmid"], "identity": machineIdentity(m), "before": textAt(m, "network_access", "tenant"), "previous_owner": m["access_operation"], "after": change["network_access"]})
		m["network_access"], m["access_operation"] = change["network_access"], e.Op["id"]
		e.Put("machines", m["vmid"], integer(t["n"]), m)
	}
	return changes
}

func (e *Execution) CheckPolicy(deployment D) {
	for _, change := range dicts(deployment["access"]) {
		m := e.S.Get("machines", str(change["vmid"]))
		if m == nil || !equal(machineIdentity(m), change["identity"]) || m["access_operation"] != e.Op["id"] || m["network_access"] != change["after"] {
			fail("conflict", "Access policy changed since this operation; retry refused", D{"recovery": "revise_request"})
		}
	}
}

func (e *Execution) RestorePolicy() []D {
	failures := []D{}
	for _, change := range dicts(obj(e.Op["deployment"])["access"]) {
		m := e.S.Get("machines", str(change["vmid"]))
		// Deleted/replaced machines or newer policy owners are never modified.
		if m == nil || !equal(machineIdentity(m), change["identity"]) || m["access_operation"] != e.Op["id"] {
			continue
		}
		m["network_access"] = change["before"]
		e.Put("machines", m["vmid"], integer(m["tenant_n"]), m)
		if err := attempt(func() { e.Reconcile() }); err != nil {
			failures = append(failures, D{"kind": "access", "machine": m["name"]})
			continue
		}
		m["access_operation"] = change["previous_owner"]
		e.Put("machines", m["vmid"], integer(m["tenant_n"]), m)
	}
	return failures
}
