package carrel

// machine_rename gives a machine a new name in its tenant. Everything that
// follows the machine holds its vmid, its address or its grants by vmid, so
// only what carries the name changes: the record, the Proxmox VM name (or
// CT hostname), the internal name <name>.<tenant>.internal, the SSH alias
// carrel returns, NetBox (matched by VMID) and the names apps and peer
// grants keep for display. The guest's own hostname stays as cloud-init set
// it: its files are kept byte for byte (issue #93), so regenerating them
// would run cloud-init again. The result says how to change it in the guest.

// RenameMachine renames machine a["machine"] of tenant t to a["name"].
func (e *Execution) RenameMachine(a, t D) D {
	dry, n := boolean(a["dry_run"]), integer(t["n"])
	m := e.Machine(t, a["machine"])
	old, name := str(m["name"]), str(a["name"])
	if a["confirm"] != old {
		fail("invalid", "confirm must equal the machine's current name")
	}
	if !labelPattern.MatchString(name) || contains(reservedLabels, name) {
		fail("invalid", "Give the new name as a lowercase label", D{"recovery": "revise_request"})
	}
	if name == old {
		return D{"machine": e.PublicMachine(m, e.ports(n)), "dry_run": dry}
	}
	if find(e.S.Objects("machines", n), func(x D) bool { return x["name"] == name }) != nil {
		fail("conflict", "Machine name is already allocated", D{"recovery": "revise_request", "machine": name})
	}
	if state := str(m["state"]); state == "provisioning" || state == "deleting" || state == "migrating" {
		fail("conflict", "The machine is "+state+"; rename it once that has finished", D{"recovery": "resolve_prerequisite"})
	}
	for _, o := range e.S.ActiveOperations(n) {
		if target := obj(o["machine_target"]); target != nil && integer(target["vmid"]) == integer(m["vmid"]) {
			fail("conflict", "An operation on this machine is still running", D{"recovery": "resolve_prerequisite"})
		}
		if o["current_resource"] == old {
			fail("conflict", "An operation on this machine is still running", D{"recovery": "resolve_prerequisite"})
		}
	}
	if dry {
		planned := merge(m, D{"name": name})
		return D{"machine": e.PublicMachine(planned, e.ports(n)), "dry_run": true}
	}
	// The node first: if Proxmox refuses, nothing changed here.
	e.Call(D{"op": "action", "machine": m, "action": "rename", "name": name})
	e.Transaction(func(tx *Execution) {
		m["name"] = name
		tx.S.Put("machines", m["vmid"], n, m)
		for _, app := range tx.S.Objects("apps", n) {
			if integer(app["vmid"]) == integer(m["vmid"]) {
				app["machine"] = name
				tx.S.Put("apps", app["id"], n, app)
			}
		}
		for _, p := range tx.peers() {
			changed := false
			if p.Target == m["ip"] && p.Machine == old {
				p.Machine, changed = name, true
			}
			if p.Source == str(m["ip"])+"/32" && p.FromMachine == old {
				p.FromMachine, changed = name, true
			}
			if changed {
				tx.S.Put("peers", p.ID, p.TenantN, p.D())
			}
		}
	})
	e.S.Log("system", n, "machine_renamed", D{"vmid": m["vmid"], "from": old, "to": name}, "ok")
	e.Reconcile()
	e.P.NetBoxKick()
	return D{
		"machine": e.PublicMachine(m, e.ports(n)),
		"renamed": D{"from": old, "to": name},
		"owner_actions": []string{
			"Replace the SSH alias " + old + "." + str(t["slug"]) + " with the returned ssh_config.",
			"The guest's own hostname is unchanged; set it with: sudo hostnamectl set-hostname " + name,
		},
		"dry_run": false,
	}
}
