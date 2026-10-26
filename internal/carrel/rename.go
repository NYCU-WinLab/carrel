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
	if find(e.S.Objects("machines", n), func(x D) bool { return x["name"] == name }) != nil || e.frozenMachine(t, name) != nil {
		fail("conflict", "Machine name is already allocated", D{"recovery": "revise_request", "machine": name})
	}
	if state := str(m["state"]); state == "provisioning" || state == "deleting" || state == "migrating" {
		fail("conflict", "The machine is "+state+"; rename it once that has finished", D{"recovery": "resolve_prerequisite"})
	}
	if e.machineBusy(n, m) {
		fail("conflict", "An operation on this machine is queued or running; rename it once that has finished", D{"recovery": "resolve_prerequisite"})
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
		"machine":       e.PublicMachine(m, e.ports(n)),
		"renamed":       D{"from": old, "to": name},
		"owner_actions": e.renameActions(m, old, str(t["slug"])),
		"dry_run":       false,
	}
}

// machineBusy reports whether any active operation of the tenant may still
// reach the machine: by its target, a deployment's machines or bindings, a
// machine it created, or arguments that name it by name or vmid, since a
// queued job binds those only when it runs (CheckBusy in operations.go).
func (e *Execution) machineBusy(n int, m D) bool {
	vmid, name := integer(m["vmid"]), str(m["name"])
	names := func(v any) bool { return str(v) == name || str(v) == str(vmid) }
	for _, o := range e.S.ActiveOperations(n) {
		ids := arr(obj(o["deployment"])["machines"])
		if id := obj(o["machine_target"])["vmid"]; id != nil {
			ids = append(ids, id)
		}
		for id := range obj(obj(o["deployment"])["bindings"]) {
			ids = append(ids, id)
		}
		for _, id := range ids {
			if integer(id) == vmid {
				return true
			}
		}
		if m["operation_id"] == o["id"] || o["current_resource"] == name {
			return true
		}
		args := obj(o["args"])
		// machine_migrate names nodes in from and to, not machines.
		if names(args["machine"]) {
			return true
		}
		for _, list := range []string{"attachments", "access", "publications"} {
			for _, x := range dicts(args[list]) {
				if names(x["machine"]) {
					return true
				}
			}
		}
		for _, c := range dicts(args["connections"]) {
			if names(c["from"]) || names(c["to"]) {
				return true
			}
		}
	}
	return false
}

// renameActions says what is left to the owner after a rename.
func (e *Execution) renameActions(m D, old, slug string) []string {
	name := str(m["name"])
	out := []string{
		"Replace the SSH alias " + old + "." + slug + " with the returned ssh_config.",
		"The internal name " + old + "." + slug + ".internal no longer resolves; use " + name + "." + slug + ".internal in other machines' settings.",
	}
	if m["kind"] == "ct" {
		return append(out, "The container's hostname is now "+name+".")
	}
	// cloud-init sets the hostname and /etc/hosts from its files at every
	// boot unless told to keep what the guest has.
	return append(out, "The guest's own hostname is unchanged; set it and keep it across boots with: sudo hostnamectl set-hostname "+name+" && printf 'preserve_hostname: true\\nmanage_etc_hosts: false\\n' | sudo tee /etc/cloud/cloud.cfg.d/99-carrel-hostname.cfg && sudo sed -i 's/\\b"+old+"\\b/"+name+"/g' /etc/hosts")
}
