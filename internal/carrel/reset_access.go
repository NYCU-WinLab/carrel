package carrel

// machine_reset_access (issue #820, PLAN 7.9) lets a tenant back into a VM
// that accepts none of its keys any more. The node rewrites the VM's
// cloud-init user file from the one it booted with: the new keys in the
// login user's entry, and none of the steps that ran at creation (member
// commands, packages, apt sources, written files, swap), with the SSH host
// keys kept. New bytes give the VM a new cloud-init instance id, so the next
// boot runs the user and SSH modules again and adds the keys; keys already in
// authorized_keys stay. This is the one action that stores new cloud-init
// bytes (PLAN 7.10): the record, the node's file and the machine's keys change
// together, and a running VM is shut down and started for the change to take.

// ResetAccess adds keys to machine a["machine"] of tenant t through cloud-init.
func (e *Execution) ResetAccess(a, w, t D) D {
	dry, n := boolean(a["dry_run"]), integer(t["n"])
	m := e.Machine(t, a["machine"])
	if a["confirm"] != m["name"] {
		fail("invalid", "confirm must equal the machine name", D{"recovery": "revise_request"})
	}
	if m["kind"] != "vm" || unmanaged(m) || len(servicePortsOf(m)) > 0 {
		fail("invalid", "Only a VM that Carrel configures through cloud-init takes new keys; a CT, a machine installed from an ISO and one that serves its own ports do not", D{"recovery": "revise_request"})
	}
	if state := str(m["state"]); contains([]string{"provisioning", "deleting", "migrating"}, state) {
		fail("conflict", "The machine is "+state+"; reset its access once that has finished", D{"recovery": "resolve_prerequisite"})
	}
	keys := arr(a["ssh_keys"])
	if len(keys) == 0 {
		for _, k := range rowsOf[sshKey](e.S, "keys", n) {
			keys = append(keys, k.Key)
		}
	}
	if len(keys) == 0 {
		fail("invalid", "Pass ssh_keys, or save a key with ssh_key_add first", D{"recovery": "revise_request", "requirements": []any{"ssh_public_key"}})
	}
	validateKeys(keys)
	power := powerState(obj(e.Call(D{"op": "status", "machine": m})))
	if power != "running" && power != "stopped" {
		fail("conflict", "The machine is "+power+"; resume it or shut it down first", D{"recovery": "resolve_prerequisite"})
	}
	restart := power == "running"
	plan := D{"machine": m["name"], "keys_added": len(keys), "restart": restart, "host_keys": "kept",
		"note": "Keys already on the machine stay; remove any you no longer trust from ~/.ssh/authorized_keys."}
	if dry {
		return merge(plan, D{"dry_run": true, "requirements": []any{}, "ready_to_apply": true})
	}
	// The node first: it writes the file and returns the exact bytes, which
	// the record must hold for every later start and migration. The node
	// rewrites the file it has, so a retry after a lost answer writes the
	// same bytes again.
	files := obj(obj(e.Call(D{"op": "action", "machine": m, "action": "reset_access", "ssh_keys": keys}))["cloud_init"])
	if str(files["user"]) == "" || str(files["network"]) == "" {
		fail("unavailable", "The node did not return the machine's cloud-init files", D{"recovery": "retry"})
	}
	e.Transaction(func(tx *Execution) {
		cur := tx.Machine(t, a["machine"])
		if cur["vmid"] != m["vmid"] {
			fail("conflict", "The machine changed meanwhile; try again", D{"recovery": "retry"})
		}
		tx.keepCloudInit(cur, files)
		have := arr(cur["ssh_keys"])
		for _, k := range keys {
			if !contains(have, k) {
				have = append(have, k)
			}
		}
		cur["ssh_keys"] = have
		tx.S.Put("machines", cur["vmid"], n, cur)
		m = cur
	})
	e.S.Log(str(w["sub"]), n, "machine_reset_access", D{"vmid": m["vmid"], "keys_added": len(keys), "restart": restart}, "ok")
	// The jump host admits a machine's keys.
	e.syncJumpNow()
	if restart {
		// Graceful first; a guest that ignores the shutdown is stopped, since
		// its owner cannot log in to stop it either.
		if attempt(func() { e.PowerMachine(m, D{"action": "shutdown"}, t) }) != nil {
			e.PowerMachine(e.Machine(t, a["machine"]), D{"action": "stop"}, t)
		}
		e.PowerMachine(e.Machine(t, a["machine"]), D{"action": "start"}, t)
	}
	return merge(plan, D{"machine": e.PublicMachine(e.Machine(t, a["machine"]), e.ports(n)), "dry_run": false})
}
