package carrel

import (
	"fmt"
	"regexp"
	"time"
)

// Freeze and thaw (issue #190): a stopped machine is backed up to the PVE
// storage that fronts the Proxmox Backup Server and removed from the cluster.
// Its row moves from "machines" to "frozen", so nothing that walks the live
// machines sees it, while its VMID, name and internal address stay taken.
// Only the frozen quota and the address are charged until it is thawed or
// deleted.

// freezeReleasable names the resources a machine may hold that freeze can
// require released first; the site's freeze_release list picks among them.
var freezeReleasable = []string{"public_ips", "special_ports", "special_domains"}

var backupVolume = regexp.MustCompile(`^[a-z][a-z0-9_.-]*:backup/[A-Za-z0-9_./:+-]+$`)

// forgetMachine removes everything of a machine that hangs off its VMID.
func (tx *Execution) forgetMachine(n int, m D) {
	for _, kind := range []string{"ports", "domains", "snapshots", "guest_reports", "cloud_init"} {
		for _, o := range tx.S.Objects(kind, n) {
			if integer(o["vmid"]) == integer(m["vmid"]) {
				tx.S.Remove(kind, fallback(o, "id", o["vmid"]))
			}
		}
	}
	for _, p := range tx.peers() {
		if p.Target == m["ip"] || p.Source == str(m["ip"])+"/32" {
			tx.S.Remove("peers", p.ID)
		}
	}
	// A public address stays the tenant's, unbound (issue #91): a
	// later machine with this VMID must not inherit it.
	for _, b := range tx.publicIPs(n) {
		if b.VMID == integer(m["vmid"]) {
			b.VMID, b.Ports, b.BoundAt = 0, nil, 0
			tx.Put("public_ips", b.ID, n, b)
		}
	}
	// The address stays reserved for the tenant; only this holder goes.
	for _, v := range tx.vips(n) {
		holders := []int{}
		for _, id := range v.VMIDs {
			if id != integer(m["vmid"]) {
				holders = append(holders, id)
			}
		}
		if len(holders) != len(v.VMIDs) {
			v.VMIDs = holders
			tx.Put("vips", v.ID, n, v)
		}
	}
}

// frozenMachine finds a frozen machine of the tenant by name or VMID.
func (e *Execution) frozenMachine(t D, ref any) D {
	return find(e.S.Objects("frozen", integer(t["n"])), func(f D) bool { return str(f["vmid"]) == str(ref) || str(f["name"]) == str(ref) })
}

// frozenDisks is the configured disk size of the tenant's frozen machines.
func frozenDisks(frozen []D) float64 {
	sum := 0.0
	for _, f := range frozen {
		sum += num(f["disk_gb"])
	}
	return sum
}

// PublicFrozen is a frozen machine as machine_list shows it.
func (e *Execution) PublicFrozen(f D) D {
	r := pick(f, "name", "kind", "image", "cpu", "memory_mb", "disk_gb", "swap_mb", "ip", "frozen_at")
	r["state"] = "frozen"
	r["backup"] = D{"size_bytes": f["backup_bytes"]}
	r["quota"] = D{"frozen_gb": f["disk_gb"], "ips": 1}
	return r
}

func (e *Execution) backupStorage() string {
	storage := str(e.P.Config["backup_storage"])
	if storage == "" {
		fail("backend_unavailable", "Freezing machines is not set up on this site", D{"recovery": "contact_administrator"})
	}
	return storage
}

// freezeRelease is the site's list of resource kinds a machine must have
// released before it freezes.
func (e *Execution) freezeRelease() []string {
	list := freezeReleasable
	if v, ok := e.P.Config["freeze_release"]; ok {
		list = nil
		for _, k := range arr(v) {
			if !contains(freezeReleasable, str(k)) {
				fail("invalid", "freeze_release names an unknown resource kind", D{"resource": k})
			}
			list = append(list, str(k))
		}
	}
	return list
}

// freezeHeld lists what the machine holds of the resources that must go
// first, each named for the member.
func (e *Execution) freezeHeld(n int, m D) []D {
	vmid, held := integer(m["vmid"]), []D{}
	for _, kind := range e.freezeRelease() {
		switch kind {
		case "public_ips":
			for _, b := range e.publicIPs(n) {
				if b.VMID == vmid {
					held = append(held, D{"resource": "public_ip", "name": b.Address, "release_with": "public_ip_release"})
				}
			}
		case "special_ports":
			for _, g := range e.ports(n) {
				if g.VMID == vmid && g.Special {
					held = append(held, D{"resource": "special_port", "name": fmt.Sprintf("%d/%s", g.PublicPort, g.Proto), "release_with": "port_close"})
				}
			}
		case "special_domains":
			for _, d := range rowsOf[domainRecord](e.S, "domains", n) {
				if d.VMID == vmid && d.Grant != "" {
					held = append(held, D{"resource": "special_domain", "name": d.Name, "release_with": "domain_remove"})
				}
			}
		}
	}
	return held
}

// freezeDelta is what a freeze changes in the quota: the machine's compute
// is released, its address and public ports stay, its disk size is charged
// to the frozen quota.
func freezeDelta(m D) D {
	d := machineDelta(m)
	delete(d, "ips")
	delete(d, "public_ports")
	for k, v := range d {
		d[k] = -num(v)
	}
	d["frozen_gb"] = m["disk_gb"]
	return d
}

// thawDelta is the reverse: the normal quota is checked as for a creation.
func thawDelta(f D) D {
	d := machineDelta(f)
	delete(d, "ips")
	delete(d, "public_ports")
	d["frozen_gb"] = -num(f["disk_gb"])
	return d
}

func (e *Execution) FreezeMachine(a, t D) D {
	dry, n := boolean(a["dry_run"]), integer(t["n"])
	storage := e.backupStorage()
	if f := e.frozenMachine(t, a["machine"]); f != nil && e.S.Get("machines", str(f["vmid"])) == nil {
		fail("conflict", "The machine is already frozen", D{"recovery": "resolve_prerequisite"})
	}
	m := e.Machine(t, a["machine"])
	if a["confirm"] != m["name"] {
		fail("invalid", "confirm must equal the machine name")
	}
	// A freeze that stopped after the backup: the machine row is all that is left to remove.
	resumed := e.S.Get("frozen", str(m["vmid"])) != nil && m["state"] == "deleting"
	if !resumed {
		if state := str(m["state"]); contains([]string{"provisioning", "deleting", "migrating", "needs_owner_fix"}, state) || m["resize_from"] != nil {
			fail("conflict", "The machine is "+state+"; freeze it once that has finished", D{"recovery": "resolve_prerequisite"})
		}
		if e.machineBusy(n, m) && e.Op == nil {
			fail("conflict", "An operation on this machine is queued or running; freeze it once that has finished", D{"recovery": "resolve_prerequisite"})
		}
		if status := obj(e.Call(D{"op": "status", "machine": m})); powerState(status) != "stopped" {
			fail("conflict", "Shut the machine down with machine_power before freezing it", D{"recovery": "resolve_prerequisite", "requirements": []string{"machine_stopped"}})
		}
		if snaps := filter(toDicts(e.snapshots(n)), func(s D) bool { return integer(s["vmid"]) == integer(m["vmid"]) }); len(snaps) > 0 {
			fail("conflict", "Delete the machine's disk snapshots first; they are not part of the backup", D{"recovery": "resolve_prerequisite", "snapshots": len(snaps)})
		}
		if held := e.freezeHeld(n, m); len(held) > 0 {
			fail("conflict", "Release "+str(held[0]["name"])+" first: it is a shared resource that a frozen machine cannot keep", D{"recovery": "resolve_prerequisite", "held": held})
		}
	}
	delta := freezeDelta(m)
	if !resumed {
		e.Quota(t, delta)
	}
	if dry {
		return D{"machine": D{"name": m["name"], "state": "frozen_planned"}, "dry_run": true, "quota_after": e.Quota(t, delta), "requirements": []string{"machine_stopped"}, "ready_to_apply": true}
	}
	if !resumed {
		freezeID := randomID()
		if e.Op != nil {
			freezeID = str(e.Op["id"])
		}
		backup := obj(e.Call(D{"op": "freeze", "machine": m, "storage": storage, "freeze_id": freezeID}))
		if !backupVolume.MatchString(str(backup["volid"])) || num(backup["size"]) <= 0 {
			fail("backend_unavailable", "The backup could not be verified; the machine is unchanged", D{"recovery": "retry_infrastructure"})
		}
		frozen := merge(without(m, "state", "power_state", "ssh_ready", "onboot", "resize", "readiness"), D{"state": "frozen", "frozen_at": time.Now().Unix(), "backup_volid": backup["volid"], "backup_storage": storage, "backup_bytes": backup["size"], "frozen_by": e.Op["id"]})
		e.Transaction(func(tx *Execution) {
			tx.Put("frozen", m["vmid"], n, frozen)
			m["state"] = "deleting"
			tx.Put("machines", m["vmid"], n, m)
		})
	}
	e.Call(D{"op": "action", "machine": m, "action": "delete", "confirm": m["name"]})
	e.P.invalidateInventory()
	e.Reconcile()
	e.Transaction(func(tx *Execution) {
		for _, kind := range []string{"guest_reports"} {
			tx.S.Remove(kind, m["vmid"])
		}
		tx.S.Remove("machines", m["vmid"])
	})
	return D{"machine": e.PublicFrozen(e.S.Get("frozen", str(m["vmid"]))), "dry_run": false, "quota_after": e.Quota(t)}
}

func toDicts[T any](rows []T) []D {
	out := []D{}
	for _, r := range rows {
		out = append(out, decode(string(encoded(r))))
	}
	return out
}

func (e *Execution) ThawMachine(a, t D) D {
	dry, n := boolean(a["dry_run"]), integer(t["n"])
	f := e.frozenMachine(t, a["machine"])
	if f == nil {
		fail("not_found", "No frozen machine of this name in this tenant")
	}
	delta := thawDelta(f)
	after := e.Quota(t, delta)
	node, admission := e.Place(num(f["cpu"]), num(f["memory_mb"]), num(f["disk_gb"]))
	if dry {
		return D{"machine": D{"name": f["name"], "state": "thaw_planned"}, "dry_run": true, "quota_after": after, "admission": admission}
	}
	m := node.record(without(f, "state", "frozen_at", "frozen_by", "backup_volid", "backup_storage", "backup_bytes"))
	m["state"], m["power_state"], m["ssh_ready"], m["onboot"] = "stopped", "stopped", false, false
	e.Call(D{"op": "thaw", "machine": m, "volid": f["backup_volid"], "storage": f["backup_storage"]})
	// Only now is the backup of no use: a retry finds the machine restored and the backup gone.
	e.Call(D{"op": "backup_remove", "machine": m, "volid": f["backup_volid"]})
	e.Transaction(func(tx *Execution) {
		tx.S.Remove("frozen", f["vmid"])
		tx.Put("machines", m["vmid"], n, m)
	})
	e.P.invalidateInventory()
	e.Reconcile()
	return D{"machine": e.PublicMachine(m, e.ports(n)), "dry_run": false, "quota_after": e.Quota(t)}
}

// DeleteFrozen removes a frozen machine and its backup.
func (e *Execution) DeleteFrozen(f D, a, t D) D {
	dry, n := boolean(a["dry_run"]), integer(t["n"])
	if a["confirm"] != f["name"] {
		fail("invalid", "confirm must equal the machine name")
	}
	delta := D{"ips": -1, "frozen_gb": -num(f["disk_gb"]), "public_ports": -len(filter(toDicts(e.ports(n)), func(p D) bool { return integer(p["vmid"]) == integer(f["vmid"]) }))}
	if !dry {
		e.Call(D{"op": "backup_remove", "machine": f, "volid": f["backup_volid"]})
		e.removeApps(filter(e.S.Objects("apps", n), func(x D) bool { return integer(x["vmid"]) == integer(f["vmid"]) }))
		e.Transaction(func(tx *Execution) {
			tx.forgetMachine(n, f)
			tx.S.Remove("frozen", f["vmid"])
		})
		e.Reconcile()
	}
	q := e.Quota(t)
	if dry {
		q = e.Quota(t, delta)
	}
	r := D{"dry_run": dry, "quota_after": q}
	if !dry {
		r["deleted"] = D{"name": f["name"], "state": "deleted"}
	}
	return r
}
