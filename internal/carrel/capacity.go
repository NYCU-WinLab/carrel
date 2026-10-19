package carrel

import (
	"context"
	"time"
)

const GiB = 1024 * 1024 * 1024
const MiB = 1024 * 1024

func summarize(inventory D, reservations, snapshots []D, at time.Time) D {
	status, storage := obj(inventory["status"]), obj(inventory["storage"])
	byID := map[int]D{}
	cpu, memory := 0.0, 0.0
	for _, g := range dicts(inventory["resources"]) {
		if (g["type"] != "qemu" && g["type"] != "lxc") || boolean(g["template"]) || num(g["template"]) == 1 {
			continue
		}
		if inventory["node"] != nil && g["node"] != inventory["node"] {
			continue
		}
		byID[integer(g["vmid"])] = g
		if g["status"] == "running" {
			cpu += num(g["maxcpu"])
			memory += num(g["maxmem"])
		}
	}
	disk := num(inventory["disk_committed_bytes"])
	source := "all_local_lvm_volumes"
	if inventory["disk_committed_bytes"] == nil {
		source = "guest_primary_disks_only"
		for _, g := range byID {
			disk += num(g["maxdisk"])
		}
	}
	for _, m := range reservations {
		g := byID[integer(m["vmid"])]
		running := D{}
		if g["status"] == "running" {
			running = g
		}
		cpu += max(0, num(m["cpu"])-num(running["maxcpu"]))
		memory += max(0, num(m["memory_mb"])*MiB-num(running["maxmem"]))
		disk += max(0, num(m["disk_gb"])*GiB-num(g["maxdisk"]))
	}
	reserved := 0.0
	for _, s := range snapshots {
		reserved += num(s["disk_gb"]) * GiB
	}
	disk += reserved
	info := obj(status["cpuinfo"])
	mem := obj(status["memory"])
	totalMem, totalDisk := num(mem["total"]), num(storage["total"])
	cpuLimit := num(info["cpus"]) * 4
	memLimit := max(0, (totalMem-8*GiB)*0.9)
	diskLimit := totalDisk * 1.5
	metadata := obj(inventory["thin_pool"])["metadata_fraction"]
	blocked := num(storage["used"]) > totalDisk*0.8 || num(metadata) >= 0.8
	diskRemaining := max(0, diskLimit-disk) / GiB
	if blocked {
		diskRemaining = 0
	}
	var cores, usedMem, freeMem any
	if num(info["cores"]) > 0 {
		cores = num(info["cores"]) * num(fallback(info, "sockets", 1))
	}
	if mem["used"] != nil {
		usedMem = num(mem["used"]) / GiB
		freeMem = (totalMem - num(mem["used"])) / GiB
	}
	return D{"checked_at": at.UTC().Format(time.RFC3339Nano), "scope": "carrel01; shared with infrastructure and other tenants", "units": D{"memory": "GiB", "disk": "GiB", "cpu_utilization": "fraction"}, "physical": D{"cpu": D{"logical_cpus": info["cpus"], "cores": cores, "utilization": status["cpu"]}, "memory": D{"total": totalMem / GiB, "used": usedMem, "free": freeMem}, "disk": D{"storage": storageID(inventory), "total": totalDisk / GiB, "used": num(storage["used"]) / GiB, "free": (totalDisk - num(storage["used"])) / GiB, "metadata_fraction": metadata, "snapshot_reserved_gib": reserved / GiB}}, "allocatable": D{"vcpu": D{"limit": cpuLimit, "committed": cpu, "remaining": max(0, cpuLimit-cpu)}, "memory_gib": D{"limit": memLimit / GiB, "committed": memory / GiB, "remaining": max(0, memLimit-memory) / GiB}, "disk_gib": D{"limit": diskLimit / GiB, "committed": disk / GiB, "remaining": diskRemaining}}, "policy": D{"cpu_overcommit": 4, "memory_reserve_gib": 8, "memory_fraction": 0.9, "disk_overcommit": 1.5, "disk_usage_ceiling": 0.8, "snapshot_headroom_gib": max(0, totalDisk*0.8-num(storage["used"])-reserved) / GiB, "storage_admission_blocked": blocked, "disk_accounting": source, "cpu_memory_accounting": "running unmanaged guests plus all allocated Carrel machines (including stopped)", "tenant_quotas_apply_separately": true, "stopped_machines_retain_capacity": true, "cpu_is_shared": true, "quota_is_a_ceiling_not_a_capacity_reservation": true, "reserves_capacity": false}, "gpu": D{"allocation_supported": false, "inventory": "unknown"}}
}
func (e *Execution) Capacity(proposed D, cached bool) D {
	reservations := e.S.Objects("machines")
	if proposed != nil {
		reservations = filter(reservations, func(m D) bool { return integer(m["vmid"]) != integer(proposed["vmid"]) })
		reservations = append(reservations, proposed)
	}
	var inventory any
	at := time.Now()
	if cached {
		var err error
		inventory, at, err = e.P.inventory.Get(e.Ctx, 2*time.Second, func(ctx context.Context) (any, error) {
			return e.P.Backend.Call(ctx, D{"op": "inventory"}, "carrel-node")
		})
		must(err)
	} else {
		inventory = e.Call(D{"op": "inventory"})
		at = time.Now()
	}
	return summarize(obj(inventory), reservations, e.S.Objects("snapshots"), at)
}
func (e *Execution) Admission(cpu, memory, disk float64, proposed D, snapshot bool) D {
	c := e.Capacity(proposed, false)
	for k, amount := range map[string]float64{"vcpu": cpu, "memory_gib": memory / 1024, "disk_gib": disk} {
		allocation := obj(obj(c["allocatable"])[k])
		if amount+num(allocation["committed"]) > num(allocation["limit"]) {
			fail("capacity_exhausted", "Node admission limit", D{"dimension": k, "requested": amount, "remaining": allocation["remaining"]})
		}
	}
	policy := obj(c["policy"])
	if snapshot && disk > num(policy["snapshot_headroom_gib"]) {
		fail("capacity_exhausted", "Snapshot worst-case reservation exceeds safe physical headroom")
	}
	growing := disk > 0
	if proposed != nil {
		old := e.S.Get("machines", str(proposed["vmid"]))
		growing = growing || num(proposed["disk_gb"]) > num(old["disk_gb"])
	}
	if growing && boolean(policy["storage_admission_blocked"]) {
		fail("capacity_exhausted", "Storage usage exceeds admission ceiling")
	}
	return D{"accepted": true, "checked_at": c["checked_at"], "reserved": false}
}

// storageID names the node's guest storage; inventories from nodes that predate
// the per-site setting report none and use local-lvm.
func storageID(inventory D) string {
	if id, ok := inventory["storage_id"].(string); ok && id != "" {
		return id
	}
	return "local-lvm"
}
