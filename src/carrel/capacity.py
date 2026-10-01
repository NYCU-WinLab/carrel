"""Shared admission accounting and member-safe capacity summaries."""

from datetime import UTC, datetime

MIB = 1024**2
GIB = 1024**3
UNITS = {
    "cpu": "vCPU",
    "vcpu": "vCPU",
    "memory_mb": "MiB",
    "swap_mb": "MiB",
    "disk_gb": "GiB",
    "snapshot_gb": "GiB",
}


def summarize(inventory, reservations=(), snapshots=()):
    status, storage = inventory["status"], inventory["storage"]
    guests = [
        g
        for g in inventory["resources"]
        if g.get("type") in ("qemu", "lxc")
        and not g.get("template")
        and (not inventory.get("node") or g.get("node") == inventory["node"])
    ]
    by_id = {g["vmid"]: g for g in guests if "vmid" in g}
    running = [g for g in guests if g.get("status") == "running"]
    cpu = sum(g.get("maxcpu", 0) for g in running)
    memory = sum(g.get("maxmem", 0) for g in running)
    disk = inventory.get("disk_committed_bytes")
    disk_source = "all_local_lvm_volumes"
    if disk is None:
        # Compatibility with older node adapters; never present this as complete.
        disk = sum(g.get("maxdisk", 0) for g in guests)
        disk_source = "guest_primary_disks_only"
    for m in reservations:
        guest = by_id.get(m["vmid"], {})
        # Every allocated Carrel machine retains CPU/RAM until deletion, even
        # while stopped. Subtract the running inventory to avoid double charging.
        running_guest = guest if guest.get("status") == "running" else {}
        cpu += max(0, m["cpu"] - running_guest.get("maxcpu", 0))
        memory += max(0, m["memory_mb"] * MIB - running_guest.get("maxmem", 0))
        disk += max(0, m["disk_gb"] * GIB - guest.get("maxdisk", 0))
    snapshot_reserved = sum(s["disk_gb"] * GIB for s in snapshots)
    disk += snapshot_reserved
    info = status["cpuinfo"]
    total_memory = status["memory"]["total"]
    total_disk = storage["total"]
    cpu_limit = info["cpus"] * 4
    memory_limit = max(0, (total_memory - 8 * GIB) * 0.9)
    disk_limit = total_disk * 1.5
    metadata_fraction = inventory.get("thin_pool", {}).get("metadata_fraction")
    storage_blocked = storage["used"] > total_disk * 0.8 or (metadata_fraction or 0) >= 0.8
    used_memory = status["memory"].get("used")
    return {
        "checked_at": datetime.now(UTC).isoformat(),
        "scope": "carrel01; shared with infrastructure and other tenants",
        "units": {"memory": "GiB", "disk": "GiB", "cpu_utilization": "fraction"},
        "physical": {
            "cpu": {
                "logical_cpus": info["cpus"],
                "cores": info["cores"] * info.get("sockets", 1) if info.get("cores") else None,
                "utilization": status.get("cpu"),
            },
            "memory": {
                "total": total_memory / GIB,
                "used": used_memory / GIB if used_memory is not None else None,
                "free": (total_memory - used_memory) / GIB if used_memory is not None else None,
            },
            "disk": {
                "storage": "local-lvm",
                "total": total_disk / GIB,
                "used": storage["used"] / GIB,
                "free": (total_disk - storage["used"]) / GIB,
                "metadata_fraction": metadata_fraction,
                "snapshot_reserved_gib": snapshot_reserved / GIB,
            },
        },
        "allocatable": {
            "vcpu": {"limit": cpu_limit, "committed": cpu, "remaining": max(0, cpu_limit - cpu)},
            "memory_gib": {
                "limit": memory_limit / GIB,
                "committed": memory / GIB,
                "remaining": max(0, memory_limit - memory) / GIB,
            },
            "disk_gib": {
                "limit": disk_limit / GIB,
                "committed": disk / GIB,
                "remaining": 0 if storage_blocked else max(0, disk_limit - disk) / GIB,
            },
        },
        "policy": {
            "cpu_overcommit": 4,
            "memory_reserve_gib": 8,
            "memory_fraction": 0.9,
            "disk_overcommit": 1.5,
            "disk_usage_ceiling": 0.8,
            "snapshot_headroom_gib": max(0, total_disk * 0.8 - storage["used"] - snapshot_reserved) / GIB,
            "storage_admission_blocked": storage_blocked,
            "disk_accounting": disk_source,
            "cpu_memory_accounting": "running unmanaged guests plus all allocated Carrel machines (including stopped)",
            "tenant_quotas_apply_separately": True,
            "stopped_machines_retain_capacity": True,
            "cpu_is_shared": True,
            "quota_is_a_ceiling_not_a_capacity_reservation": True,
            "reserves_capacity": False,
        },
        "gpu": {"allocation_supported": False, "inventory": "unknown"},
    }
