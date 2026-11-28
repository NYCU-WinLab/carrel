package carrel

import (
	"fmt"
	"maps"
	"math"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// machine_import (PLAN 10.6). This file holds the plan: dry_run reads the
// guest's configuration from a registered source (sources.go) and says what
// an import would do. It reserves, allocates and changes nothing on either
// side. The confirmed import is in machine_import_move.go.

// importTargetStorage is the storage the guest lands on (PLAN 10.6).
const (
	importTargetStorage = "tank"
	importTargetType    = "zfspool"
)

var (
	importDiskKey = regexp.MustCompile(`^(virtio|scsi|sata|ide)[0-9]+$|^(efidisk|tpmstate)0$|^rootfs$|^mp[0-9]+$`)
	importSize    = regexp.MustCompile(`(?:^|,)size=([0-9]+(?:\.[0-9]+)?)([KMGT]?)(?:,|$)`)
)

// importDisk is one volume of the source guest.
type importDisk struct {
	Key, Storage, Volume, Type string
	GiB                        float64
	CloudInit                  bool
}

// importSizeGiB reads a Proxmox size option such as 32G or 512M.
func importSizeGiB(options string) float64 {
	m := importSize.FindStringSubmatch(options)
	if m == nil {
		return 0
	}
	v, _ := strconv.ParseFloat(m[1], 64)
	switch m[2] {
	case "K":
		return v / (1 << 20)
	case "M":
		return v / 1024
	case "T":
		return v * 1024
	}
	return v
}

// importDisks lists the volumes of a guest configuration, with the type of the
// storage each sits on. A CD-ROM that is not the cloud-init disk is not a disk.
func importDisks(config D, storageTypes map[string]string) []importDisk {
	disks := []importDisk{}
	for _, key := range slices.Sorted(maps.Keys(config)) {
		if !importDiskKey.MatchString(key) {
			continue
		}
		value := str(config[key])
		volume, options, _ := strings.Cut(value, ",")
		storage, name, ok := strings.Cut(volume, ":")
		if !ok || volume == "none" {
			continue
		}
		cloudInit := strings.Contains(name, "cloudinit")
		if strings.Contains(options, "media=cdrom") && !cloudInit {
			continue
		}
		size := importSizeGiB(options)
		if cloudInit && size == 0 {
			size = 4.0 / 1024
		}
		disks = append(disks, importDisk{Key: key, Storage: storage, Volume: name, Type: storageTypes[storage], GiB: size, CloudInit: cloudInit})
	}
	return disks
}

// importContext is what a plan learned about the guest and the target; the
// confirmed import acts on the same facts.
type importContext struct {
	Tenant, Config, Plan                   D
	Source, SourceNode, API, Kind, TokenID string
	URL, Fingerprint                       string
	VMID, N, Slot                          int
	Running, CloudInit, Hop                bool
	Disks                                  []importDisk
	Delta                                  D
	DiskGiB, CPU, Memory                   float64
	Target                                 nodeRef
}

// MachineImport runs machine_import: dry_run plans, confirm moves the guest.
func (e *Execution) MachineImport(a, w D) D {
	if !boolean(a["dry_run"]) && !boolean(a["confirm"]) {
		fail("invalid", "Give dry_run: true to plan, or confirm: true to run the import", D{"recovery": "revise_request"})
	}
	r, c := e.importPlan(a)
	if boolean(a["dry_run"]) {
		return r
	}
	return e.importStart(a, c, r)
}

// importPlace picks the node the guest lands on. Proxmox remote migration
// puts it on the node behind import_target_endpoint, whose certificate the
// pinned fingerprint names, so with import_target_node set that node is the
// only choice; without it the plan shows where Place would put the machine.
func (e *Execution) importPlace(cpu, memory, disk float64) (nodeRef, D) {
	name := e.P.Config.ImportTargetNode
	if name == "" {
		return e.Place(cpu, memory, disk)
	}
	node, ok := e.nodeNamed(name)
	if !ok {
		fail("invalid", "import_target_node is not a configured node", D{"recovery": "contact_administrator"})
	}
	if e.drained(name) {
		fail("conflict", "The import target node is drained", D{"recovery": "resolve_prerequisite", "node": name})
	}
	var admission D
	if f := attempt(func() { admission, _ = e.admitOn(node, cpu, memory, disk, nil, false) }); f != nil {
		if failure, ok := f.(Failure); ok && obj(failure.Result["error"])["code"] == "capacity_exhausted" {
			fail("conflict", "The import target node has no room for this guest", merge(pick(obj(failure.Result["error"]), "dimension", "requested", "remaining"), D{"recovery": "resolve_prerequisite", "node": name}))
		}
		panic(f)
	}
	return node, admission
}

// importPlan reads the guest from its source and works out the import. It
// reserves, allocates and changes nothing.
func (e *Execution) importPlan(a D) (D, importContext) {
	t := find(e.S.Tenants(), func(t D) bool { return t["slug"] == a["tenant"] })
	if t == nil {
		fail("not_found", "Tenant not found", D{"recovery": "revise_request"})
	}
	if t["status"] != "active" {
		fail("forbidden", "Tenant is suspended")
	}
	name := str(a["source"])
	rec := e.S.SiteGet("source", name)
	if rec == nil {
		fail("not_found", "This source is not registered; add it with source_add", D{"recovery": "resolve_prerequisite"})
	}
	secret, _ := e.sourceSecretOf(D{}, name)
	client := sourceClient(str(rec["fingerprint"]))
	defer client.CloseIdleConnections()
	base, tokenID := str(rec["api_url"]), str(rec["token_id"])
	get := func(path string) D { return sourceGet(e.Ctx, client, base, tokenID, secret, path) }

	// Find the guest: the node and the kind come from the source.
	vmid := integer(a["guest"])
	guest := find(dicts(get("/cluster/resources?type=vm")["data"]), func(g D) bool {
		return integer(g["vmid"]) == vmid && (g["type"] == "qemu" || g["type"] == "lxc") && num(g["template"]) == 0
	})
	if guest == nil {
		fail("not_found", "The source has no such guest", D{"recovery": "revise_request"})
	}
	node, api := str(guest["node"]), str(guest["type"])
	if !matches(`^[a-zA-Z0-9][a-zA-Z0-9-]{0,62}$`, node) {
		fail("backend_unavailable", "The source did not answer as a Proxmox host", D{"component": "source", "backend_code": "source_response_invalid", "recovery": "retry_infrastructure"})
	}
	kind := "vm"
	if api == "lxc" {
		kind = "ct"
	}
	config := obj(get("/nodes/" + url.PathEscape(node) + "/" + api + "/" + strconv.Itoa(vmid) + "/config")["data"])
	storageTypes := map[string]string{}
	for _, s := range dicts(get("/storage")["data"]) {
		storageTypes[str(s["storage"])] = str(s["type"])
	}
	running := guest["status"] == "running"
	disks := importDisks(config, storageTypes)

	// What it would take: sizes, quota, the target slot. Nothing is written.
	var diskGiB float64
	volumes := []D{}
	for _, d := range disks {
		if !d.CloudInit {
			diskGiB += d.GiB
		}
		volumes = append(volumes, D{"key": d.Key, "storage": d.Storage, "storage_type": textAt(D{"t": d.Type}, "t", "unknown"), "size_gib": d.GiB, "cloud_init": d.CloudInit})
	}
	cpu := num(config["cores"])
	if cpu == 0 {
		cpu = 1
	}
	if kind == "vm" {
		cpu *= num(fallback(config, "sockets", 1))
	}
	memory := num(config["memory"])
	if memory == 0 {
		memory = 512
	}
	delta := D{"vcpu": cpu, "memory_mb": memory, "disk_gb": math.Ceil(diskGiB), "machines": 1, "ips": 1, "public_ports": 0}
	n := integer(t["n"])
	slot := e.freeSlot(t)
	target, admission := e.importPlace(cpu, memory, math.Ceil(diskGiB))

	// Which way the disks move (PLAN 10.6, storage rules).
	allZFS, hasCloudInit, offline := true, false, []string{}
	for _, d := range disks {
		hasCloudInit = hasCloudInit || d.CloudInit
		if d.Type != "zfspool" {
			allZFS = false
		}
		if !d.CloudInit {
			offline = append(offline, d.Key)
		}
	}
	path := "direct"
	if !allZFS {
		path = "directory_hop"
	}
	warnings := []string{}
	changes := []D{}
	change := func(what string, from, to any) { changes = append(changes, D{"what": what, "from": from, "to": to}) }
	if hasCloudInit {
		change("cloud-init disk", "present", "dropped; carrel writes its own")
		warnings = append(warnings, "The cloud-init disk is dropped before the move")
	}
	if !allZFS {
		warnings = append(warnings, "Not every disk is on ZFS: offline volumes land on a directory storage on the target, then move to "+importTargetStorage)
	}
	if len(offline) > 0 && path == "directory_hop" {
		warnings = append(warnings, "Offline volumes ("+strings.Join(offline, ", ")+") need a directory storage on the target")
	}
	if running {
		warnings = append(warnings, "The guest is shut down first and moves offline; a container that does not shut down is stopped, a VM is not")
	}
	change("storage", "per disk", importTargetStorage+" ("+importTargetType+")")
	net := "net0"
	netValue := str(config[net])
	change("network", netValue, "tenant primary network with firewall=1, mtu=1, security group, ipfilter and rate")
	ipKey := "ipconfig0"
	if kind == "ct" {
		ipKey = "net0"
	}
	if strings.Contains(netValue, "ip=dhcp") || strings.Contains(str(config["ipconfig0"]), "ip=dhcp") {
		change("address", "dhcp", fmt.Sprintf("10.200.%d.%d in the DHCP reservation", n, 10+slot))
	} else {
		change("address", str(config[ipKey]), fmt.Sprintf("10.200.%d.%d in %s", n, 10+slot, ipKey))
	}
	if kind == "vm" {
		change("cloud-init keys", "as found", "only the owner's keys")
		if config["cicustom"] != nil {
			change("cicustom", config["cicustom"], "carrel's vendor data")
		}
		if boolean(a["nested_virt"]) {
			change("cpu type", config["cpu"], "unchanged for nested_virt")
		} else {
			change("cpu type", fallback(config, "cpu", "default"), "x86-64-v3")
		}
	}

	r := D{
		"dry_run": true,
		"plan": D{
			"source": name, "guest": D{"vmid": vmid, "name": config["name"], "hostname": config["hostname"], "kind": kind, "node": node, "state": str(guest["status"])},
			"target": D{"vmid": 10000 + n*100 + slot, "ip": fmt.Sprintf("10.200.%d.%d", n, 10+slot), "node": target.Name, "storage": importTargetStorage, "storage_type": importTargetType, "admission": admission},
			"path":   path, "disks": volumes, "disk_gib": math.Ceil(diskGiB), "quota_delta": delta, "changes": changes, "warnings": warnings,
		},
		"quota_after":  e.Quota(t, delta),
		"requirements": []any{},
	}
	return r, importContext{Tenant: t, Config: config, Plan: obj(r["plan"]), Source: name, SourceNode: node, API: api, Kind: kind, TokenID: tokenID,
		URL: base, Fingerprint: str(rec["fingerprint"]), VMID: vmid, N: n, Slot: slot, Running: running, CloudInit: hasCloudInit, Hop: !allZFS,
		Disks: disks, Delta: delta, DiskGiB: math.Ceil(diskGiB), CPU: cpu, Memory: memory, Target: target}
}
