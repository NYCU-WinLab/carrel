package carrel

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"
)

// Tenant images and ISOs (PLAN 7.8). The fetch container downloads a file;
// the first exit node checks it and moves it onto the site's shared storage
// as carrel-tNNN-<name>-<12 hex of its SHA-256>.<iso|qcow2|raw>. Its size
// counts against images_gb, together with app releases (7.9).

const maxImageBytes = 20 << 30

var sha256Hex = regexp.MustCompile(`^[a-f0-9]{64}$`)

type imageRecord struct {
	CreatedAt   int64  `json:"created_at"`
	ID          string `json:"id"`
	Job         string `json:"job"`
	Kind        string `json:"kind"`
	Name        string `json:"name"`
	OperationID string `json:"operation_id,omitempty"`
	// Ports marks an image that runs no SSH and no cloud-config, such as
	// Talos (issue #94): its VMs are ready when the first port answers,
	// and the jump host forwards these ports instead of SSH.
	Ports       []int  `json:"ports,omitempty"`
	SHA256      string `json:"sha256"`
	Size        int64  `json:"size"`
	State       string `json:"state"`
	TenantN     int    `json:"tenant_n"`
	URL         string `json:"url"`
	VirtualSize int64  `json:"virtual_size,omitempty"`
	Volume      string `json:"volume,omitempty"`
}

func (r imageRecord) public() D {
	out := D{"name": r.Name, "kind": r.Kind, "sha256": r.SHA256, "size_bytes": r.Size, "state": r.State, "volume": orNil(r.Volume), "created_at": r.CreatedAt}
	if r.VirtualSize > 0 {
		out["virtual_size_bytes"] = r.VirtualSize
	}
	if len(r.Ports) > 0 {
		out["ports"] = r.Ports
	}
	return out
}

func (r imageRecord) file() string {
	ext := r.Kind
	return fmt.Sprintf("carrel-t%03d-%s-%s.%s", r.TenantN, r.Name, r.SHA256[:12], ext)
}

func (e *Execution) images(n int) []imageRecord { return rowsOf[imageRecord](e.S, "images", n) }

// imageBytes is what a tenant's images hold, a download in flight counted
// at the space it reserved.
func (e *Execution) imageBytes(n int) float64 {
	total := 0.0
	for _, r := range e.images(n) {
		total += float64(r.Size)
	}
	return total
}

func (e *Execution) imageUsage(t D) D {
	n := integer(t["n"])
	used := e.storedBytes(n) + e.imageBytes(n)
	return D{"used_gib": used / GiB, "limit_gib": obj(t["quota"])["images_gb"]}
}

func (e *Execution) ImageAction(tool string, a, t D) D {
	n := integer(t["n"])
	switch tool {
	case "image_list":
		out := []D{}
		for _, r := range e.images(n) {
			out = append(out, r.public())
		}
		return D{"images": out, "images_gb": e.imageUsage(t)}
	case "image_delete":
		r, ok := e.imageNamed(n, str(a["name"]))
		if !ok {
			fail("not_found", "Image not found in this tenant")
		}
		if a["confirm"] != r.Name {
			fail("invalid", "confirm must equal the image name")
		}
		if r.State != "ready" {
			fail("conflict", "The image is still being imported", D{"recovery": "resolve_prerequisite"})
		}
		for _, m := range e.S.Objects("machines", n) {
			if m["iso"] == r.Name && m["iso_volume"] != nil {
				fail("conflict", "Eject the ISO from "+str(m["name"])+" first (machine_media)", D{"recovery": "resolve_prerequisite"})
			}
			// A VM still being created imports its disk from the image.
			if m["import_volume"] == r.Volume && m["state"] == "provisioning" {
				fail("conflict", str(m["name"])+" is being created from this image; wait for it", D{"recovery": "resolve_prerequisite"})
			}
		}
		// A queued creation names the image before it has a machine record.
		if e.imageWanted(n, r.Name) {
			fail("conflict", "A queued machine creation uses this image; wait for it", D{"recovery": "resolve_prerequisite"})
		}
		if boolean(a["dry_run"]) {
			return D{"image": r.public(), "dry_run": true, "images_gb": e.imageUsage(t)}
		}
		e.Call(D{"op": "image_delete", "tenant_n": n, "volume": r.file(), "kind": imageStorageKind(r.Kind)}, e.P.Nodes()[0].Target)
		e.S.Remove("images", r.ID)
		r.State = "deleted"
		return D{"image": r.public(), "dry_run": false, "images_gb": e.imageUsage(t)}
	}
	fail("invalid", "Unknown image tool")
	return nil
}

// imageWanted reports whether an active operation of the tenant creates
// machines from the named image or ISO.
func (e *Execution) imageWanted(n int, name string) bool {
	for _, op := range e.S.ActiveOperations(n) {
		args := obj(op["args"])
		specs := []D{args}
		if op["tool"] == "deployment_apply" {
			specs = dicts(args["machines"])
		} else if op["tool"] != "machine_create" {
			continue
		}
		for _, a := range specs {
			if a["image"] == "tenant:"+name || a["iso"] == name {
				return true
			}
		}
	}
	return false
}

func imageStorageKind(kind string) string {
	if kind == "iso" {
		return "iso"
	}
	return "import"
}

func (e *Execution) imageNamed(n int, name string) (imageRecord, bool) {
	for _, r := range e.images(n) {
		if r.Name == name {
			return r, true
		}
	}
	return imageRecord{}, false
}

// tenantImageServesPorts reports whether a["image"] names one of the
// tenant's images imported with ports (no SSH, no saved keys needed).
func (e *Execution) tenantImageServesPorts(t, a D) bool {
	r, ok := e.imageNamed(integer(t["n"]), strings.TrimPrefix(str(a["image"]), "tenant:"))
	return ok && len(r.Ports) > 0
}

// PlanImport checks and reserves an import under the writer lock.
func (e *Execution) PlanImport(tool string, a, t D) D {
	n := integer(t["n"])
	if plan := obj(obj(e.Op)["import"]); plan["id"] != nil {
		if r, ok := rowOf[imageRecord](e.S, "images", str(plan["id"])); ok {
			return D{"image": r.public()}
		}
	}
	if !e.P.Config.Fetch {
		fail("invalid", "This site has no image fetcher", D{"recovery": "revise_request"})
	}
	kind := "iso"
	if tool == "image_import" {
		kind = textAt(a, "format", "qcow2")
		if kind != "qcow2" && kind != "raw" {
			fail("invalid", "format is qcow2 or raw")
		}
	}
	var ports []int
	if tool == "image_import" {
		ports = servicePorts(a["ports"])
	}
	name, url, sum := str(a["name"]), str(a["url"]), str(a["sha256"])
	if !labelPattern.MatchString(name) {
		fail("invalid", "Name must be a lowercase label")
	}
	if !sha256Hex.MatchString(sum) {
		fail("invalid", "sha256 must be 64 lowercase hex digits")
	}
	if _, taken := e.imageNamed(n, name); taken {
		fail("conflict", "An image with this name exists", D{"recovery": "revise_request"})
	}
	// One import per tenant, 3 per site: the rest wait for a slot.
	if e.Op != nil {
		mine, all := 0, 0
		for _, other := range e.S.ActiveOperations() {
			if other["id"] == e.Op["id"] || other["import"] == nil {
				continue
			}
			all++
			if integer(other["tenant_n"]) == n {
				mine++
			}
		}
		if mine >= 1 || all >= 3 {
			panic(Waiting{"waiting_for_import_slot", now() + 30})
		}
	}
	limit := num(obj(t["quota"])["images_gb"]) * GiB
	room := limit - e.storedBytes(n) - e.imageBytes(n)
	reserve := int64(min(float64(maxImageBytes), room))
	if reserve < 1<<20 {
		fail("quota_exceeded", "images_gb is full", D{"dimension": "images_gb", "images_gb": e.imageUsage(t), "recovery": "remove_unused"})
	}
	r := imageRecord{ID: randomID()[:16], TenantN: n, Name: name, Kind: kind, URL: url, SHA256: sum, Size: reserve, State: "fetching", Job: randomID(), CreatedAt: time.Now().Unix(), Ports: ports}
	if boolean(a["dry_run"]) {
		return D{"image": merge(r.public(), D{"state": "planned"}), "dry_run": true, "images_gb": e.imageUsage(t)}
	}
	refused := []any{}
	if ip, err := netip.ParseAddr(e.P.Config.PublicAddress); err == nil {
		refused = append(refused, ip.String()+"/32")
	}
	e.Put("images", r.ID, n, r)
	if f := attempt(func() {
		e.Call(D{"op": "fetch_start", "job": r.Job, "url": url, "sha256": sum, "max_bytes": reserve, "format": kind, "refused": refused}, e.P.Nodes()[0].Target)
	}); f != nil {
		// Nothing started, or nothing anyone tracks: the reservation goes,
		// and so does whatever the container may have begun.
		_ = attempt(func() { e.Call(D{"op": "fetch_clean", "job": r.Job}, e.P.Nodes()[0].Target) })
		e.S.Remove("images", r.ID)
		panic(f)
	}
	if e.Op != nil {
		e.Op["import"] = D{"id": r.ID}
		e.P.Operations.Save(e.Op)
	}
	return D{"image": r.public()}
}

// PerformImport waits for the download outside the writer lock, then stores
// the file. A failure removes the record and the staged file.
func (e *Execution) PerformImport() {
	if (e.Op["tool"] != "iso_import" && e.Op["tool"] != "image_import") || e.Op["import"] == nil {
		return
	}
	id := str(obj(e.Op["import"])["id"])
	r, ok := rowOf[imageRecord](e.S, "images", id)
	if !ok || r.State == "ready" {
		return
	}
	target := e.P.Nodes()[0].Target
	abandon := func(code, message string) {
		// A shutdown is not a failure: the job resumes after the restart.
		if err := e.Ctx.Err(); err != nil {
			panic(err)
		}
		_ = attempt(func() { e.Call(D{"op": "fetch_clean", "job": r.Job}, target) })
		e.P.writer.Lock()
		e.S.Remove("images", id)
		e.P.writer.Unlock()
		fail(code, message, D{"recovery": "revise_request"})
	}
	func() {
		e.P.writer.Lock()
		defer e.P.writer.Unlock()
		e.Op["phase"] = "downloading"
		e.P.Operations.Save(e.Op)
	}()
	misses := 0
	virtual := int64(0)
	for {
		var status D
		if f := attempt(func() { status = obj(e.Call(D{"op": "fetch_status", "job": r.Job}, target)) }); f != nil {
			// A node that does not answer once is not a failed download.
			if misses++; misses >= 6 || e.Ctx.Err() != nil {
				panic(f)
			}
			status = D{"state": "running"}
		} else {
			misses = 0
		}
		if status["state"] == "done" {
			virtual = int64(num(obj(status["result"])["virtual_size"]))
			if r.Kind != "iso" && virtual <= 0 {
				abandon("image_refused", "The fetcher did not report the image's virtual size")
			}
			break
		}
		if status["state"] == "failed" {
			res := obj(status["result"])
			abandon(textAt(res, "code", "fetch_failed"), textAt(res, "error", "The download failed"))
		}
		select {
		case <-e.Ctx.Done():
			panic(e.Ctx.Err())
		case <-time.After(5 * time.Second):
		}
	}
	stored := D{}
	if f := attempt(func() {
		stored = obj(e.Call(D{"op": "fetch_store", "job": r.Job, "volume": r.file(), "kind": imageStorageKind(r.Kind), "sha256": r.SHA256, "tenant_n": r.TenantN, "max_bytes": r.Size}, target))
	}); f != nil {
		abandon("backend_unavailable", "The image could not be stored")
	}
	e.P.writer.Lock()
	defer e.P.writer.Unlock()
	if cur, ok := rowOf[imageRecord](e.S, "images", id); ok {
		cur.State, cur.Volume, cur.VirtualSize = "ready", str(stored["volume"]), virtual
		if s := int64(num(stored["size"])); s > 0 {
			cur.Size = s
		}
		e.Put("images", cur.ID, cur.TenantN, cur)
	}
}

// FinishImport reports the stored image.
func (e *Execution) FinishImport() D {
	r, ok := rowOf[imageRecord](e.S, "images", str(obj(e.Op["import"])["id"]))
	if !ok || r.State != "ready" {
		fail("backend_unavailable", "The image was not stored", D{"recovery": "retry_infrastructure"})
	}
	return D{"image": r.public()}
}

// ISOMachineSpec is a VM that installs from one of the tenant's ISOs (PLAN
// 7.8): an empty disk, no cloud-init, no guest reports. carrel manages its
// power, network and firewall; the member installs through the console and
// ejects the ISO with machine_media.
func (e *Execution) ISOMachineSpec(t, a D) D {
	if textAt(a, "kind", "vm") != "vm" {
		fail("invalid", "Only a VM installs from an ISO")
	}
	for _, k := range []string{"image", "packages", "runcmd", "health_checks", "ssh_keys", "user_data"} {
		if a[k] != nil {
			fail("invalid", k+" does not apply to a machine installed from an ISO", D{"recovery": "revise_request"})
		}
	}
	r, ok := e.imageNamed(integer(t["n"]), str(a["iso"]))
	if !ok || r.Kind != "iso" || r.State != "ready" {
		fail("not_found", "No ready ISO with that name in this tenant; import one with iso_import")
	}
	firmware := textAt(a, "firmware", "bios")
	if boolean(a["tpm"]) && firmware != "uefi" {
		fail("invalid", "A TPM needs firmware uefi")
	}
	spec := merge(obj(obj(Contract["sizes"])[textAt(a, "size", "small")]), pick(a, "cpu", "memory_mb", "disk_gb"))
	m := merge(spec, D{"name": a["name"], "kind": "vm", "image": "iso:" + r.Name, "iso": r.Name, "iso_volume": r.Volume, "firmware": firmware, "tpm": boolean(a["tpm"]), "ssh_keys": []any{}, "nested_virt": boolean(a["nested_virt"]), "swap_mb": 0, "packages": []any{}, "runcmd": []any{}, "health_checks": []any{}, "network_access": textAt(a, "network_access", "tenant"), "guest_management": 0, "nics": []D{}})
	if a["public_ssh"] == false {
		if !e.jumpEnabled() {
			fail("invalid", "This site has no SSH jump host; every machine needs a public SSH port", D{"recovery": "revise_request"})
		}
		m["public_ssh"] = false
	}
	return m
}

// unmanaged reports a machine without guest reports: installed from an ISO,
// or booted from an image imported with ports.
func unmanaged(m D) bool { return m["guest_management"] != nil && integer(m["guest_management"]) == 0 }

// bootState is the state a machine takes when it boots: a managed guest
// initializes until it reports, one with service ports until its first port
// answers; one installed from an ISO is installing while the ISO is in, and
// ready once it is out.
func bootState(m D) string {
	if !unmanaged(m) || len(servicePortsOf(m)) > 0 {
		return "initializing"
	}
	if m["iso_volume"] != nil {
		return "installing"
	}
	return "ready"
}

// Media inserts or ejects a machine's ISO (machine_media).
func (e *Execution) Media(m, a, t D) D {
	if !unmanaged(m) || len(servicePortsOf(m)) > 0 {
		fail("invalid", "Only a machine installed from an ISO takes media")
	}
	n := integer(t["n"])
	request := D{"op": "action", "machine": m, "action": "media"}
	switch a["action"] {
	case "eject":
		delete(m, "iso_volume")
	case "insert":
		r, ok := e.imageNamed(n, str(a["iso"]))
		if !ok || r.Kind != "iso" || r.State != "ready" {
			fail("not_found", "No ready ISO with that name in this tenant")
		}
		m["iso"], m["iso_volume"] = r.Name, r.Volume
		request["iso_volume"] = r.Volume
	default:
		fail("invalid", "action is eject or insert")
	}
	if boolean(a["dry_run"]) {
		return D{"dry_run": true, "machine": e.PublicMachine(m, e.ports(n))}
	}
	e.Call(request)
	if m["power_state"] == "running" || m["state"] == "installing" || m["state"] == "ready" {
		m["state"] = bootState(m)
	}
	e.Put("machines", m["vmid"], n, m)
	return D{"dry_run": false, "machine": e.PublicMachine(m, e.ports(n))}
}

// installInfo is what an installer asks for: carrel gives no DHCP on the
// primary network, so the address is typed in.
func installInfo(m D) D {
	ip := str(m["ip"])
	gateway := ip[:len(ip)-len(ip[lastDot(ip):])] + ".1"
	return D{"iso": m["iso"], "media": map[bool]string{true: "inserted", false: "ejected"}[m["iso_volume"] != nil], "address": ip + "/24", "gateway": gateway, "dns": "10.200.0.2", "mtu": 1450, "firmware": m["firmware"]}
}

func lastDot(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '.' {
			return i
		}
	}
	return 0
}

// servicePorts validates image_import's ports: 1 to 4 distinct TCP ports,
// never 22, which these images do not serve.
func servicePorts(v any) []int {
	if v == nil {
		return nil
	}
	ps := arr(v)
	if len(ps) < 1 || len(ps) > 4 {
		fail("invalid", "ports takes 1 to 4 TCP ports", D{"recovery": "revise_request"})
	}
	out, seen := []int{}, map[int]bool{}
	for _, p := range ps {
		port, ok := p.(float64)
		if !ok || port != float64(int(port)) || port < 1 || port > 65535 || port == 22 || seen[int(port)] {
			fail("invalid", "ports are distinct TCP ports from 1 to 65535, not 22", D{"recovery": "revise_request"})
		}
		seen[int(port)] = true
		out = append(out, int(port))
	}
	return out
}

// servicePortsOf is a machine's declared ports, empty for SSH machines.
func servicePortsOf(m D) []int {
	out := []int{}
	for _, p := range arr(m["service_ports"]) {
		out = append(out, integer(p))
	}
	return out
}

// ImportedMachineSpec is a VM whose boot disk is one of the tenant's cloud
// images (image "tenant:<name>"). A managed one needs cloud-init and
// python3 in the image for keys, addresses and readiness reports. One
// imported with ports (Talos, issue #94) runs no SSH and no cloud-config:
// carrel writes its network file, passes the member's user_data unchanged
// (Talos reads it as its machine config) and probes the first port.
func (e *Execution) ImportedMachineSpec(t, a D, m D) D {
	name := strings.TrimPrefix(str(a["image"]), "tenant:")
	r, ok := e.imageNamed(integer(t["n"]), name)
	if !ok || r.Kind == "iso" || r.State != "ready" || r.VirtualSize <= 0 {
		fail("not_found", "No ready cloud image with that name in this tenant; import one with image_import")
	}
	if textAt(a, "kind", "vm") != "vm" {
		fail("invalid", "Only a VM boots a cloud image")
	}
	least := int((r.VirtualSize + GiB - 1) / GiB)
	if a["disk_gb"] != nil && integer(a["disk_gb"]) < least {
		fail("invalid", fmt.Sprintf("disk_gb must be at least the image's %d GiB", least), D{"recovery": "revise_request"})
	}
	if integer(m["disk_gb"]) < least {
		m["disk_gb"] = least
	}
	m["image"], m["import_volume"], m["import_sha256"] = "tenant:"+r.Name, r.Volume, r.SHA256
	if len(r.Ports) == 0 {
		if a["user_data"] != nil {
			fail("invalid", "user_data applies only to an image imported with ports", D{"recovery": "revise_request"})
		}
		return m
	}
	for _, k := range []string{"packages", "runcmd", "health_checks", "ssh_keys", "swap_mb"} {
		if a[k] != nil {
			fail("invalid", k+" does not apply to an image without SSH", D{"recovery": "revise_request"})
		}
	}
	if a["public_ssh"] == true {
		fail("invalid", "This image runs no SSH; reach its ports through the jump host or port_open", D{"recovery": "revise_request"})
	}
	if a["user_data"] != nil {
		if s, ok := a["user_data"].(string); !ok || len(s) > 65536 {
			fail("invalid", "user_data is a string of at most 64 KiB", D{"recovery": "revise_request"})
		}
		m["user_data"] = a["user_data"]
	}
	ports := make([]any, len(r.Ports))
	for i, p := range r.Ports {
		ports[i] = p
	}
	// Talos needs 2 GiB for a control plane: small, unless the member sized it.
	small := obj(obj(Contract["sizes"])["small"])
	for _, k := range []string{"cpu", "memory_mb"} {
		if a["size"] == nil && a[k] == nil {
			m[k] = small[k]
		}
	}
	// The tunnel needs a saved key: the jump host admits saved keys only here.
	if e.jumpEnabled() && len(rowsOf[sshKey](e.S, "keys", integer(t["n"]))) == 0 && !boolean(a["dry_run"]) {
		fail("invalid", "Save an SSH public key with ssh_key_add first: the jump host tunnel to this machine needs one", D{"recovery": "resolve_prerequisite"})
	}
	m["service_ports"], m["guest_management"], m["public_ssh"], m["swap_mb"], m["ssh_keys"] = ports, 0, false, 0, []any{}
	delete(m, "readiness_token")
	return m
}
