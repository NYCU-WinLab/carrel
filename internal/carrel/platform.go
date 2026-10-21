package carrel

import (
	"context"
	_ "embed"
	"fmt"
	"maps"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

//go:embed contract.json
var contractJSON string
var Contract = decode(contractJSON)
var Units = D{"cpu": "vCPU", "vcpu": "vCPU", "memory_mb": "MiB", "swap_mb": "MiB", "disk_gb": "GiB", "snapshot_gb": "GiB"}
var reservedLabels = []string{"carrel", "www", "auth", "mail", "admin", "api", "mcp", "status", "internal"}

func named(group, name string) bool { return contains(Contract[group], name) }
func normalizeSlug(v string) string {
	return strings.Trim(regexp.MustCompile(`-+`).ReplaceAllString(strings.NewReplacer(".", "-", "_", "-").Replace(strings.ToLower(v)), "-"), "-")
}
func slug(v string) string {
	v = normalizeSlug(v)
	if !matches(`^[a-z][a-z0-9-]{0,31}$`, v) || contains(reservedLabels, v) {
		fail("conflict", "Username requires an administrator-assigned tenant alias")
	}
	return v
}
func validateKeys(keys any) {
	ks := arr(keys)
	if len(ks) < 1 || len(ks) > 20 {
		fail("invalid", "Supply 1 to 20 SSH public keys")
	}
	for _, k := range ks {
		if len(str(k)) > 16000 || !matches(`^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp[0-9]+) [A-Za-z0-9+/=]+( [^\r\n]*)?$`, str(k)) {
			fail("invalid", "Only SSH public keys are accepted")
		}
	}
}

type Platform struct {
	Store              *Store
	Backend            Backend
	Config             D
	HTTP               *http.Client
	writer             sync.Mutex
	certificates       sync.Mutex
	registration       sync.Mutex
	delivered          atomic.Value
	inventoryMu        sync.Mutex
	inventories        map[string]*ObservationCache
	Operations         *Operations
	ctx                context.Context
	cancel             context.CancelFunc
	wg                 sync.WaitGroup
	reportMu           sync.Mutex
	reports            map[int]chan struct{}
	uploadMu           sync.Mutex
	uploads            map[string]int64
	sshProbe           func(context.Context, D) bool
	serviceProbe       func(context.Context, D) bool
	certificatePrepare func(D) D
	// issue and lookupTXT replace Let's Encrypt and DNS in tests.
	issue     func(context.Context, string) ([]byte, []byte, error)
	lookupTXT func(context.Context, string) ([]string, error)
}
type Execution struct {
	P                   *Platform
	S                   *Store
	Ctx                 context.Context
	Op                  D
	publicationPrepared bool
	placement           nodeRef
}

func NewPlatform(s *Store, b Backend, c D) *Platform {
	ctx, cancel := context.WithCancel(context.Background())
	p := &Platform{Store: s, Backend: b, Config: c, HTTP: &http.Client{Timeout: 20 * time.Second}, ctx: ctx, cancel: cancel, reports: map[int]chan struct{}{}}
	p.Operations = NewOperations(p)
	return p
}
func (p *Platform) execution(ctx context.Context) *Execution {
	return &Execution{P: p, S: p.Store, Ctx: ctx}
}
func (e *Execution) Put(kind string, id any, n int, value any) {
	v, ok := value.(D)
	if !ok {
		v = decode(string(encoded(value)))
	}
	if e.Op != nil && kind != "operations" && kind != "guest_reports" && kind != "requests" && kind != "certificates" {
		old := e.S.Get(kind, str(id))
		if old == nil {
			v = merge(v, D{"operation_id": e.Op["id"]})
		} else if old["operation_id"] != nil {
			v = merge(D{"operation_id": old["operation_id"]}, v)
		}
	}
	e.S.Put(kind, id, n, v)
}

// Call asks a node adapter. Machine requests go to the machine's node; other
// requests without a target go to the first node.
func (e *Execution) Call(r D, target ...string) any {
	to := e.P.Nodes()[0].Target
	if len(target) > 0 {
		to = target[0]
	} else if m, ok := r["machine"].(map[string]any); ok {
		to = e.P.nodeOf(m).Target
	}
	if e.Op != nil && (r["op"] == "create" || r["op"] == "action") {
		// The files a start carries are not part of what it asks for.
		identity := without(r, "machine", "cloud_init")
		identity["vmid"] = obj(r["machine"])["vmid"]
		r = merge(r, D{"request_id": digest(string(encoded([]any{e.Op["id"], e.Op["generation"], to, identity})))})
	}
	ctx := e.Ctx
	if e.Op != nil {
		ctx = context.WithValue(ctx, operationLogKey{}, e.Op["id"])
	}
	v, err := e.P.Backend.Call(ctx, r, to)
	must(err)
	return v
}
func (e *Execution) Transaction(f func(*Execution)) {
	e.S.Transaction(func(s *Store) { child := *e; child.S = s; f(&child) })
}
func subjects(w D) [][2]string {
	out := [][2]string{{"user:" + str(w["sub"]), str(w["username"])}}
	for _, v := range arr(w["projects"]) {
		s := str(v)
		out = append(out, [2]string{s, strings.TrimPrefix(s, "winlab-projects/")})
	}
	return out
}
func (e *Execution) Register(w D, name string, overview bool) []D {
	e.P.registration.Lock()
	defer e.P.registration.Unlock()
	ss := subjects(w)
	if !overview {
		if name == "" {
			ss = ss[:1]
		} else {
			for _, s := range ss {
				if t := e.S.Tenant(s[0]); t != nil && t["slug"] == name {
					return []D{}
				}
			}
			wanted := [][2]string{}
			for _, s := range ss {
				if normalizeSlug(s[1]) == name {
					wanted = append(wanted, s)
				}
			}
			ss = wanted
			if len(ss) == 0 {
				fail("forbidden", "Tenant is not in your current Keycloak memberships")
			}
		}
	}
	missing := [][2]string{}
	for _, s := range ss {
		if e.S.Tenant(s[0]) == nil {
			missing = append(missing, s)
		}
	}
	if len(missing) == 0 {
		return []D{}
	}
	var reserved map[string]bool
	err := attempt(func() { reserved = e.Reserved() })
	problems := []D{}
	if err != nil {
		if !overview {
			panic(err)
		}
		for _, s := range missing {
			problems = append(problems, D{"name": s[1], "code": "registration_unavailable"})
		}
		return problems
	}
	for _, t := range e.S.Tenants() {
		reserved[str(t["slug"])] = true
	}
	for _, s := range missing {
		err := attempt(func() {
			label := slug(s[1])
			if reserved[label] {
				fail("conflict", "Tenant slug is already owned; administrator alias required")
			}
			t := e.S.Register(s[0], label)
			reserved[label] = true
			e.S.Log(str(w["sub"]), t["n"], "tenant_register", D{}, "ok")
		})
		if err != nil {
			if !overview {
				panic(err)
			}
			problems = append(problems, merge(D{"name": s[1]}, obj(failureResult(err)["error"])))
		}
	}
	return problems
}
func (e *Execution) Tenant(w D, name string) D {
	for _, s := range subjects(w) {
		t := e.S.Tenant(s[0])
		if t != nil && ((name == "" && s[0] == "user:"+str(w["sub"])) || name == str(t["slug"])) {
			return t
		}
	}
	fail("forbidden", "Tenant is not registered or is not in your current Keycloak memberships")
	return nil
}
func (e *Execution) Machine(t D, ref any) D {
	m := find(e.S.Objects("machines", integer(t["n"])), func(m D) bool { return str(m["vmid"]) == str(ref) || str(m["name"]) == str(ref) })
	if m == nil {
		fail("not_found", "Machine not found in this tenant")
	}
	return m
}
func (e *Execution) RequireActive(n int) {
	t := e.S.TenantN(n)
	if t == nil || t["status"] != "active" {
		fail("forbidden", "Tenant is suspended or suspension is pending")
	}
}
func (e *Execution) Usage(t D) D {
	n := integer(t["n"])
	used := D{}
	for k := range DefaultQuota {
		used[k] = 0
	}
	for _, m := range e.S.Objects("machines", n) {
		for k, v := range (D{"vcpu": m["cpu"], "memory_mb": m["memory_mb"], "disk_gb": m["disk_gb"], "machines": 1, "ips": 1}) {
			used[k] = num(used[k]) + num(v)
		}
	}
	for kind, dim := range map[string]string{"ports": "public_ports", "domains": "domains", "networks": "networks", "snapshots": "snapshots"} {
		used[dim] = len(e.S.Objects(kind, n))
	}
	for _, s := range e.snapshots(n) {
		used["snapshot_gb"] = num(used["snapshot_gb"]) + float64(s.DiskGB)
	}
	return used
}
func (e *Execution) Quota(t D, delta ...D) D {
	used := without(e.Usage(t), "images_gb")
	limit := without(obj(t["quota"]), "images_gb")
	d := D{}
	if len(delta) > 0 && delta[0] != nil {
		d = delta[0]
	}
	for k, v := range d {
		used[k] = num(used[k]) + num(v)
	}
	remaining := D{}
	over := []string{}
	violations := []D{}
	// Sorted: the first violation is the error's headline.
	for _, k := range slices.Sorted(maps.Keys(used)) {
		v := used[k]
		remaining[k] = num(limit[k]) - num(v)
		if num(v) > num(limit[k]) {
			over = append(over, k)
			if len(delta) > 0 && delta[0] != nil && (len(d) == 0 || num(d[k]) > 0) {
				violations = append(violations, D{"dimension": k, "used": v, "limit": limit[k]})
			}
		}
	}
	result := D{"used": used, "limit": limit, "remaining": remaining, "units": Units, "over_limit": over}
	if len(violations) > 0 {
		fail("quota_exceeded", "Tenant quota would be exceeded", merge(violations[0], D{"violations": violations, "quota_after": result}))
	}
	return result
}
func (e *Execution) SnapshotUsage(t D) D {
	if u, ok := rowOf[storageUsage](e.S, "storage_usage", str(t["n"])); ok {
		return D{"accounting": u.Accounting, "available": u.Available, "retained_snapshot_bytes": u.RetainedSnapshotBytes, "sampled_at": u.SampledAt, "unique_total_bytes": u.UniqueTotalBytes}
	}
	return D{"available": false, "retained_snapshot_bytes": nil, "accounting": "pending_sample; snapshot_gb reserves worst-case size"}
}

const maxBootstrapArgumentBytes = 64 * 1024

func validateBootstrapArguments(tool string, args D) {
	var machines []D
	switch tool {
	case "machine_create":
		machines = []D{args}
	case "deployment_plan", "deployment_apply":
		machines = dicts(args["machines"])
	default:
		return
	}
	for _, machine := range machines {
		for commandIndex, command := range arr(machine["runcmd"]) {
			for argumentIndex, argument := range arr(command) {
				if size := len(str(argument)); size > maxBootstrapArgumentBytes {
					fail("invalid", "runcmd argument exceeds 65536 UTF-8 bytes; transfer larger files over SSH after creation", D{"machine": machine["name"], "command_index": commandIndex, "argument_index": argumentIndex, "actual_bytes": size, "max_bytes": maxBootstrapArgumentBytes})
				}
			}
		}
	}
}

func (e *Execution) MachineSpec(t, a D, dry bool) D {
	if find(e.S.Objects("machines", integer(t["n"])), func(m D) bool { return m["name"] == a["name"] }) != nil {
		fail("conflict", "Machine name is already allocated", D{"recovery": "revise_request", "machine": a["name"]})
	}
	if a["iso"] != nil {
		return e.ISOMachineSpec(t, a)
	}
	kind := textAt(a, "kind", "vm")
	defaultImage := find(dicts(Contract["images"]), func(i D) bool { return i["kind"] == kind && boolean(i["default"]) })
	image := textAt(a, "image", str(defaultImage["name"]))
	tenantImage := strings.HasPrefix(image, "tenant:")
	if tenantImage {
		// Sized and set up like the minimal image; the disk comes from the import.
		image = "debian-13-minimal"
	}
	installed := find(dicts(Contract["images"]), func(i D) bool { return i["name"] == image && i["kind"] == kind })
	if installed == nil {
		fail("invalid", "Image is not available")
	}
	spec := merge(obj(obj(Contract["sizes"])[textAt(a, "size", textAt(installed, "default_size", "tiny"))]), pick(a, "cpu", "memory_mb", "disk_gb"))
	keys := arr(a["ssh_keys"])
	if len(keys) == 0 {
		for _, k := range rowsOf[sshKey](e.S, "keys", integer(t["n"])) {
			keys = append(keys, k.Key)
		}
	}
	if (len(keys) > 0 || !dry) && !(tenantImage && e.tenantImageServesPorts(t, a)) {
		validateKeys(keys)
	}
	if a["public_ssh"] == false && !e.jumpEnabled() && !(tenantImage && e.tenantImageServesPorts(t, a)) {
		fail("invalid", "This site has no SSH jump host; every machine needs a public SSH port", D{"recovery": "revise_request"})
	}
	if kind == "ct" && (boolean(a["nested_virt"]) || len(arr(a["packages"])) > 0 || len(arr(a["runcmd"])) > 0 || len(arr(a["health_checks"])) > 0) {
		fail("invalid", "Use a VM for nested virtualization or cloud-init commands")
	}
	swap := 0
	if kind == "vm" {
		swap = 1024
	}
	var token any
	if !dry {
		token = random(32)
	}
	m := merge(spec, D{"name": a["name"], "kind": kind, "image": image, "ssh_keys": keys, "nested_virt": boolean(a["nested_virt"]), "swap_mb": intAt(a, "swap_mb", swap), "packages": arr(a["packages"]), "runcmd": arr(a["runcmd"]), "health_checks": arr(a["health_checks"]), "network_access": textAt(a, "network_access", "tenant"), "readiness_token": token, "guest_management": 1, "nics": []D{}})
	if a["public_ssh"] == false {
		// Reached through the jump host only (issue #98).
		m["public_ssh"] = false
	}
	if tenantImage {
		m = e.ImportedMachineSpec(t, a, m)
	} else if a["user_data"] != nil {
		fail("invalid", "user_data applies only to an image imported with ports", D{"recovery": "revise_request"})
	}
	return m
}
func machineDelta(m D) D {
	ports := 1
	if m["public_ssh"] == false {
		ports = 0
	}
	return D{"vcpu": m["cpu"], "memory_mb": m["memory_mb"], "disk_gb": m["disk_gb"], "machines": 1, "ips": 1, "public_ports": ports}
}
func plannedMachine(m D) D {
	req := []string{}
	if len(arr(m["ssh_keys"])) == 0 && !unmanaged(m) {
		req = append(req, "ssh_public_key")
	}
	return merge(pick(m, "name", "kind", "image", "cpu", "memory_mb", "disk_gb", "swap_mb", "nested_virt", "packages", "health_checks", "network_access"), D{"state": "planned", "reserved": false, "requirements": req})
}
func mutationResult(before, result D, dry bool) D {
	after := obj(fallback(result, "quota_after", before))
	delta, ld := D{}, D{}
	for k, v := range obj(before["used"]) {
		if n := num(obj(after["used"])[k]) - num(v); n != 0 {
			delta[k] = n
		}
	}
	for k, v := range obj(before["limit"]) {
		if n := num(obj(after["limit"])[k]) - num(v); n != 0 {
			ld[k] = n
		}
	}
	result = merge(result, D{"quota_before": before, "quota_after": after, "delta": delta, "dry_run": dry})
	if len(ld) > 0 {
		result["limit_delta"] = ld
	}
	if dry {
		result = merge(result, D{"state": "planned", "reserved": false, "resource_changes": false})
		result["requirements"] = fallback(result, "requirements", []any{})
		result["ready_to_apply"] = fallback(result, "ready_to_apply", len(arr(result["requirements"])) == 0)
	}
	return result
}
func (e *Execution) AllocatePort(t D) int {
	n := integer(t["n"])
	used := map[int]bool{}
	for _, p := range e.ports(n) {
		used[p.PublicPort] = true
	}
	for p := 20000 + n*10; p < 20010+n*10; p++ {
		if !used[p] {
			return p
		}
	}
	fail("quota_exceeded", "Public port block is full", D{"dimension": "public_ports"})
	return 0
}
func (e *Execution) PublicMachine(m D, ports []portGrant) D {
	safe := without(m, "ssh_keys", "runcmd", "user_data", "mac", "host", "tenant_n", "resize_from", "readiness_token", "access_operation", "network_configured_at", "node")
	report := e.S.guestReport(m["vmid"])
	if m["kind"] == "ct" && m["state"] == "ready" {
		report.InitializationStatus, report.ApplicationStatus = "complete", "not_checked"
	}
	safe["readiness"] = D{"ssh_ready": boolean(m["ssh_ready"]), "initialization_status": or(report.InitializationStatus, "unknown"), "application_status": or(report.ApplicationStatus, "not_checked"), "checks": orEmpty(report.Checks), "reported_at": optional(report.ReportedAt), "private_interfaces": orEmpty(report.Interfaces), "failed_step": optional(report.FailedStep)}
	presentReadiness(safe, report)
	allowed := []D{}
	for _, p := range e.peers(integer(m["tenant_n"])) {
		if p.Target == m["ip"] && p.State != "deleting" {
			g := e.PublicGrant("peers", p.D(), integer(m["tenant_n"]))
			allowed = append(allowed, D{"id": p.ID, "from": fallback(g, "from_machine", p.Source), "from_tenant": g["from_tenant"], "port": p.Port, "protocol": p.protocol()})
		}
	}
	// network_access filters the primary NIC only; private NICs are the
	// member's own unfiltered segments (issue #75).
	safe["access"] = D{"inbound": textAt(m, "network_access", "tenant"), "private_nics": "unfiltered_experiment_networks", "allowed_connections": allowed}
	if unmanaged(m) {
		safe["install"] = installInfo(m)
	}
	nics := []D{}
	for _, nic := range dicts(m["nics"]) {
		entry := clone(nic)
		if network := e.S.Get("networks", str(nic["network"])); network != nil {
			entry["network_name"] = network["name"]
		}
		nics = append(nics, entry)
	}
	safe["nics"] = nics
	if ports := servicePortsOf(m); len(ports) > 0 {
		// No SSH (issue #94): its ports, forwarded through the jump host.
		if e.jumpEnabled() {
			forwards := ""
			for _, p := range ports {
				forwards += fmt.Sprintf(" -L %d:%s:%d", p, str(m["ip"]), p)
			}
			safe["tunnel"] = "ssh -N" + forwards + " jump@carrel.winlab.tw"
		}
		return safe
	}
	var ssh *portGrant
	for i, p := range ports {
		if p.VMID == integer(m["vmid"]) && p.Port == 22 && p.Proto == "tcp" {
			ssh = &ports[i]
			break
		}
	}
	user := "user"
	if m["kind"] == "ct" {
		user = "root"
	}
	t := e.S.TenantN(integer(m["tenant_n"]))
	alias := str(m["name"]) + "." + str(t["slug"])
	if ssh != nil {
		safe["ssh"] = fmt.Sprintf("ssh -p %d %s@carrel.winlab.tw", ssh.PublicPort, user)
		safe["ssh_short"] = "ssh " + alias
		safe["ssh_config"] = fmt.Sprintf("Host %s %s.winlab.tw\n  HostName carrel.winlab.tw\n  User %s\n  Port %d\n", alias, alias, user, ssh.PublicPort)
		safe["ssh_short_requires"] = "Install ssh_config on the connecting client once; this is an SSH alias, not a DNS route."
	}
	if e.jumpEnabled() {
		// Through the platform jump host (issue #98): no public port needed.
		jump := fmt.Sprintf("ssh -J jump@carrel.winlab.tw %s@%s", user, str(m["ip"]))
		safe["ssh_jump"] = jump
		if ssh == nil {
			safe["ssh"] = jump
			safe["ssh_short"] = "ssh " + alias
			safe["ssh_config"] = fmt.Sprintf("Host %s %s.winlab.tw\n  HostName %s\n  User %s\n  ProxyJump jump@carrel.winlab.tw\n", alias, alias, str(m["ip"]), user)
			safe["ssh_short_requires"] = "Install ssh_config on the connecting client once; this is an SSH alias, not a DNS route."
		}
	}
	return safe
}
