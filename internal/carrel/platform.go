package carrel

import (
	"context"
	_ "embed"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
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
	Store        *Store
	Backend      Backend
	Config       D
	HTTP         *http.Client
	writer       sync.Mutex
	registration sync.Mutex
	inventory    ObservationCache
	Operations   *Operations
	ctx          context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup
	reportMu     sync.Mutex
	reports      map[int]chan struct{}
	sshProbe     func(context.Context, D) bool
}
type Execution struct {
	P   *Platform
	S   *Store
	Ctx context.Context
	Op  D
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
func (e *Execution) Put(kind string, id any, n int, v D) {
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
func (e *Execution) Call(r D, target ...string) any {
	to := "carrel-node"
	if len(target) > 0 {
		to = target[0]
	}
	if e.Op != nil && (r["op"] == "create" || r["op"] == "action") {
		identity := without(r, "machine")
		identity["vmid"] = obj(r["machine"])["vmid"]
		r = merge(r, D{"request_id": digest(pythonJSON([]any{e.Op["id"], e.Op["generation"], to, identity}))})
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
	for _, s := range e.S.Objects("snapshots", n) {
		used["snapshot_gb"] = num(used["snapshot_gb"]) + num(s["disk_gb"])
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
	for k, v := range used {
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
	ss := e.S.Objects("storage_usage", integer(t["n"]))
	if len(ss) > 0 {
		return without(ss[0], "tenant_n", "operation_id")
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
		fail("conflict", "Machine name is already allocated")
	}
	spec := merge(obj(obj(Contract["sizes"])[textAt(a, "size", "small")]), pick(a, "cpu", "memory_mb", "disk_gb"))
	kind, image := textAt(a, "kind", "vm"), textAt(a, "image", "debian-13")
	if find(dicts(Contract["images"]), func(i D) bool { return i["name"] == image && i["kind"] == kind }) == nil {
		fail("invalid", "Image is not available")
	}
	keys := arr(a["ssh_keys"])
	if len(keys) == 0 {
		for _, k := range e.S.Objects("keys", integer(t["n"])) {
			keys = append(keys, k["key"])
		}
	}
	if len(keys) > 0 || !dry {
		validateKeys(keys)
	}
	if kind == "ct" && (boolean(a["nested_virt"]) || len(arr(a["packages"])) > 0 || len(arr(a["runcmd"])) > 0 || len(arr(a["health_checks"])) > 0) {
		fail("invalid", "Use a VM for nested virtualization or cloud-init commands")
	}
	swap := 0
	if kind == "vm" {
		swap = 4096
	}
	var token any
	if !dry {
		token = random(32)
	}
	return merge(spec, D{"name": a["name"], "kind": kind, "image": image, "ssh_keys": keys, "nested_virt": boolean(a["nested_virt"]), "swap_mb": intAt(a, "swap_mb", swap), "packages": arr(a["packages"]), "runcmd": arr(a["runcmd"]), "health_checks": arr(a["health_checks"]), "network_access": textAt(a, "network_access", "tenant"), "readiness_token": token, "guest_management": 1, "nics": []D{}})
}
func machineDelta(m D) D {
	return D{"vcpu": m["cpu"], "memory_mb": m["memory_mb"], "disk_gb": m["disk_gb"], "machines": 1, "ips": 1, "public_ports": 1}
}
func plannedMachine(m D) D {
	req := []string{}
	if len(arr(m["ssh_keys"])) == 0 {
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
	for _, p := range e.S.Objects("ports", n) {
		used[integer(p["public_port"])] = true
	}
	for p := 20000 + n*10; p < 20010+n*10; p++ {
		if !used[p] {
			return p
		}
	}
	fail("quota_exceeded", "Public port block is full", D{"dimension": "public_ports"})
	return 0
}
func (e *Execution) PublicMachine(m D, ports []D) D {
	safe := without(m, "ssh_keys", "runcmd", "mac", "host", "tenant_n", "resize_from", "readiness_token")
	report := obj(e.S.Get("guest_reports", str(m["vmid"])))
	if m["kind"] == "ct" && m["state"] == "ready" {
		report = merge(report, D{"initialization_status": "complete", "application_status": "not_checked"})
	}
	safe["readiness"] = D{"ssh_ready": boolean(m["ssh_ready"]), "initialization_status": textAt(report, "initialization_status", "unknown"), "application_status": textAt(report, "application_status", "not_checked"), "checks": arr(report["checks"]), "reported_at": report["reported_at"], "private_interfaces": arr(report["interfaces"]), "failed_step": report["failed_step"]}
	allowed := []D{}
	for _, p := range e.S.Objects("peers", integer(m["tenant_n"])) {
		if p["target"] == m["ip"] {
			allowed = append(allowed, D{"from": fallback(p, "from_machine", p["source"]), "port": p["port"], "protocol": textAt(p, "proto", "tcp")})
		}
	}
	private := "unfiltered_experiment_networks"
	if m["network_access"] == "restricted" {
		private = "not_allowed"
	}
	safe["access"] = D{"inbound": textAt(m, "network_access", "tenant"), "private_nics": private, "allowed_connections": allowed}
	ssh := find(ports, func(p D) bool {
		return integer(p["vmid"]) == integer(m["vmid"]) && integer(p["port"]) == 22 && p["proto"] == "tcp"
	})
	if ssh != nil {
		user := "user"
		if m["kind"] == "ct" {
			user = "root"
		}
		t := e.S.TenantN(integer(m["tenant_n"]))
		alias := str(m["name"]) + "." + str(t["slug"])
		safe["ssh"] = fmt.Sprintf("ssh -p %d %s@carrel.winlab.tw", integer(ssh["public_port"]), user)
		safe["ssh_short"] = "ssh " + alias
		safe["ssh_config"] = fmt.Sprintf("Host %s %s.winlab.tw\n  HostName carrel.winlab.tw\n  User %s\n  Port %d\n", alias, alias, user, integer(ssh["public_port"]))
		safe["ssh_short_requires"] = "Install ssh_config on the connecting client once; this is an SSH alias, not a DNS route."
	}
	return safe
}
