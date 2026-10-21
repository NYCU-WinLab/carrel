package carrel

import (
	"bufio"
	"context"
	"crypto/subtle"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"
)

func machineIdentity(m D) []any { return []any{m["allocation_id"], m["created_at"], m["operation_id"]} }
func (e *Execution) AllocateMachine(t, spec D) (D, portGrant) {
	n := integer(t["n"])
	used := map[int]bool{}
	for _, m := range e.S.Objects("machines", n) {
		used[integer(m["vmid"])] = true
	}
	slot := 0
	for ; slot < 100; slot++ {
		if !used[10000+n*100+slot] {
			break
		}
	}
	if slot == 100 {
		fail("quota_exceeded", "No machine address slots remain")
	}
	vmid := 10000 + n*100 + slot
	var op any
	if e.Op != nil {
		op = e.Op["id"]
	}
	m := merge(spec, D{"vmid": vmid, "tenant_n": n, "ip": fmt.Sprintf("10.200.%d.%d", n, 10+slot), "host": 10 + slot, "mac": fmt.Sprintf("02:ca:%02x:%02x:00:01", n, slot), "state": "provisioning", "created_at": time.Now().Unix(), "allocation_id": randomID(), "nics": []D{}, "operation_id": op})
	e.Put("machines", vmid, n, m)
	if m["public_ssh"] == false {
		return m, portGrant{}
	}
	port := e.AllocatePort(t)
	grant := portGrant{ID: fmt.Sprintf("%d-%d-tcp", n, port), TenantN: n, VMID: vmid, IP: str(m["ip"]), PublicPort: port, Port: 22, Proto: "tcp"}
	e.Put("ports", grant.ID, n, grant)
	return m, grant
}
func (e *Execution) NetworkSpec(t, a D, existing []D) D {
	n := integer(t["n"])
	if existing == nil {
		existing = e.S.Objects("networks", n)
	}
	serial := 1
	for ; serial < 100; serial++ {
		if find(existing, func(v D) bool { return integer(v["serial"]) == serial }) == nil {
			break
		}
	}
	if serial == 100 {
		fail("quota_exceeded", "No network slots remain")
	}
	mode, cidr := textAt(a, "mode", "managed"), str(a["cidr"])
	if mode == "managed" {
		if cidr == "" {
			address := uint32(0x0a400000 + ((n-1)*128+serial-1)*128)
			ip := netip.AddrFrom4([4]byte{byte(address >> 24), byte(address >> 16), byte(address >> 8), byte(address)})
			cidr = netip.PrefixFrom(ip, 25).String()
		}
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() {
			fail("invalid", "Invalid private network CIDR")
		}
		private := false
		for _, c := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"} {
			p := netip.MustParsePrefix(c)
			private = private || p.Contains(prefix.Addr())
		}
		if (prefix.Bits() != 24 && prefix.Bits() != 25) || !private {
			fail("invalid", "Managed private networks require an RFC1918 /24 or /25")
		}
		for _, c := range []string{"10.200.0.0/16", "10.254.0.0/16", "192.168.13.0/24", "172.31.255.0/24"} {
			if prefix.Overlaps(netip.MustParsePrefix(c)) {
				fail("invalid", "Private subnet overlaps infrastructure")
			}
		}
		for _, v := range existing {
			if v["mode"] == "managed" && str(v["cidr"]) != "" {
				p, err := netip.ParsePrefix(str(v["cidr"]))
				if err == nil && prefix.Overlaps(p) {
					fail("conflict", "Private subnet overlaps another managed network in this tenant")
				}
			}
		}
	} else if cidr != "" {
		p, err := netip.ParsePrefix(cidr)
		if err != nil || !p.Addr().Is4() || p != p.Masked() {
			fail("invalid", "Invalid network CIDR")
		}
	}
	var c any
	if cidr != "" {
		c = cidr
	}
	return D{"id": fmt.Sprintf("p%03d%02d", n, serial), "tenant_n": n, "serial": serial, "name": a["name"], "mode": mode, "cidr": c, "mtu": 1450, "gateway": nil, "dhcp": mode == "managed"}
}
func (e *Execution) NICSpec(m, network D, index int) D {
	managed := network["mode"] == "managed"
	if managed && m["kind"] == "vm" && num(m["guest_management"]) == 0 {
		fail("conflict", "This older VM lacks automatic private networking; use raw_l2 or a new VM")
	}
	n := integer(m["tenant_n"])
	slot := integer(m["vmid"]) - 10000 - n*100
	tag := "cc"
	if managed {
		tag = "cb"
	}
	var op any
	if e.Op != nil {
		op = e.Op["id"]
	}
	nic := D{"index": index, "network": network["id"], "mode": textAt(network, "mode", "raw_l2"), "mac": fmt.Sprintf("02:%s:%02x:%02x:%02x:01", tag, n, slot, index), "mtu": 1450, "operation_id": op}
	if managed {
		p := netip.MustParsePrefix(str(network["cidr"]))
		address := p.Addr()
		for i := 0; i < 10+slot; i++ {
			address = address.Next()
		}
		nic["ip"] = address.String()
		nic["prefix"] = p.Bits()
	}
	return nic
}
func (e *Execution) Provision(m D, reconciled bool) {
	e.RequireActive(integer(m["tenant_n"]))
	if e.Op != nil {
		e.Op["phase"] = "provisioning"
		e.Op["current_resource"] = m["name"]
		e.P.Operations.Save(e.Op)
	}
	err := attempt(func() {
		if !reconciled {
			e.Reconcile()
		}
		e.keepCloudInit(m, obj(e.Call(D{"op": "create", "machine": m}))["cloud_init"])
		m["state"] = bootState(m)
		e.Put("machines", m["vmid"], integer(m["tenant_n"]), m)
	})
	if err != nil {
		m["state"] = "error"
		e.Put("machines", m["vmid"], integer(m["tenant_n"]), m)
		panic(err)
	}
}
func (p *Platform) reportSignal(vmid int) <-chan struct{} {
	p.reportMu.Lock()
	defer p.reportMu.Unlock()
	if p.reports[vmid] == nil {
		p.reports[vmid] = make(chan struct{})
	}
	return p.reports[vmid]
}
func (p *Platform) notifyReport(vmid int) {
	p.reportMu.Lock()
	defer p.reportMu.Unlock()
	if ch := p.reports[vmid]; ch != nil {
		close(ch)
	}
	p.reports[vmid] = make(chan struct{})
}
func (e *Execution) WaitReady(original D, previousBoot string) {
	id := str(original["vmid"])
	e.P.writer.Lock()
	deadline := e.readinessDeadline(id, "guest", intAt(e.P.Config, "guest_ready_timeout", 900))
	e.P.writer.Unlock()
	identity := machineIdentity(original)
	appDeadline := num(obj(obj(e.Op)["readiness_deadlines"])[id+":application"])
	for now() < deadline {
		must(e.Ctx.Err())
		signal := e.P.reportSignal(integer(original["vmid"]))
		m := e.S.Get("machines", id)
		if m == nil || !equal(machineIdentity(m), identity) {
			fail("conflict", "Machine allocation changed while waiting for readiness")
		}
		e.RequireActive(integer(m["tenant_n"]))
		probe := probeSSH
		if e.P.sshProbe != nil {
			probe = e.P.sshProbe
		}
		ssh := probe(e.Ctx, m)
		r := e.S.guestReport(id)
		var reportedAt float64
		if r.ReportedAt != nil {
			reportedAt = *r.ReportedAt
		}
		current := r.ReportedAt != nil && fresh(reportedAt) && (previousBoot == "" || r.BootID != previousBoot)
		if e.Op != nil && e.Op["tool"] == "machine_power" {
			current = current && reportedAt >= num(obj(e.Op["power_restore"])["reported_after"])
		}
		init, app := "", ""
		if current {
			init, app = r.InitializationStatus, r.ApplicationStatus
		}
		if m["kind"] == "ct" {
			init, app = "complete", "not_checked"
		}
		network := true
		for _, nic := range dicts(m["nics"]) {
			if nic["ip"] == nil || m["kind"] == "ct" {
				continue
			}
			if !current || reportedAt < num(m["network_configured_at"]) || find(r.Interfaces, func(i D) bool { return i["mac"] == nic["mac"] && i["ip"] == nic["ip"] && integer(i["mtu"]) == 1450 }) == nil {
				network = false
			}
		}
		// Re-read under the writer before persisting. A suspension or deletion cannot be overwritten by a stale probe.
		e.P.writer.Lock()
		problem := attempt(func() {
			latest := e.S.Get("machines", id)
			if latest == nil || !equal(machineIdentity(latest), identity) {
				fail("conflict", "Machine allocation changed while waiting for readiness")
			}
			e.RequireActive(integer(latest["tenant_n"]))
			latest["ssh_ready"], latest["ssh_checked_at"] = ssh, now()
			if init == "complete" && (app == "failed" || app == "pending") {
				if appDeadline == 0 {
					appDeadline = e.readinessDeadline(id, "application", intAt(e.P.Config, "application_ready_timeout", 120))
				}
			}
			appExpired := appDeadline > 0 && now() >= appDeadline && !contains([]string{"healthy", "not_checked"}, app)
			if init == "failed" || appExpired {
				latest["state"] = "needs_owner_fix"
				latest["reason"] = "Guest initialization or an application check failed"
			} else if ssh && init == "complete" && (app == "healthy" || app == "not_checked") && network {
				latest["state"] = "ready"
				latest["power_state"] = "running"
				latest["network_verification"] = "verified"
				delete(latest, "reason")
			} else {
				latest["state"] = "initializing"
				delete(latest, "reason")
			}
			e.Put("machines", latest["vmid"], integer(latest["tenant_n"]), latest)
			m = latest
		})
		e.P.writer.Unlock()
		if problem != nil {
			panic(problem)
		}
		if m["state"] == "needs_owner_fix" {
			fail("guest_not_ready", str(m["reason"]), D{"machine": m["name"], "initialization_status": init, "application_status": app, "checks": orEmpty(r.Checks), "failed_step": optional(r.FailedStep)})
		}
		if m["state"] == "ready" {
			return
		}
		timer := time.NewTimer(time.Duration(intAt(e.P.Config, "guest_poll_interval", 3)) * time.Second)
		select {
		case <-e.Ctx.Done():
			timer.Stop()
			must(e.Ctx.Err())
		case <-signal:
			timer.Stop()
		case <-timer.C:
		}
	}
	e.P.writer.Lock()
	defer e.P.writer.Unlock()
	m := e.S.Get("machines", id)
	if m != nil && equal(machineIdentity(m), identity) {
		m["state"] = "needs_owner_fix"
		m["reason"] = "Timed out waiting for guest initialization and health checks"
		e.Put("machines", m["vmid"], integer(m["tenant_n"]), m)
	}
	last := e.S.guestReport(id)
	var checks any
	if last.Checks != nil {
		checks = last.Checks
	}
	fail("guest_not_ready", "Timed out waiting for guest initialization and health checks", D{"machine": original["name"], "checks": checks, "failed_step": optional(last.FailedStep)})
}

func probeSSH(ctx context.Context, m D) bool {
	conn, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(str(m["ip"]), "22"))
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	line, _ := bufio.NewReaderSize(conn, 1024).ReadSlice('\n')
	return strings.HasPrefix(string(line), "SSH-")
}
func (e *Execution) GuestReport(body D, source string) {
	m := e.S.Get("machines", str(body["vmid"]))
	if m == nil || source != str(m["ip"]) || str(m["readiness_token"]) == "" || subtle.ConstantTimeCompare([]byte(str(body["token"])), []byte(str(m["readiness_token"]))) != 1 {
		fail("forbidden", "Invalid guest report")
	}
	init, app := str(body["initialization_status"]), str(body["application_status"])
	if !contains([]string{"running", "complete", "failed"}, init) || !contains([]string{"pending", "healthy", "failed", "not_checked"}, app) {
		fail("invalid", "Invalid guest status")
	}
	checks, ok := body["checks"].([]any)
	if body["checks"] == nil {
		ok = true
	}
	if !ok || len(checks) > 20 {
		fail("invalid", "Invalid health checks")
	}
	safe := []D{}
	for i, c := range checks {
		d := obj(c)
		if d["status"] == "healthy" || d["status"] == "failed" {
			safe = append(safe, D{"index": i, "status": d["status"]})
		}
	}
	if len(str(body["boot_id"])) != 36 {
		fail("invalid", "Invalid boot ID")
	}
	if f := body["failed_step"]; f != nil {
		_, number := f.(float64)
		if !number || num(f) < 0 || num(f) >= 100 || num(f) != float64(integer(f)) {
			fail("invalid", "Invalid failed step")
		}
	}
	interfaces, ok := body["interfaces"].([]any)
	if body["interfaces"] == nil {
		ok = true
	}
	if !ok || len(interfaces) > 7 {
		fail("invalid", "Invalid guest interface report")
	}
	ifs := []D{}
	for _, v := range interfaces {
		i := obj(v)
		if integer(i["mtu"]) == 1450 && find(dicts(m["nics"]), func(n D) bool { return n["mac"] == i["mac"] && n["ip"] == i["ip"] }) != nil {
			ifs = append(ifs, pick(i, "mac", "ip", "mtu"))
		}
	}
	e.S.Put("guest_reports", m["vmid"], integer(m["tenant_n"]), D{"vmid": m["vmid"], "initialization_status": init, "application_status": app, "checks": safe, "interfaces": ifs, "failed_step": body["failed_step"], "boot_id": body["boot_id"], "reported_at": now()})
	e.P.notifyReport(integer(m["vmid"]))
}

// keepCloudInit stores the files a node reported for a VM, unchanged.
func (e *Execution) keepCloudInit(m D, files any) {
	f := obj(files)
	user, network := str(f["user"]), str(f["network"])
	if user == "" || network == "" {
		return
	}
	r := cloudInitRecord{VMID: integer(m["vmid"]), User: user, UserSHA256: digest(user), Network: network, NetworkSHA256: digest(network)}
	e.S.Put("cloud_init", m["vmid"], integer(m["tenant_n"]), decode(string(encoded(r))))
}

// cloudInitFiles returns the stored files of a VM, for a node to write back
// before it boots the VM.
func (e *Execution) cloudInitFiles(m D) D {
	r, ok := rowOf[cloudInitRecord](e.S, "cloud_init", str(m["vmid"]))
	if !ok || m["kind"] != "vm" || digest(r.User) != r.UserSHA256 || digest(r.Network) != r.NetworkSHA256 {
		return nil
	}
	return D{"user": r.User, "network": r.Network}
}

// CollectCloudInit reads the files of VMs created before carrel kept them.
func (e *Execution) CollectCloudInit() int {
	added := 0
	for _, m := range e.S.Objects("machines") {
		if m["kind"] != "vm" || m["state"] == "deleting" {
			continue
		}
		if _, ok := rowOf[cloudInitRecord](e.S, "cloud_init", str(m["vmid"])); ok {
			continue
		}
		if err := attempt(func() { e.keepCloudInit(m, obj(e.Call(D{"op": "cloud_init_read", "machine": m}))["cloud_init"]) }); err != nil {
			continue
		}
		if _, ok := rowOf[cloudInitRecord](e.S, "cloud_init", str(m["vmid"])); ok {
			added++
		}
	}
	return added
}
