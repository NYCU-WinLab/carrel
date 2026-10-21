package carrel

import (
	"fmt"
	"net/url"
	"sort"
	"sync"
)

func (e *Execution) sameOperation(o D) bool { return e.Op != nil && o["operation_id"] == e.Op["id"] }
func (e *Execution) NetworkAction(tool string, a, t D) D {
	dry, n := boolean(a["dry_run"]), integer(t["n"])
	switch tool {
	case "network_list":
		return D{"networks": e.S.Objects("networks", n)}
	case "port_list":
		return D{"ports": e.PublicGrants("ports", n)}
	case "peer_list":
		return D{"peers": e.PublicGrants("peers", n)}
	case "vip_list":
		return D{"vips": e.PublicGrants("vips", n)}
	case "vip_add", "vip_remove":
		return e.VIPAction(tool, a, t)
	case "network_create", "network_delete":
		nets := e.S.Objects("networks", n)
		var network, delta D
		if tool == "network_create" {
			old := find(nets, func(v D) bool { return v["name"] == a["name"] })
			if old != nil && !e.sameOperation(old) {
				fail("conflict", "Network name already exists", D{"recovery": "revise_request"})
			}
			delta = D{}
			if old == nil {
				delta["networks"] = 1
			}
			e.Quota(t, delta)
			network = old
			if network == nil {
				network = e.NetworkSpec(t, a, nil)
			}
			if !dry {
				e.Put("networks", network["id"], n, network)
				e.Reconcile()
			} else {
				network = without(network, "id", "serial", "tenant_n")
				network["state"] = "planned"
			}
		} else {
			network = find(nets, func(v D) bool { return v["name"] == a["network"] || v["id"] == a["network"] })
			if network == nil {
				fail("not_found", "Network not found")
			}
			delta = D{"networks": -1}
			if a["confirm"] != network["name"] {
				fail("invalid", "confirm must equal the network name")
			}
			for _, m := range e.S.Objects("machines", n) {
				for _, nic := range dicts(m["nics"]) {
					if nic["network"] == network["id"] {
						fail("conflict", "Network still has attached NICs", D{"recovery": "resolve_prerequisite"})
					}
				}
			}
			if !dry {
				network["state"] = "deleting"
				e.Put("networks", network["id"], n, network)
				e.Reconcile()
				e.S.Remove("networks", network["id"])
				network["state"] = "deleted"
			}
		}
		q := e.Quota(t)
		if dry {
			q = e.Quota(t, delta)
		}
		return D{"network": network, "dry_run": dry, "quota_after": q}
	case "machine_nic_attach", "machine_nic_detach":
		m := e.Machine(t, a["machine"])
		var request, nic D
		nics := dicts(m["nics"])
		if tool == "machine_nic_attach" {
			network := find(e.S.Objects("networks", n), func(v D) bool { return v["id"] == a["network"] || v["name"] == a["network"] })
			if network == nil {
				fail("not_found", "Network not found in this tenant")
			}
			existing := find(nics, func(v D) bool { return v["network"] == network["id"] })
			if existing != nil && !e.sameOperation(existing) {
				fail("conflict", "Machine already attached to this network", D{"recovery": "revise_request"})
			}
			i := 0
			if existing != nil {
				i = integer(existing["index"])
			} else {
				i = nextNIC(nics)
			}
			if i == 0 {
				fail("quota_exceeded", "Machine already has 8 NICs")
			}
			nic = existing
			if nic == nil {
				nic = e.NICSpec(m, network, i)
				nics = append(nics, nic)
			}
			request = D{"action": "nic_attach", "index": i, "serial": network["serial"], "nic": nic}
		} else {
			i := integer(a["nic"])
			if !dry && m["kind"] == "vm" && powerState(obj(e.Call(D{"op": "status", "machine": m}))) == "paused" {
				fail("conflict", "Resume or shut down the VM before detaching a NIC; a paused guest cannot acknowledge hot unplug", D{"recovery": "resolve_prerequisite"})
			}
			if i == 0 || find(nics, func(n D) bool { return integer(n["index"]) == i }) == nil {
				if e.Op != nil && i != 0 {
					e.Reconcile()
					return D{"nics": nics, "quota_after": e.Quota(t)}
				}
				fail("invalid", "Only attached private NICs can be detached")
			}
			request = D{"action": "nic_detach", "index": i}
			nics = filter(nics, func(n D) bool { return integer(n["index"]) != i })
		}
		if !dry {
			if tool == "machine_nic_attach" {
				m["nics"] = nics
				e.Put("machines", m["vmid"], n, m)
				e.Reconcile()
			}
			e.Call(merge(D{"op": "action", "machine": m}, request))
			m["nics"] = nics
			if tool == "machine_nic_detach" && len(nics) == 0 {
				delete(m, "network_verification")
			}
			if tool == "machine_nic_attach" {
				e.NICReadiness(m, nic)
			}
			e.Put("machines", m["vmid"], n, m)
			if tool == "machine_nic_detach" {
				e.Reconcile()
			}
		}
		r := D{"nics": nics, "dry_run": dry, "quota_after": e.Quota(t)}
		if !dry {
			r["machine"] = e.PublicMachine(m, e.ports(n))
		}
		return r
	case "port_open", "port_close":
		var grant, delta D
		if tool == "port_open" {
			m := e.Machine(t, a["machine"])
			for _, p := range e.ports(n) {
				if p.VMID == integer(m["vmid"]) && float64(p.Port) == num(a["port"]) && p.Proto == a["proto"] {
					if p.State == "deleting" {
						fail("conflict", "Finish removing this port before reopening it", D{"recovery": "finish_cleanup"})
					}
					if !dry {
						e.Reconcile()
					}
					return D{"port": e.PublicGrant("ports", p.D(), n), "quota_after": e.Quota(t)}
				}
			}
			delta = D{"public_ports": 1}
			e.Quota(t, delta)
			public := e.AllocatePort(t)
			opened := portGrant{ID: fmt.Sprintf("%d-%d-%s", n, public, str(a["proto"])), TenantN: n, VMID: integer(m["vmid"]), IP: str(m["ip"]), PublicPort: public, Port: integer(a["port"]), Proto: str(a["proto"])}
			grant = opened.D()
			if !dry {
				e.Put("ports", opened.ID, n, opened)
				e.Reconcile()
			} else {
				grant = D{"machine": m["name"], "port": a["port"], "proto": a["proto"], "state": "planned"}
			}
		} else {
			var closing portGrant
			ok := false
			for _, p := range e.ports(n) {
				if p.ID == a["id"] {
					closing, ok = p, true
					break
				}
			}
			if !ok {
				fail("not_found", "Port grant not found")
			}
			delta = D{"public_ports": -1}
			if !dry {
				closing.State = "deleting"
				e.Put("ports", closing.ID, n, closing)
				e.Reconcile()
				e.S.Remove("ports", closing.ID)
				closing.State = "deleted"
			}
			grant = closing.D()
		}
		q := e.Quota(t)
		if dry {
			q = e.Quota(t, delta)
		}
		return D{"port": e.PublicGrant("ports", grant, n), "dry_run": dry, "quota_after": q}
	case "peer_allow", "peer_revoke":
		var grant D
		var peer peerGrant
		if tool == "peer_allow" {
			m := e.Machine(t, a["machine"])
			source := find(e.S.Tenants(), func(t D) bool { return t["slug"] == a["from_tenant"] })
			if source == nil || source["status"] != "active" {
				fail("not_found", "Source tenant not found")
			}
			src := fmt.Sprintf("10.200.%d.0/24", integer(source["n"]))
			if a["from_machine"] != nil {
				src = str(e.Machine(source, a["from_machine"])["ip"]) + "/32"
			}
			found := false
			for _, p := range e.peers(n) {
				if p.Source == src && p.Target == m["ip"] && float64(p.Port) == num(a["port"]) && p.protocol() == "tcp" {
					peer, found = p, true
					break
				}
			}
			if !found {
				peer = peerGrant{ID: randomID()[:16], TenantN: n, Source: src, Target: str(m["ip"]), Port: integer(a["port"]), Proto: "tcp"}
			}
			if peer.State == "deleting" {
				fail("conflict", "Finish removing this peer grant before reusing it", D{"recovery": "finish_cleanup"})
			}
			grant = peer.D()
			if !dry {
				e.Put("peers", peer.ID, n, peer)
				e.Reconcile()
			} else {
				grant = without(grant, "id", "tenant_n")
			}
		} else {
			found := false
			for _, p := range e.peers(n) {
				if p.ID == a["id"] {
					peer, found = p, true
					break
				}
			}
			if !found {
				fail("not_found", "Peer grant not found")
			}
			if !dry {
				peer.State = "deleting"
				e.Put("peers", peer.ID, n, peer)
				e.Reconcile()
				e.S.Remove("peers", peer.ID)
				peer.State = "deleted"
			}
			grant = peer.D()
		}
		return D{"peer": e.PublicGrant("peers", grant, n), "dry_run": dry, "quota_after": e.Quota(t)}
	}
	fail("invalid", "Unknown network tool")
	return nil
}

// VIPAction keeps a tenant's virtual addresses (issue #96). carrel only lets
// each holder's NIC use the address; keepalived or kube-vip in the guests
// decides which holder answers for it.
func (e *Execution) VIPAction(tool string, a, t D) D {
	dry, n := boolean(a["dry_run"]), integer(t["n"])
	vips := e.vips(n)
	var vip vipRecord
	found := false
	for _, v := range vips {
		if v.Name == a["name"] {
			vip, found = v, true
		}
	}
	if tool == "vip_add" {
		if found && vip.State == "deleting" {
			fail("conflict", "Finish removing this address before reusing its name", D{"recovery": "finish_cleanup"})
		}
		holders, seen := []int{}, map[int]bool{}
		for _, name := range arr(a["machines"]) {
			id := integer(e.Machine(t, name)["vmid"])
			if seen[id] {
				fail("invalid", "A machine is listed twice", D{"recovery": "revise_request"})
			}
			seen[id] = true
			holders = append(holders, id)
		}
		sort.Ints(holders)
		if !found {
			used := map[string]bool{}
			for _, v := range vips {
				used[v.Address] = true
			}
			for _, host := range vipHosts {
				if address := fmt.Sprintf("10.200.%d.%d", n, host); !used[address] {
					vip = vipRecord{ID: randomID()[:16], TenantN: n, Name: str(a["name"]), Address: address}
					if e.Op != nil {
						vip.OperationID = str(e.Op["id"])
					}
					break
				}
			}
			if vip.Address == "" {
				fail("conflict", fmt.Sprintf("A tenant keeps at most %d virtual addresses", len(vipHosts)), D{"recovery": "revise_request"})
			}
		}
		vip.VMIDs, vip.State = holders, "ready"
	} else {
		if !found {
			fail("not_found", "Virtual address not found")
		}
		vip.State = "deleted"
	}
	if dry {
		vip.State = "planned"
		if tool == "vip_remove" {
			vip.State = "deleted"
		}
		return D{"vip": e.PublicGrant("vips", without(vip.D(), "id", "tenant_n", "operation_id"), n), "dry_run": true, "quota_after": e.Quota(t)}
	}
	if tool == "vip_add" {
		e.Put("vips", vip.ID, n, vip)
		e.Reconcile()
	} else {
		// Holders drop the address before the record goes, so a failed
		// reconcile leaves it visible and retryable.
		vip.State = "deleting"
		e.Put("vips", vip.ID, n, vip)
		e.Reconcile()
		e.S.Remove("vips", vip.ID)
		vip.State = "deleted"
	}
	return D{"vip": e.PublicGrant("vips", vip.D(), n), "dry_run": false, "quota_after": e.Quota(t)}
}

func nextNIC(nics []D) int {
	for i := 1; i < 8; i++ {
		if find(nics, func(n D) bool { return integer(n["index"]) == i }) == nil {
			return i
		}
	}
	return 0
}

func (e *Execution) Reconcile() D {
	state := e.S.Desired()
	domains := dicts(state["domains"])
	for _, d := range domains {
		if d["state"] == "configuring" {
			d["state"] = "ready"
		}
	}
	state["domains"] = domains
	state["certificates"] = e.CertificateBundles(domains)
	machines := []D{}
	for _, m := range dicts(state["machines"]) {
		machines = append(machines, without(m, "ssh_keys", "runcmd", "user_data"))
	}
	state["machines"] = machines
	// Every node reconciles: SDN and guest firewalls are cluster-wide, while
	// rate limits and connection tracking live on each node. The first
	// node goes first; it holds the infra gateway and creates new VNets.
	if boolean(e.P.Config["fetch"]) {
		// The fetch network and its container's firewall (PLAN 7.8).
		state["fetch"] = true
	}
	request := D{"op": "reconcile", "state": without(state, "certificates")}
	nodes := e.P.Nodes()
	result := D{"node": e.Call(request, nodes[0].Target)}
	// The gateway goes after the first node, whose guest firewalls admit it,
	// and together with the other nodes.
	var held map[string]any
	var gatewayFailure any
	var gatewayDone sync.WaitGroup
	gatewayDone.Add(1)
	go func() {
		defer gatewayDone.Done()
		gatewayFailure = attempt(func() { held = e.SyncGateway(state) })
	}()
	var jump any
	if e.jumpEnabled() {
		// Store reads stay on this goroutine; only the request runs beside.
		keys := jumpAuthorizedKeys(e.S)
		gatewayDone.Add(1)
		go func() {
			defer gatewayDone.Done()
			jump = e.SyncJump(keys)
		}()
	}
	if len(nodes) > 1 {
		// The other nodes reconcile at once and catch up on the next pass: one
		// node down for an upgrade (PLAN 8.3) must not stop every change.
		results, failures := make([]any, len(nodes)), make([]any, len(nodes))
		var wg sync.WaitGroup
		for i, n := range nodes[1:] {
			wg.Add(1)
			go func() {
				defer wg.Done()
				// Not first: the first node already applied this pass's SDN.
				failures[i+1] = attempt(func() { results[i+1] = e.Call(merge(request, D{"first": false}), n.Target) })
			}()
		}
		wg.Wait()
		each, unreachable := D{nodes[0].Name: result["node"]}, []any{}
		for i, n := range nodes[1:] {
			if f := failures[i+1]; f != nil {
				if _, ok := f.(Failure); !ok {
					panic(f)
				}
				unreachable = append(unreachable, n.Name)
				continue
			}
			each[n.Name] = results[i+1]
		}
		result["nodes"] = each
		if len(unreachable) > 0 {
			result["unreachable_nodes"] = unreachable
		}
	}
	gatewayDone.Wait()
	if gatewayFailure != nil {
		panic(gatewayFailure)
	}
	if jump != nil {
		result["jump"] = jump
	}
	// Fingerprints of the pairs the gateway holds: records point here only
	// for those (MaintainOrigin, DomainRecord).
	e.P.delivered.Store(held)
	return result
}

// RefreshStorage asks each node about the machines it holds and adds a
// tenant's samples across nodes.
func (e *Execution) RefreshStorage() {
	_ = attempt(func() {
		totals := map[int]D{}
		for _, n := range e.P.Nodes() {
			machines := filter(e.S.Objects("machines"), func(m D) bool { return e.P.nodeOf(m).Name == n.Name })
			for _, sample := range dicts(e.Call(D{"op": "storage_usage", "machines": machines}, n.Target)) {
				t := integer(sample["tenant_n"])
				if old := totals[t]; old != nil {
					for _, k := range []string{"retained_snapshot_bytes", "unique_total_bytes"} {
						sample[k] = num(old[k]) + num(sample[k])
					}
					sample["available"] = boolean(old["available"]) && boolean(sample["available"])
				}
				totals[t] = sample
			}
		}
		for t, sample := range totals {
			e.Put("storage_usage", t, t, sample)
		}
	})
}

// originHost is the host name of carrel's public origin, such as carrel.winlab.tw.
func originHost(c D) string {
	u, err := url.Parse(str(c["origin"]))
	if err != nil {
		return ""
	}
	return u.Hostname()
}
