package carrel

import (
	"fmt"
	"net/url"
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
			r["machine"] = e.PublicMachine(m, e.S.Objects("ports", n))
		}
		return r
	case "port_open", "port_close":
		ports := e.S.Objects("ports", n)
		var grant, delta D
		if tool == "port_open" {
			m := e.Machine(t, a["machine"])
			existing := find(ports, func(p D) bool {
				return integer(p["vmid"]) == integer(m["vmid"]) && num(p["port"]) == num(a["port"]) && p["proto"] == a["proto"]
			})
			if existing != nil {
				if existing["state"] == "deleting" {
					fail("conflict", "Finish removing this port before reopening it", D{"recovery": "finish_cleanup"})
				}
				if !dry {
					e.Reconcile()
				}
				return D{"port": e.PublicGrant("ports", existing, n), "quota_after": e.Quota(t)}
			}
			delta = D{"public_ports": 1}
			e.Quota(t, delta)
			public := e.AllocatePort(t)
			grant = D{"id": fmt.Sprintf("%d-%d-%s", n, public, str(a["proto"])), "tenant_n": n, "vmid": m["vmid"], "ip": m["ip"], "public_port": public, "port": a["port"], "proto": a["proto"]}
			if !dry {
				e.Put("ports", grant["id"], n, grant)
				e.Reconcile()
			} else {
				grant = D{"machine": m["name"], "port": a["port"], "proto": a["proto"], "state": "planned"}
			}
		} else {
			grant = find(ports, func(p D) bool { return p["id"] == a["id"] })
			if grant == nil {
				fail("not_found", "Port grant not found")
			}
			delta = D{"public_ports": -1}
			if !dry {
				grant["state"] = "deleting"
				e.Put("ports", grant["id"], n, grant)
				e.Reconcile()
				e.S.Remove("ports", grant["id"])
				grant["state"] = "deleted"
			}
		}
		q := e.Quota(t)
		if dry {
			q = e.Quota(t, delta)
		}
		return D{"port": e.PublicGrant("ports", grant, n), "dry_run": dry, "quota_after": q}
	case "peer_allow", "peer_revoke":
		var grant D
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
			grant = find(e.S.Objects("peers", n), func(p D) bool {
				return p["source"] == src && p["target"] == m["ip"] && num(p["port"]) == num(a["port"]) && textAt(p, "proto", "tcp") == "tcp"
			})
			if grant == nil {
				grant = D{"id": randomID()[:16], "tenant_n": n, "source": src, "target": m["ip"], "port": a["port"], "proto": "tcp"}
			}
			if grant["state"] == "deleting" {
				fail("conflict", "Finish removing this peer grant before reusing it", D{"recovery": "finish_cleanup"})
			}
			if !dry {
				e.Put("peers", grant["id"], n, grant)
				e.Reconcile()
			} else {
				grant = without(grant, "id", "tenant_n")
			}
		} else {
			grant = find(e.S.Objects("peers", n), func(p D) bool { return p["id"] == a["id"] })
			if grant == nil {
				fail("not_found", "Peer grant not found")
			}
			if !dry {
				grant["state"] = "deleting"
				e.Put("peers", grant["id"], n, grant)
				e.Reconcile()
				e.S.Remove("peers", grant["id"])
				grant["state"] = "deleted"
			}
		}
		return D{"peer": e.PublicGrant("peers", grant, n), "dry_run": dry, "quota_after": e.Quota(t)}
	}
	fail("invalid", "Unknown network tool")
	return nil
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
		machines = append(machines, without(m, "ssh_keys", "runcmd"))
	}
	state["machines"] = machines
	// Every node reconciles: SDN and guest firewalls are cluster-wide, while
	// DHCP, rate limits and connection tracking live on each node. The first
	// node goes first; it holds the infra gateway and creates new VNets.
	request := D{"op": "reconcile", "state": without(state, "certificates")}
	nodes := e.P.Nodes()
	first := request
	exit := str(e.P.Config["ingress"]) == "exit"
	if exit {
		// The first node holds the infra gateway, which terminates TLS here.
		gateway := merge(state, D{"origin": originHost(e.P.Config)})
		if crt, key, ok := e.originFiles(); ok {
			gateway["origin_certificate"] = originPair(crt, key)
		}
		first = D{"op": "reconcile", "state": gateway}
	}
	result := D{"node": e.Call(first, nodes[0].Target)}
	if exit {
		// Fingerprints of the pairs the gateway confirmed it holds: records
		// move to this site only for those (MaintainOrigin, DomainRecord).
		held, _ := obj(result["node"])["certificates"].(map[string]any)
		e.P.delivered.Store(held)
	}
	if len(nodes) > 1 {
		// The other nodes catch up on the next reconcile: one node down for an
		// upgrade (PLAN 8.3) must not stop every change on the site.
		each, unreachable := D{nodes[0].Name: result["node"]}, []any{}
		for _, n := range nodes[1:] {
			if f := attempt(func() { each[n.Name] = e.Call(request, n.Target) }); f != nil {
				if _, ok := f.(Failure); !ok {
					panic(f)
				}
				unreachable = append(unreachable, n.Name)
			}
		}
		result["nodes"] = each
		if len(unreachable) > 0 {
			result["unreachable_nodes"] = unreachable
		}
	}
	// A site with its own public address publishes on its first exit node;
	// the external edge then only keeps the backups.
	if str(e.P.Config["ingress"]) != "exit" {
		result["edge"] = e.Call(D{"op": "reconcile", "state": pick(state, "ports", "domains", "certificates")}, "carrel-edge")
	}
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
