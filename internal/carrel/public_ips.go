package carrel

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"
)

// Public IP per machine (issue #91, PLAN 6.12): the Elastic IP of 6.11. A
// member files public_ip_request; an admin approves it and the tenant holds
// an address from the pool. public_ip_bind points it at one machine: the exit
// node DNATs the address to the machine's primary address and SNATs the
// machine's egress to it, 1:1, and the guest firewall admits the internet on
// the ports the member chose. The pool is what NetBox assigns to carrel, read
// on each NetBox pass; carrel hands out nothing else.

// publicIP is one address a tenant holds, bound to a machine or not.
type publicIP struct {
	Address   string   `json:"address"`
	BoundAt   float64  `json:"bound_at,omitempty"`
	GrantedAt int64    `json:"granted_at"`
	ID        string   `json:"id"`
	Ports     []string `json:"ports,omitempty"`
	RequestID string   `json:"request_id"`
	State     string   `json:"state,omitempty"`
	TenantN   int      `json:"tenant_n"`
	VMID      int      `json:"vmid,omitempty"`
}

func (b publicIP) D() D { return decode(string(encoded(b))) }

func (e *Execution) publicIPs(n ...int) []publicIP {
	return rowsOf[publicIP](e.S, "public_ips", n...)
}

// publicPoolLimit bounds the addresses one NetBox range may add to the pool.
const publicPoolLimit = 256

// publicPool is the addresses NetBox assigns to carrel as last read, in order.
func (e *Execution) publicPool() []string {
	out := []string{}
	shared := str(e.P.Config["public_address"])
	for _, r := range dicts(obj(e.S.SiteGet("public_pool", "netbox"))["ranges"]) {
		start, err1 := netip.ParsePrefix(str(r["start"]))
		end, err2 := netip.ParsePrefix(str(r["end"]))
		if err1 != nil || err2 != nil || !start.Addr().Is4() || !end.Addr().Is4() {
			continue
		}
		from, to := binary.BigEndian.Uint32(start.Addr().AsSlice()), binary.BigEndian.Uint32(end.Addr().AsSlice())
		for a := from; a <= to && a-from < publicPoolLimit; a++ {
			addr := netip.AddrFrom4([4]byte{byte(a >> 24), byte(a >> 16), byte(a >> 8), byte(a)})
			if s := addr.String(); s != shared && addr.IsGlobalUnicast() && !addr.IsPrivate() {
				out = append(out, s)
			}
		}
	}
	return out
}

// freePublicIPs is the pool less the addresses held, and less those NetBox
// holds an address object for that carrel does not own (#180).
func (e *Execution) freePublicIPs() []string {
	held := map[string]bool{}
	for _, b := range e.publicIPs() {
		held[b.Address] = true
	}
	for _, a := range e.publicIPsTaken() {
		held[a] = true
	}
	out := []string{}
	for _, a := range e.publicPool() {
		if !held[a] {
			out = append(out, a)
		}
	}
	return out
}

// publicIPsTaken lists the pool addresses an unowned NetBox object sits at.
func (e *Execution) publicIPsTaken() []string {
	out := []string{}
	for _, a := range arr(obj(e.S.SiteGet("public_pool", "netbox"))["taken"]) {
		out = append(out, str(a))
	}
	return out
}

// PublicIPRequest files a request for a public address.
func (e *Execution) PublicIPRequest(a, w, t D) D {
	dry, n := boolean(a["dry_run"]), integer(t["n"])
	key := str(a["idempotency_key"])
	fingerprint := digest(string(encoded(D{"reason": a["reason"]})))
	if key != "" && !dry {
		for _, old := range e.S.Objects("requests", n) {
			if old["idempotency_key"] == key {
				if old["fingerprint"] != fingerprint {
					fail("conflict", "Idempotency key was already used for different arguments", D{"recovery": "revise_request"})
				}
				return D{"request": without(old, "fingerprint", "idempotency_key"), "reused": true}
			}
		}
	}
	if len(e.publicPool()) == 0 {
		fail("conflict", "This site offers no public addresses", D{"recovery": "revise_request"})
	}
	pending := filter(e.S.Objects("requests", n), func(r D) bool { return r["kind"] == "public_ip" && r["status"] == "pending" })
	if len(pending) >= maxPendingDomainRequests {
		fail("quota_exceeded", "A tenant has at most 3 pending public address requests; wait for a decision", D{"recovery": "revise_request"})
	}
	r := D{"id": randomID()[:16], "tenant_n": n, "kind": "public_ip", "status": "pending", "reason": a["reason"], "actor": w["sub"], "created_at": time.Now().Unix()}
	if dry {
		r = without(r, "id", "tenant_n", "actor", "created_at")
		r["status"] = "planned"
		return D{"request": r, "dry_run": true}
	}
	if key != "" {
		r["idempotency_key"], r["fingerprint"] = key, fingerprint
	}
	e.Put("requests", r["id"], n, r)
	return D{"request": without(r, "fingerprint", "idempotency_key"), "dry_run": false}
}

// approvePublicIP decides a public address request: an approval takes the
// first free address of the pool for the tenant.
func (e *Execution) approvePublicIP(tool string, a, w, r, t D) D {
	dry, n := boolean(a["dry_run"]), integer(t["n"])
	var b publicIP
	if tool == "request_approve" {
		free := e.freePublicIPs()
		if len(free) == 0 {
			detail := D{"recovery": "resolve_prerequisite"}
			if taken := e.publicIPsTaken(); len(taken) > 0 {
				detail["taken_in_netbox"] = taken
				fail("conflict", "No public address of the pool is free; NetBox holds an address object carrel does not own at "+strings.Join(taken, ", ")+": the network team removes it or hands it to carrel", detail)
			}
			fail("conflict", "No public address of the pool is free", detail)
		}
		b = publicIP{ID: randomID()[:16], TenantN: n, Address: free[0], RequestID: str(r["id"]), GrantedAt: time.Now().Unix()}
	}
	switch {
	case dry && tool == "request_approve":
		r["status"] = "planned_approval"
		r["address"] = b.Address
	case dry:
		r["status"] = "planned_rejection"
	default:
		e.Transaction(func(tx *Execution) {
			if tool == "request_approve" {
				tx.Put("public_ips", b.ID, n, b)
				r["status"] = "approved"
				r["address"] = b.Address
			} else {
				r["status"] = "rejected"
			}
			r["decided_by"] = w["sub"]
			tx.Put("requests", r["id"], n, r)
		})
	}
	return D{"request": without(r, "idempotency_key", "fingerprint"), "dry_run": dry}
}

// publicPorts checks the ports a bound address admits: "all", or up to 32
// distinct tcp/N and udp/N.
func publicPorts(v any) []string {
	if v == nil {
		return []string{"tcp/22"}
	}
	ports := []string{}
	for _, p := range arr(v) {
		ports = append(ports, strings.ToLower(str(p)))
	}
	if len(ports) == 1 && ports[0] == "all" {
		return ports
	}
	seen := map[string]bool{}
	for _, p := range ports {
		proto, port, _ := strings.Cut(p, "/")
		n := 0
		if _, err := fmt.Sscanf(port, "%d", &n); err != nil || fmt.Sprint(n) != port || n < 1 || n > 65535 || (proto != "tcp" && proto != "udp") || seen[p] {
			fail("invalid", `ports is ["all"] or up to 32 distinct "tcp/N" and "udp/N"`, D{"recovery": "revise_request"})
		}
		seen[p] = true
	}
	if len(ports) == 0 || len(ports) > 32 {
		fail("invalid", `ports is ["all"] or up to 32 distinct "tcp/N" and "udp/N"`, D{"recovery": "revise_request"})
	}
	sort.Strings(ports)
	return ports
}

// PublicIPAction lists, binds and releases the tenant's public addresses.
func (e *Execution) PublicIPAction(tool string, a, t D) D {
	dry, n := boolean(a["dry_run"]), integer(t["n"])
	held := e.publicIPs(n)
	if tool == "public_ip_list" {
		out := []D{}
		for _, b := range held {
			out = append(out, e.publicPublicIP(b))
		}
		return D{"public_ips": out, "pool_free": len(e.freePublicIPs())}
	}
	var b publicIP
	switch address := str(a["address"]); {
	case address != "":
		for _, h := range held {
			if h.Address == address {
				b = h
			}
		}
	case len(held) == 1:
		b = held[0]
	case len(held) > 1:
		fail("invalid", "The tenant holds several public addresses; name one with address", D{"recovery": "revise_request"})
	}
	if b.ID == "" {
		fail("not_found", "The tenant holds no such public address; file public_ip_request first", D{"recovery": "resolve_prerequisite"})
	}
	if b.State == "deleting" && tool != "public_ip_release" {
		fail("conflict", "This public address is being released; release it again to finish", D{"recovery": "finish_cleanup"})
	}
	if tool == "public_ip_release" {
		if !dry {
			// The rules leave the exit node before the record goes, so a
			// failed reconcile leaves it visible and retryable.
			b.State = "deleting"
			e.Put("public_ips", b.ID, n, b)
			e.Reconcile()
			e.Transaction(func(tx *Execution) {
				tx.S.Remove("public_ips", b.ID)
				if r := tx.S.Get("requests", b.RequestID); r != nil {
					r["status"] = "released"
					r["released_at"] = time.Now().Unix()
					tx.Put("requests", b.RequestID, n, r)
				}
			})
		}
		out := e.publicPublicIP(b)
		out["state"] = "released"
		return D{"public_ip": out, "dry_run": dry}
	}
	m := e.Machine(t, a["machine"])
	if m["state"] == "deleting" {
		fail("conflict", "The machine is being deleted", D{"recovery": "revise_request"})
	}
	for _, h := range held {
		if h.ID != b.ID && h.VMID == integer(m["vmid"]) {
			fail("conflict", "The machine already has public address "+h.Address+"; release it or bind it elsewhere first", D{"recovery": "revise_request"})
		}
	}
	// NetBox may take an address back from carrel (PLAN 6.12): a binding
	// that stands keeps working, but no new one is made.
	if !slices.Contains(e.publicPool(), b.Address) {
		fail("conflict", "NetBox no longer assigns "+b.Address+" to carrel; release it", D{"recovery": "revise_request"})
	}
	// Binding again moves the address or changes its ports.
	b.VMID, b.Ports, b.BoundAt = integer(m["vmid"]), publicPorts(a["ports"]), now()
	if dry {
		out := e.publicPublicIP(b)
		out["state"] = "planned"
		return D{"public_ip": out, "dry_run": true}
	}
	e.Put("public_ips", b.ID, n, b)
	e.Reconcile()
	return D{"public_ip": e.publicPublicIP(b), "dry_run": false}
}

// publicPublicIP is a held address as members see it.
func (e *Execution) publicPublicIP(b publicIP) D {
	out := D{"address": b.Address, "state": "unbound"}
	if b.VMID != 0 {
		if m := e.S.Get("machines", str(b.VMID)); m != nil && integer(m["tenant_n"]) == b.TenantN {
			out["machine"], out["ports"], out["state"] = m["name"], b.Ports, "bound"
		}
	}
	if b.State == "deleting" {
		out["state"] = "releasing"
	}
	return out
}

// machinePublicIP is the bound address of a machine, for machine_get.
func (e *Execution) machinePublicIP(m D) D {
	for _, b := range e.publicIPs(integer(m["tenant_n"])) {
		if b.VMID == integer(m["vmid"]) && b.State != "deleting" {
			return D{"address": b.Address, "ports": b.Ports}
		}
	}
	return nil
}

// desiredPublicIPs is the bindings the exit node applies.
func desiredPublicIPs(s *Store) []any {
	out := []any{}
	for _, b := range rowsOf[publicIP](s, "public_ips") {
		if b.VMID != 0 && b.State != "deleting" {
			out = append(out, D{"address": b.Address, "tenant_n": b.TenantN, "vmid": b.VMID, "ports": b.Ports})
		}
	}
	return out
}
