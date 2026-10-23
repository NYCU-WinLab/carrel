package carrel

import (
	"fmt"
	"log/slog"
	"slices"
	"time"
)

// Special ports (PLAN 6.10): a public port outside the tenant's own block,
// such as TCP 25565 for Minecraft. A member files port_request, an admin
// approves it, and the approved port becomes a grant of the tenant that
// port_open with public_port forwards to a machine. A grant that forwards
// nothing is released after grantUnusedDays, like a special domain.

// specialPort is one approved public port.
type specialPort struct {
	GrantedAt   int64   `json:"granted_at"`
	ID          string  `json:"id"`
	Proto       string  `json:"proto"`
	PublicPort  int     `json:"public_port"`
	RequestID   string  `json:"request_id"`
	TenantN     int     `json:"tenant_n"`
	UnusedSince float64 `json:"unused_since,omitempty"`
}

func (g specialPort) D() D { return decode(string(encoded(g))) }

func (e *Execution) specialPorts(n ...int) []specialPort {
	return rowsOf[specialPort](e.S, "port_grants", n...)
}

// neverGranted reports whether a public port is never granted: well-known
// ports of the site, the tenant blocks (20000 + 10n to 20009 + 10n for n up
// to 254) and the client VPN ports of the exit node. scripts/node-agent.py
// keeps the same list.
func neverGranted(port int) bool {
	return slices.Contains([]int{22, 25, 53, 80, 111, 443, 3128, 8006}, port) ||
		(port >= 20000 && port <= 22549) || (port >= vpnPortBase && port <= vpnPortBase+254)
}

// vpnPortBase is where the exit node's client VPN ports start (issue #103).
const vpnPortBase = 31000

// checkSpecialPort applies the rules of PLAN 6.10 step 2 to a port.
func (e *Execution) checkSpecialPort(port int, proto, ignore string) {
	if port < 1 || port > 65535 || (proto != "tcp" && proto != "udp") {
		fail("invalid", "Give a port from 1 to 65535 and tcp or udp", D{"recovery": "revise_request"})
	}
	if neverGranted(port) {
		fail("conflict", fmt.Sprintf("Public port %d is never granted", port), D{"recovery": "revise_request"})
	}
	for _, g := range e.specialPorts() {
		if g.PublicPort == port && g.Proto == proto {
			fail("conflict", "This public port is already granted", D{"recovery": "revise_request"})
		}
	}
	for _, r := range e.S.Objects("requests") {
		if r["kind"] == "port" && r["status"] == "pending" && r["id"] != ignore && integer(r["public_port"]) == port && r["proto"] == proto {
			fail("conflict", "A pending request already asks for this public port", D{"recovery": "revise_request"})
		}
	}
}

// PortRequest files a request for a special public port.
func (e *Execution) PortRequest(a, w, t D) D {
	dry, n := boolean(a["dry_run"]), integer(t["n"])
	port, proto := integer(a["public_port"]), str(fallback(a, "proto", "tcp"))
	key := str(a["idempotency_key"])
	fingerprint := digest(string(encoded(D{"public_port": port, "proto": proto, "reason": a["reason"]})))
	if key != "" && !dry {
		for _, old := range e.S.Objects("requests", n) {
			if old["idempotency_key"] == key {
				if old["fingerprint"] != fingerprint {
					fail("conflict", "Idempotency key was already used for different arguments", D{"recovery": "revise_request"})
				}
				return D{"request": without(old, "fingerprint", "idempotency_key"), "quota_after": e.Quota(t), "reused": true}
			}
		}
	}
	e.checkSpecialPort(port, proto, "")
	pending := filter(e.S.Objects("requests", n), func(r D) bool { return r["kind"] == "port" && r["status"] == "pending" })
	if len(pending) >= maxPendingDomainRequests {
		fail("quota_exceeded", "A tenant has at most 3 pending port requests; wait for a decision", D{"recovery": "revise_request"})
	}
	r := D{"id": randomID()[:16], "tenant_n": n, "kind": "port", "status": "pending", "public_port": port, "proto": proto, "reason": a["reason"], "actor": w["sub"], "created_at": time.Now().Unix()}
	if !dry {
		if key != "" {
			r["idempotency_key"], r["fingerprint"] = key, fingerprint
		}
		e.Put("requests", r["id"], n, r)
	} else {
		r = without(r, "id", "tenant_n", "actor", "created_at")
		r["status"] = "planned"
	}
	return D{"request": without(r, "fingerprint", "idempotency_key"), "dry_run": dry, "quota_after": e.Quota(t)}
}

// approvePort decides a port request; the rules are checked again.
func (e *Execution) approvePort(tool string, a, w, r, t D) D {
	dry, n := boolean(a["dry_run"]), integer(t["n"])
	if tool == "request_approve" {
		e.checkSpecialPort(integer(r["public_port"]), str(r["proto"]), str(r["id"]))
	}
	g := specialPort{ID: randomID()[:16], TenantN: n, PublicPort: integer(r["public_port"]), Proto: str(r["proto"]), RequestID: str(r["id"]), GrantedAt: time.Now().Unix(), UnusedSince: now()}
	switch {
	case dry && tool == "request_approve":
		r["status"] = "planned_approval"
	case dry:
		r["status"] = "planned_rejection"
	default:
		e.Transaction(func(tx *Execution) {
			if tool == "request_approve" {
				tx.Put("port_grants", g.ID, n, g)
				r["status"] = "approved"
				r["grant"] = g.ID
			} else {
				r["status"] = "rejected"
			}
			r["decided_by"] = w["sub"]
			tx.Put("requests", r["id"], n, r)
		})
	}
	return D{"request": without(r, "idempotency_key", "fingerprint"), "dry_run": dry, "quota_after": e.Quota(t)}
}

// specialPortFor finds the tenant's grant of a public port and proto.
func (e *Execution) specialPortFor(n, port int, proto string) specialPort {
	for _, g := range e.specialPorts(n) {
		if g.PublicPort == port && g.Proto == proto {
			return g
		}
	}
	fail("not_found", "No special port grant of this tenant covers this public port and protocol; file port_request first", D{"recovery": "resolve_prerequisite"})
	return specialPort{}
}

// publicSpecialPorts is the tenant's port grants as port_list shows them.
func (e *Execution) publicSpecialPorts(n int) []D {
	out := []D{}
	for _, g := range e.specialPorts(n) {
		p := D{"public_port": g.PublicPort, "proto": g.Proto, "state": "in_use"}
		if g.UnusedSince != 0 {
			p["state"] = "unused"
			p["release_at"] = time.Unix(int64(g.UnusedSince)+grantUnusedDays*86400, 0).UTC().Format(time.RFC3339)
		}
		out = append(out, p)
	}
	return out
}

// MaintainSpecialPorts marks port grants used or unused and releases those
// unused for grantUnusedDays.
func (e *Execution) MaintainSpecialPorts() {
	e.P.writer.Lock()
	defer e.P.writer.Unlock()
	for _, g := range e.specialPorts() {
		used := find(e.S.Objects("ports", g.TenantN), func(p D) bool {
			return p["state"] != "deleting" && integer(p["public_port"]) == g.PublicPort && p["proto"] == g.Proto
		}) != nil
		switch {
		case used && g.UnusedSince != 0:
			g.UnusedSince = 0
			e.S.Put("port_grants", g.ID, g.TenantN, g.D())
		case !used && g.UnusedSince == 0:
			g.UnusedSince = now()
			e.S.Put("port_grants", g.ID, g.TenantN, g.D())
		case !used && now()-g.UnusedSince > grantUnusedDays*86400:
			e.Transaction(func(tx *Execution) {
				tx.S.Remove("port_grants", g.ID)
				if r := tx.S.Get("requests", g.RequestID); r != nil {
					r["status"] = "released"
					r["released_at"] = time.Now().Unix()
					tx.S.Put("requests", g.RequestID, g.TenantN, r)
				}
			})
			e.S.Log("system", g.TenantN, "port_grant_released", D{"grant": g.ID, "public_port": g.PublicPort, "proto": g.Proto}, "ok")
			slog.Info("port_grant_released", "grant", g.ID, "public_port", g.PublicPort)
		}
	}
}
