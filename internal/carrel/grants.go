package carrel

import (
	"fmt"
	"strings"
)

// Resolve only resources already visible through this tenant's grants.
func (e *Execution) PublicGrant(kind string, grant D, n int) D {
	g := clone(grant)
	for _, m := range e.S.Objects("machines", n) {
		if (g["vmid"] != nil && integer(g["vmid"]) == integer(m["vmid"])) || g["target"] == m["ip"] {
			g["machine"] = m["name"]
		}
	}
	if g["vip"] != nil {
		// Members name a virtual address; its id stays internal.
		for _, v := range e.vips(n) {
			if v.ID == g["vip"] {
				g["vip"] = v.Name
			}
		}
	}
	switch kind {
	case "ports":
		if g["public_port"] != nil {
			g["endpoint"] = fmt.Sprintf("carrel.winlab.tw:%d", integer(g["public_port"]))
			g["verification"] = "recorded_route"
		}
	case "domains":
		// A catch-all name is no address one can open.
		if g["sub"] != "*" && !strings.HasPrefix(str(g["name"]), "*.") && !strings.HasPrefix(str(g["name"]), "_") {
			g["url"] = "https://" + str(g["name"])
		}
		if g["state"] == "ready" {
			g["verification"] = "routing_configured"
		}
	case "vips":
		names := []any{}
		for _, id := range arr(g["vmids"]) {
			for _, m := range e.S.Objects("machines", n) {
				if integer(m["vmid"]) == integer(id) {
					names = append(names, m["name"])
				}
			}
		}
		g["machines"] = names
	case "peers":
		for _, t := range e.S.Tenants() {
			prefix := fmt.Sprintf("10.200.%d.", integer(t["n"]))
			if !strings.HasPrefix(str(g["source"]), prefix) {
				continue
			}
			g["from_tenant"] = t["slug"]
			for _, m := range e.S.Objects("machines", integer(t["n"])) {
				if g["source"] == str(m["ip"])+"/32" {
					g["from_machine"] = m["name"]
				}
			}
		}
	}
	if g["state"] == "deleting" || g["state"] == "deleted" {
		delete(g, "verification")
	}
	return g
}

func (e *Execution) PublicGrants(kind string, n int) []D {
	out := []D{}
	for _, g := range e.S.Objects(kind, n) {
		out = append(out, e.PublicGrant(kind, g, n))
	}
	return out
}

func grantSummary(kind string, g D) D {
	switch kind {
	case "ports":
		return pick(g, "id", "machine", "vip", "public_port", "port", "proto", "endpoint", "state", "verification")
	case "domains":
		return pick(g, "name", "machine", "vip", "sub", "target_port", "url", "state", "ready_at", "verification")
	case "peers":
		return pick(g, "id", "machine", "from_tenant", "from_machine", "source", "port", "proto", "state")
	case "networks":
		return pick(g, "id", "name", "mode", "cidr", "mtu", "gateway", "dhcp", "state")
	case "vips":
		return pick(g, "name", "address", "machines", "state")
	}
	return g
}
