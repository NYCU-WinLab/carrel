package carrel

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strings"
	"time"
)

// The infra gateway (CT 101) terminates TLS for carrel's origin and every
// tenant wildcard. The control plane renders its Caddyfile and internal hosts
// file and sends them, with the certificate pairs, straight to the forced
// command gateway-sync.py in CT 101: private keys never pass through a node.
// Plain HTTP redirects to HTTPS; carrel's own paths go to the control plane
// and the rest of its origin is the static site; each tenant wildcard routes
// the names in the database, and any other name to the tenant's catch-all
// domain (sub "*") or a 404.

var controlPaths = []string{"/mcp", "/mcp/*", "/oauth/*", "/.well-known/*", "/healthz", "/status", "/internal/*", "/apps/*", "/console/*"}

const gatewayCerts = "/etc/caddy/carrel-certs"

var (
	labelPattern  = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	originPattern = regexp.MustCompile(`^([a-z0-9-]+\.)+winlab\.tw$`)
	grantPattern  = regexp.MustCompile(`^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
)

// checkedPair returns the PEM pair if it covers host, has not expired and its
// key matches.
func checkedPair(bundle D, host string) D {
	crt, key := str(bundle["fullchain"]), str(bundle["privkey"])
	if crt == "" || key == "" || len(crt) > 65536 || len(key) > 65536 {
		fail("conflict", "Invalid certificate bundle")
	}
	if _, err := tls.X509KeyPair([]byte(crt), []byte(key)); err != nil {
		fail("conflict", "Certificate key mismatch", D{"host": host})
	}
	block, _ := pem.Decode([]byte(crt))
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil || leaf.VerifyHostname(host) != nil {
		fail("conflict", "Certificate does not cover "+host)
	}
	if time.Now().After(leaf.NotAfter) {
		fail("conflict", "Certificate expired", D{"host": host})
	}
	return D{"fullchain": crt, "privkey": key}
}

// gatewayConfig returns the gateway's Caddyfile, hosts file and certificate
// pairs for the desired state.
func gatewayConfig(state D, origin string, originBundle D, bundles []D) (string, string, map[string]D) {
	slugs := map[int]string{}
	for _, t := range dicts(state["tenants"]) {
		if !labelPattern.MatchString(str(t["slug"])) {
			fail("conflict", "Invalid tenant slug")
		}
		slugs[integer(t["n"])] = str(t["slug"])
	}
	machines := map[int]D{}
	var hosts strings.Builder
	for _, m := range dicts(state["machines"]) {
		machines[integer(m["vmid"])] = m
		fmt.Fprintf(&hosts, "%s %s.%s.internal\n", str(m["ip"]), str(m["name"]), slugs[integer(m["tenant_n"])])
	}
	// Virtual addresses a domain may point at (issue #146).
	vips := map[string]D{}
	for _, v := range dicts(state["vips"]) {
		vips[str(v["id"])] = v
	}
	type route struct {
		domain  D
		address string
		port    int
	}
	routes := map[string][]route{}
	// Special domain grants (PLAN 6.10) and the routes under each.
	grants := map[string]domainGrant{}
	srv := map[string]bool{}
	for _, raw := range dicts(state["domain_grants"]) {
		var g domainGrant
		must(json.Unmarshal(encoded(raw), &g))
		if g.Kind == "srv" {
			// An SRV record points at a public port, not at the gateway.
			srv[g.ID] = true
			continue
		}
		if !grantPattern.MatchString(g.Name) || (g.Kind == "delegated" && under(g.Name, specialZone)) || (g.Kind != "exact" && g.Kind != "wildcard" && g.Kind != "delegated") || (g.Kind != "exact") != strings.HasPrefix(g.Name, "*.") || under(g.Name, origin) {
			fail("conflict", "Invalid special domain grant")
		}
		// A tenant's subtree is its own site block; no grant may reach into it.
		for n, slug := range slugs {
			if owner := slug + ".winlab.tw"; under(g.Name, owner) && (g.Name != owner || n != g.TenantN) {
				fail("conflict", "Invalid special domain grant")
			}
		}
		grants[g.ID] = g
	}
	grantRoutes := map[string][]route{}
	for _, d := range dicts(state["domains"]) {
		if d["state"] != "ready" {
			continue
		}
		var target D
		if d["vip"] != nil {
			target = vips[str(d["vip"])]
		} else {
			target = machines[integer(d["vmid"])]
		}
		if target == nil || (d["vip"] != nil && integer(target["tenant_n"]) != integer(d["tenant_n"])) {
			fail("conflict", "Invalid tenant domain")
		}
		address := str(target["ip"])
		if d["vip"] != nil {
			address = str(target["address"])
		}
		slug := slugs[integer(target["tenant_n"])]
		if id := str(d["grant"]); id != "" {
			if srv[id] {
				continue
			}
			g, ok := grants[id]
			if !ok || g.TenantN != integer(d["tenant_n"]) || integer(target["tenant_n"]) != g.TenantN || !g.covers(str(d["name"])) {
				fail("conflict", "Invalid special domain")
			}
			port := integer(d["target_port"])
			if port < 1 || port > 65535 {
				fail("conflict", "Invalid tenant domain port")
			}
			grantRoutes[id] = append(grantRoutes[id], route{d, address, port})
			continue
		}
		sub := str(d["sub"])
		if (sub != "*" && !labelPattern.MatchString(sub)) || str(d["name"]) != sub+"."+slug+".winlab.tw" {
			fail("conflict", "Invalid tenant domain")
		}
		port := integer(d["target_port"])
		if port < 1 || port > 65535 {
			fail("conflict", "Invalid tenant domain port")
		}
		routes[slug] = append(routes[slug], route{d, address, port})
	}
	byName := map[string]D{}
	for _, b := range bundles {
		byName[str(b["slug"])] = b
	}
	lines := []string{"{", " auto_https off", "}", "http:// {", " redir https://{host}{uri} 308", "}"}
	certificates := map[string]D{}
	if origin != "" && originBundle != nil {
		if !originPattern.MatchString(origin) {
			fail("conflict", "Invalid origin host")
		}
		// "_origin" is no tenant label, so no slug can take its directory.
		certificates["_origin"] = checkedPair(originBundle, origin)
		lines = append(lines,
			"https://"+origin+" {",
			" tls "+gatewayCerts+"/_origin/fullchain.pem "+gatewayCerts+"/_origin/privkey.pem",
			" @control path "+strings.Join(controlPaths, " "),
			" handle @control {",
			"  reverse_proxy 10.200.0.3:8080 {",
			"   flush_interval -1",
			"   stream_close_delay 5m",
			"  }",
			" }",
			" handle {",
			"  root * /srv/carrel-site",
			"  try_files {path} {path}.html {path}/index.html",
			"  file_server {",
			"   hide .*",
			"  }",
			" }",
			"}",
		)
	}
	names := make([]string, 0, len(routes))
	for slug := range routes {
		names = append(names, slug)
	}
	sort.Strings(names)
	for _, slug := range names {
		bundle := byName[slug]
		if bundle == nil {
			fail("conflict", "Missing domain certificate", D{"tenant": slug})
		}
		certificates[slug] = checkedPair(bundle, "probe."+slug+".winlab.tw")
		lines = append(lines, "https://*."+slug+".winlab.tw {", " tls "+gatewayCerts+"/"+slug+"/fullchain.pem "+gatewayCerts+"/"+slug+"/privkey.pem")
		fallback := "  respond 404"
		for _, r := range routes[slug] {
			upstream := fmt.Sprintf("  reverse_proxy %s:%d", r.address, r.port)
			if r.domain["sub"] == "*" {
				// Caddy runs a handle without a matcher after every named
				// one, so a domain of its own always wins over the catch-all.
				fallback = upstream
				continue
			}
			id := str(r.domain["id"])
			lines = append(lines,
				" @d"+id+" host "+str(r.domain["name"]),
				" handle @d"+id+" {",
				upstream,
				" }",
			)
		}
		lines = append(lines, " handle {", fallback, " }", "}")
	}
	ids := make([]string, 0, len(grantRoutes))
	for id := range grantRoutes {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return grants[ids[i]].Name < grants[ids[j]].Name })
	delegated := false
	for _, id := range ids {
		g := grants[id]
		if g.Kind == "delegated" {
			// The gateway's own certificates, issued when a name is first
			// asked for, after carrel's ask endpoint agrees (PLAN 6.10):
			// names one or two labels under the base.
			delegated = true
			fallback := "  respond 404"
			for _, r := range grantRoutes[id] {
				if r.domain["name"] == g.Name {
					fallback = fmt.Sprintf("  reverse_proxy %s:%d", r.address, r.port)
				}
			}
			lines = append(lines, "https://*."+g.base()+", https://*.*."+g.base()+" {", " tls {", "  on_demand", " }", " handle {", fallback, " }", "}")
			continue
		}
		lineage := g.lineage()
		bundle := byName[lineage]
		if bundle == nil {
			fail("conflict", "Missing domain certificate", D{"grant": g.ID})
		}
		probe := g.Name
		if g.Kind == "wildcard" {
			probe = "probe." + g.base()
		}
		certificates[lineage] = checkedPair(bundle, probe)
		lines = append(lines, "https://"+g.Name+" {", " tls "+gatewayCerts+"/"+lineage+"/fullchain.pem "+gatewayCerts+"/"+lineage+"/privkey.pem")
		fallback := "  respond 404"
		for _, r := range grantRoutes[id] {
			upstream := fmt.Sprintf("  reverse_proxy %s:%d", r.address, r.port)
			if r.domain["name"] == g.Name {
				// The exact name, or a wildcard's catch-all.
				fallback = upstream
				continue
			}
			id := str(r.domain["id"])
			lines = append(lines,
				" @d"+id+" host "+str(r.domain["name"]),
				" handle @d"+id+" {",
				upstream,
				" }",
			)
		}
		lines = append(lines, " handle {", fallback, " }", "}")
	}
	if delegated {
		// Caddy asks again when it loads a certificate it holds, so the
		// gateway answers names agreed to before itself and asks the control
		// plane only for new ones: a restart while the control plane is down
		// keeps delegated sites up (#166). A name agreed to since the last
		// reconcile is still asked for.
		lines[1] += "\n on_demand_tls {\n  ask http://" + askAddress + "/gateway/ask\n }"
		var known []string
		for _, n := range dicts(state["delegated_names"]) {
			// A delegated grant's one route is its catch-all (covers).
			if g, ok := grants[str(n["grant"])]; ok && g.Kind == "delegated" && len(grantRoutes[g.ID]) > 0 && zonePattern.MatchString(str(n["id"])) {
				known = append(known, "domain="+str(n["id"]))
			}
		}
		sort.Strings(known)
		lines = append(lines, "http://"+askAddress+" {", " bind 127.0.0.1")
		if len(known) > 0 {
			lines = append(lines, " @known query "+strings.Join(known, " "), " handle @known {", "  respond 200", " }")
		}
		lines = append(lines, " handle {", "  reverse_proxy "+controlAddress, " }", "}")
	}
	// Last, for any other name: Caddy keeps certificates it obtained on
	// demand after their site is gone, and without this site a request for
	// such a name gets an empty 200 (#166).
	lines = append(lines, "https:// {", " respond 404", "}")
	return strings.Join(lines, "\n") + "\n", hosts.String(), certificates
}

// controlAddress is where the gateway reaches the control plane.
const controlAddress = "10.200.0.3:8080"

// askAddress is the gateway's own answer to Caddy's on-demand question.
const askAddress = "127.0.0.1:2020"

// SyncGateway sends the gateway its configuration and returns the
// fingerprints of the pairs it now holds.
func (e *Execution) SyncGateway(state D) map[string]any {
	var origin D
	if crt, key, ok := e.originFiles(); ok {
		origin = originPair(crt, key)
	}
	var caddy, hosts string
	var certificates map[string]D
	func() {
		// A bad pair or route belongs to one tenant. Operators get the
		// details; whoever's operation ran the reconcile gets no other
		// tenant's names.
		defer func() {
			if r := recover(); r != nil {
				f, ok := r.(Failure)
				if !ok {
					panic(r)
				}
				slog.Error("gateway_config_rejected", "event", "gateway_config_rejected", "error", f.Result["error"])
				fail("backend_unavailable", "Gateway configuration rejected; use the operation ID for operator diagnostics", D{"component": "carrel-gateway", "recovery": "retry_infrastructure"})
			}
		}()
		caddy, hosts, certificates = gatewayConfig(state, originHost(e.P.Config), origin, dicts(state["certificates"]))
	}()
	pairs, held := D{}, map[string]any{}
	for name, pair := range certificates {
		pairs[name] = pair
		held[name] = fingerprint(pair["fullchain"])
	}
	e.Call(D{"op": "sync", "hosts": hosts, "caddy": caddy, "certificates": pairs}, "carrel-gateway")
	return held
}
