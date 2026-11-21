package carrel

import (
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

// tenantSlugs maps each tenant number to its slug.
func tenantSlugs(state D) map[int]string {
	slugs := map[int]string{}
	for _, t := range dicts(state["tenants"]) {
		if !labelPattern.MatchString(str(t["slug"])) {
			fail("conflict", "Invalid tenant slug")
		}
		slugs[integer(t["n"])] = str(t["slug"])
	}
	return slugs
}

// machineHosts indexes the machines by vmid and renders the internal hosts file.
func machineHosts(state D, slugs map[int]string) (map[int]D, string) {
	machines := map[int]D{}
	var hosts strings.Builder
	for _, m := range dicts(state["machines"]) {
		machines[integer(m["vmid"])] = m
		fmt.Fprintf(&hosts, "%s %s.%s.internal\n", str(m["ip"]), str(m["name"]), slugs[integer(m["tenant_n"])])
	}
	return machines, hosts.String()
}

// vipIndex indexes the virtual addresses a domain may point at (issue #146).
func vipIndex(state D) map[string]D {
	vips := map[string]D{}
	for _, v := range dicts(state["vips"]) {
		vips[str(v["id"])] = v
	}
	return vips
}

// grantIndex returns the special domain grants (PLAN 6.10) by id, and the ids
// of the SRV grants, which have no route.
func grantIndex(state D, slugs map[int]string, origin string) (map[string]domainGrant, map[string]bool) {
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
	return grants, srv
}

// frozenIndex maps the vmid of each frozen machine to its tenant. A frozen
// machine keeps its domains for its return (freeze.go). Its names stay routes
// of their own that answer 503 until the thaw: a missing route would hand them
// to the tenant's catch-all, and a route with no machine used to fail the
// configuration of every tenant.
func frozenIndex(state D) map[int]int {
	frozen := map[int]int{}
	for _, f := range dicts(state["frozen"]) {
		frozen[integer(f["vmid"])] = integer(f["tenant_n"])
	}
	return frozen
}

// functionIndex indexes the functions a domain may point at, with their
// host's router (PLAN 7.11).
func functionIndex(state D) map[string]D {
	functions := map[string]D{}
	for _, f := range dicts(state["function_routes"]) {
		functions[str(f["id"])] = f
	}
	return functions
}

// bundleIndex indexes the certificate bundles by slug.
func bundleIndex(bundles []D) map[string]D {
	byName := map[string]D{}
	for _, b := range bundles {
		byName[str(b["slug"])] = b
	}
	return byName
}

// domainRoutes returns the routes of the ready domains: by tenant slug, and by
// special domain grant id.
func domainRoutes(state D, slugs map[int]string, machines map[int]D, vips map[string]D, grants map[string]domainGrant, srv map[string]bool, frozen map[int]int, functions map[string]D) (map[string][]route, map[string][]route) {
	routes := map[string][]route{}
	grantRoutes := map[string][]route{}
	for _, d := range dicts(state["domains"]) {
		if d["state"] != "ready" {
			continue
		}
		var r route
		var slug string
		if str(d["function"]) != "" {
			r = functionRoute(d, functions)
			slug = slugs[integer(d["tenant_n"])]
			if id := str(d["grant"]); id != "" {
				if srv[id] {
					continue
				}
				g, ok := grants[id]
				if !ok || g.TenantN != integer(d["tenant_n"]) || !g.covers(str(d["name"])) {
					fail("conflict", "Invalid special domain")
				}
				grantRoutes[id] = append(grantRoutes[id], r)
				continue
			}
			checkTenantName(d, slug)
			routes[slug] = append(routes[slug], r)
			continue
		}
		owner, address := machineTarget(d, machines, vips, frozen)
		slug = slugs[owner]
		if id := str(d["grant"]); id != "" {
			if srv[id] {
				continue
			}
			g, ok := grants[id]
			if !ok || g.TenantN != integer(d["tenant_n"]) || owner != g.TenantN || !g.covers(str(d["name"])) {
				fail("conflict", "Invalid special domain")
			}
			grantRoutes[id] = append(grantRoutes[id], route{domain: d, address: address, port: targetPort(d, "Invalid tenant domain port")})
			continue
		}
		checkTenantName(d, slug)
		routes[slug] = append(routes[slug], route{domain: d, address: address, port: targetPort(d, "Invalid tenant domain port")})
	}
	return routes, grantRoutes
}

// functionRoute is the route of a domain that points at a function. A function
// removed, or on a host no longer configured, answers 503 like a frozen
// machine: never a failure for every tenant.
func functionRoute(d D, functions map[string]D) route {
	r := route{domain: d}
	f := functions[str(d["function"])]
	if f == nil || integer(f["tenant_n"]) != integer(d["tenant_n"]) {
		return r
	}
	host, port, err := net.SplitHostPort(str(f["router"]))
	p, _ := strconv.Atoi(port)
	if err == nil && net.ParseIP(host).To4() != nil && p > 0 && p < 65536 && functionHostPattern.MatchString(str(f["host_id"])) {
		r.address, r.port, r.function = host, p, str(f["host_id"])
	}
	return r
}

// machineTarget returns the tenant that owns the domain's target and its
// address, empty while the machine is frozen.
func machineTarget(d D, machines map[int]D, vips map[string]D, frozen map[int]int) (int, string) {
	var target D
	if d["vip"] != nil {
		target = vips[str(d["vip"])]
	} else {
		target = machines[integer(d["vmid"])]
	}
	owner := integer(d["tenant_n"])
	if n, parked := frozen[integer(d["vmid"])]; target == nil && d["vip"] == nil && parked && n == owner {
		// No address: the route answers 503 (forward).
		return owner, ""
	}
	if target == nil || (d["vip"] != nil && integer(target["tenant_n"]) != owner) {
		fail("conflict", "Invalid tenant domain")
	}
	if d["vip"] != nil {
		return integer(target["tenant_n"]), str(target["address"])
	}
	return integer(target["tenant_n"]), str(target["ip"])
}

// checkTenantName fails unless the domain is a name under its tenant's slug.
func checkTenantName(d D, slug string) {
	sub := str(d["sub"])
	if (sub != "*" && !labelPattern.MatchString(sub)) || str(d["name"]) != sub+"."+slug+".winlab.tw" {
		fail("conflict", "Invalid tenant domain")
	}
}

// targetPort is the domain's target port, or fails with msg.
func targetPort(d D, msg string) int {
	port := integer(d["target_port"])
	if port < 1 || port > 65535 {
		fail("conflict", msg)
	}
	return port
}

// appendOriginSite adds carrel's own origin site and its certificate pair.
func appendOriginSite(lines []string, certificates map[string]D, origin string, originBundle D) []string {
	if origin == "" || originBundle == nil {
		return lines
	}
	if !originPattern.MatchString(origin) {
		fail("conflict", "Invalid origin host")
	}
	// "_origin" is no tenant label, so no slug can take its directory.
	certificates["_origin"] = checkedPair(originBundle, origin)
	return append(lines,
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

// appendRoutes adds one named handle per route. The route for which
// catchAll is true becomes the fallback instead, and the fallback is returned.
func appendRoutes(lines []string, rs []route, catchAll func(route) bool) ([]string, string) {
	fallback := "  respond 404"
	for _, r := range rs {
		upstream := r.forward()
		if catchAll(r) {
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
	return lines, fallback
}

// appendTenantSites adds each tenant's wildcard site, in slug order.
func appendTenantSites(lines []string, certificates map[string]D, routes map[string][]route, byName map[string]D) []string {
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
		// Caddy runs a handle without a matcher after every named one, so a
		// domain of its own always wins over the catch-all.
		var fallback string
		lines, fallback = appendRoutes(lines, routes[slug], func(r route) bool { return r.domain["sub"] == "*" })
		lines = append(lines, " handle {", fallback, " }", "}")
	}
	return lines
}

// appendGrantSites adds the site of each special domain grant that has routes,
// in name order, and reports whether any is delegated.
func appendGrantSites(lines []string, certificates map[string]D, grants map[string]domainGrant, grantRoutes map[string][]route, byName map[string]D) ([]string, bool) {
	ids := make([]string, 0, len(grantRoutes))
	for id := range grantRoutes {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return grants[ids[i]].Name < grants[ids[j]].Name })
	delegated := false
	for _, id := range ids {
		g := grants[id]
		if g.Kind == "delegated" {
			delegated = true
			lines = appendDelegatedSite(lines, g, grantRoutes[id])
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
		if g.Kind == "exact" {
			// domain_proxy's check through Cloudflare reads this: only the
			// gateway knows the grant's id, so a stale host cannot pass (#166).
			lines = append(lines, " handle "+probePath+" {", "  respond \""+g.ID+"\" 200", " }")
		}
		var fallback string
		// The exact name, or a wildcard's catch-all.
		lines, fallback = appendRoutes(lines, grantRoutes[id], func(r route) bool { return r.domain["name"] == g.Name })
		lines = append(lines, " handle {", fallback, " }", "}")
	}
	return lines, delegated
}

// appendDelegatedSite adds a delegated grant's site. It uses the gateway's own
// certificates, issued when a name is first asked for, after carrel's ask
// endpoint agrees (PLAN 6.10): names one or two labels under the base.
func appendDelegatedSite(lines []string, g domainGrant, rs []route) []string {
	fallback := "  respond 404"
	for _, r := range rs {
		if r.domain["name"] == g.Name {
			fallback = r.forward()
		}
	}
	return append(lines, "https://*."+g.base()+", https://*.*."+g.base()+" {", " tls {", "  on_demand", " }", " handle {", fallback, " }", "}")
}

// appendOnDemandAsk adds the on-demand ask site. Caddy asks again when it
// loads a certificate it holds, so the gateway answers names agreed to before
// itself and asks the control plane only for new ones: a restart while the
// control plane is down keeps delegated sites up (#166). A name agreed to
// since the last reconcile is still asked for.
func appendOnDemandAsk(lines []string, state D, grants map[string]domainGrant, grantRoutes map[string][]route) []string {
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
	return append(lines, " handle {", "  reverse_proxy "+controlAddress, " }", "}")
}
