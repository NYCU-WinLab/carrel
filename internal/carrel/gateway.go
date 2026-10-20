package carrel

import (
	"crypto/tls"
	"crypto/x509"
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
// only the names in the database.

var controlPaths = []string{"/mcp", "/mcp/*", "/oauth/*", "/.well-known/*", "/healthz", "/status", "/internal/*", "/apps/*"}

const gatewayCerts = "/etc/caddy/carrel-certs"

var (
	labelPattern  = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	originPattern = regexp.MustCompile(`^([a-z0-9-]+\.)+winlab\.tw$`)
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
	type route struct {
		domain, machine D
		port            int
	}
	routes := map[string][]route{}
	for _, d := range dicts(state["domains"]) {
		if d["state"] != "ready" {
			continue
		}
		m := machines[integer(d["vmid"])]
		slug := slugs[integer(m["tenant_n"])]
		if m == nil || !labelPattern.MatchString(str(d["sub"])) || str(d["name"]) != str(d["sub"])+"."+slug+".winlab.tw" {
			fail("conflict", "Invalid tenant domain")
		}
		port := integer(d["target_port"])
		if port < 1 || port > 65535 {
			fail("conflict", "Invalid tenant domain port")
		}
		routes[slug] = append(routes[slug], route{d, m, port})
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
		for _, r := range routes[slug] {
			id := str(r.domain["id"])
			lines = append(lines,
				" @d"+id+" host "+str(r.domain["name"]),
				" handle @d"+id+" {",
				fmt.Sprintf("  reverse_proxy %s:%d", str(r.machine["ip"]), r.port),
				" }",
			)
		}
		lines = append(lines, " handle {", "  respond 404", " }", "}")
	}
	return strings.Join(lines, "\n") + "\n", hosts.String(), certificates
}

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
