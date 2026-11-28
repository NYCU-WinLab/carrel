package carrel

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"regexp"
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

// The service paths are the public ones only: the host agents' paths
// (/services/v1/agent/*) stay on the infra network, and so do the guests'
// /internal/* paths, which they call on 10.200.0.3:8080 directly (#262).
var controlPaths = []string{"/mcp", "/mcp/*", "/oauth/*", "/.well-known/*", "/healthz", "/status", "/openapi.json", "/v1/*", "/apps/*", "/console/*",
	"/services/v1/env/*", "/services/v1/registry/*", "/services/v1/deploy/*"}

const gatewayCerts = "/etc/caddy/carrel-certs"

var (
	labelPattern  = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	originPattern = regexp.MustCompile(`^([a-z0-9-]+\.)+[a-z]{2,63}$`)
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

// route is one name the gateway serves and where its requests go.
type route struct {
	domain  D
	address string
	port    int
	// service names the service on its host, t<tenant>-<name>, when the
	// route goes to a service host's router.
	service string
}

// forward is the route's Caddy directive: its machine or virtual address, or
// 503 while the machine it names is frozen. A service's route tells the
// router which service the request is for; header_up replaces whatever the
// client sent in that header.
func (r route) forward() string {
	if r.address == "" {
		return "  respond 503"
	}
	if r.service != "" {
		return fmt.Sprintf("  reverse_proxy %s:%d {\n   header_up X-Carrel-Service %s\n   flush_interval -1\n  }", r.address, r.port, r.service)
	}
	return fmt.Sprintf("  reverse_proxy %s:%d", r.address, r.port)
}

// gatewayConfig returns the gateway's Caddyfile, hosts file and certificate
// pairs for the desired state. Each source of the state has its own builder
// (gateway_sources.go); this only calls them in order and renders the result.
func gatewayConfig(state D, origin string, originBundle D, bundles []D) (string, string, map[string]D) {
	slugs := tenantSlugs(state)
	machines, hosts := machineHosts(state, slugs)
	vips := vipIndex(state)
	grants, srv := grantIndex(state, slugs, origin)
	frozen := frozenIndex(state)
	services := serviceIndex(state)
	routes, grantRoutes := domainRoutes(state, slugs, machines, vips, grants, srv, frozen, services)
	byName := bundleIndex(bundles)
	// strict_sni_host: a request's Host must be the name its TLS handshake
	// was for, so a connection made for one site cannot ask another (#166).
	lines := []string{"{", " auto_https off", " servers {", "  strict_sni_host on", " }", "}", "http:// {", " redir https://{host}{uri} 308", "}"}
	certificates := map[string]D{}
	lines = appendOriginSite(lines, certificates, origin, originBundle)
	lines = appendTenantSites(lines, certificates, routes, byName)
	lines, delegated := appendGrantSites(lines, certificates, grants, grantRoutes, byName)
	if delegated {
		lines = appendOnDemandAsk(lines, state, grants, grantRoutes)
	}
	// Last, for any other name: Caddy keeps certificates it obtained on
	// demand after their site is gone, and without this site a request for
	// such a name gets an empty 200 (#166).
	lines = append(lines, "https:// {", " respond 404", "}")
	return strings.Join(lines, "\n") + "\n", hosts, certificates
}

// controlAddress is where the gateway reaches the control plane.
const controlAddress = "10.200.0.3:8080"

// probePath is where an exact grant's site answers with its grant id.
const probePath = "/.well-known/carrel/probe"

// askAddress is the gateway's own answer to Caddy's on-demand question.
const askAddress = "127.0.0.1:2020"

// gatewaySync is everything one gateway sync sends, as plain data: it holds no
// *Execution and no store handle, so it can be sent from another goroutine.
type gatewaySync struct {
	hosts string
	caddy string
	pairs D
	held  map[string]any
}

// BuildGatewaySync reads the store and renders the gateway's configuration for
// the desired state. It does not send anything.
func (e *Execution) BuildGatewaySync(state D) gatewaySync {
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
		// The frozen machines and the services' routers are for this
		// configuration only: the nodes get the state as it was.
		view := D{"frozen": e.S.Objects("frozen"), pluginObjectRows: e.S.Objects(pluginObjectRows), "service_routes": e.serviceRoutes()}
		for k, v := range state {
			view[k] = v
		}
		caddy, hosts, certificates = gatewayConfig(view, e.P.Config.OriginHost(), origin, dicts(state["certificates"]))
	}()
	pairs, held := D{}, map[string]any{}
	for name, pair := range certificates {
		pairs[name] = pair
		held[name] = fingerprint(pair["fullchain"])
	}
	return gatewaySync{hosts: hosts, caddy: caddy, pairs: pairs, held: held}
}

// sendGatewaySync sends a built sync to the gateway and returns the
// fingerprints of the pairs it now holds. It does not read the store.
func (e *Execution) sendGatewaySync(g gatewaySync) map[string]any {
	e.Call(D{"op": "sync", "hosts": g.hosts, "caddy": g.caddy, "certificates": g.pairs}, "carrel-gateway")
	return g.held
}

// SyncGateway sends the gateway its configuration and returns the
// fingerprints of the pairs it now holds.
func (e *Execution) SyncGateway(state D) map[string]any {
	return e.sendGatewaySync(e.BuildGatewaySync(state))
}
