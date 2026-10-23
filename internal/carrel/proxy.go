package carrel

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// The Cloudflare proxy (PLAN 6.10): an admin may proxy an exact special
// domain one label under its zone, since Cloudflare's free edge certificate
// covers only one label. Cloudflare then connects to the gateway with the
// name as SNI, and the grant's own certificate answers. carrel cannot read a
// zone's SSL mode with a DNS token, so it checks the result instead: the
// record turns proxied first, carrel asks the name through Cloudflare, and
// only an answer from Cloudflare that reached the gateway keeps it. Anything
// else, a failed write included, puts the record back; the grant records
// proxied only after the check passed, so maintenance never turns on what
// the check did not see work.

// DomainProxy turns the Cloudflare proxy of a grant on or off.
func (e *Execution) DomainProxy(a, w D) D {
	name := strings.ToLower(strings.TrimSuffix(str(a["name"]), "."))
	want, dry := boolean(a["proxied"]), boolean(a["dry_run"])
	var g domainGrant
	found := false
	for _, x := range e.grants() {
		if x.Name == name {
			g, found = x, true
		}
	}
	if !found {
		fail("not_found", "No special domain grant has this name")
	}
	if g.Kind != "exact" {
		fail("invalid", "Only an exact name can be proxied", D{"recovery": "revise_request"})
	}
	if rest, ok := strings.CutSuffix(name, "."+g.zone()); !ok || strings.Contains(rest, ".") {
		fail("invalid", "Only a name one label under its zone can be proxied: Cloudflare's edge certificate covers no more", D{"recovery": "revise_request"})
	}
	z := e.zoneNamed(g.zone())
	record := e.gatewayRecord(z, g)
	if record == nil {
		fail("conflict", "The name does not point at the gateway yet; publish it with domain_add first", D{"recovery": "resolve_prerequisite"})
	}
	// The record in DNS, not the stored flag, says whether there is work.
	if dry || (boolean(record["proxied"]) == want && g.Proxied == want) {
		return D{"domain": D{"name": name, "proxied": want}, "dry_run": dry}
	}
	if !want {
		e.storeProxied(g, false)
		e.patchProxied(z, record, false)
		e.S.Log(str(w["sub"]), g.TenantN, "domain_proxied", D{"grant": g.ID, "name": name, "proxied": false}, "ok")
		return D{"domain": D{"name": name, "proxied": false}, "dry_run": false}
	}
	kept := false
	defer func() {
		if !kept {
			// A fresh context: the caller may have gone, the record must not
			// stay proxied.
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			back := *e
			back.Ctx = ctx
			_ = attempt(func() { back.patchProxied(z, record, false) })
		}
	}()
	e.patchProxied(z, record, true)
	if why := e.probeProxied(name); why != "" {
		fail("conflict", "Through Cloudflare the name did not reach the gateway ("+why+"); the proxy is off again. Set the zone's SSL mode to Full (strict) first", D{"recovery": "resolve_prerequisite"})
	}
	e.storeProxied(g, true)
	kept = true
	e.S.Log(str(w["sub"]), g.TenantN, "domain_proxied", D{"grant": g.ID, "name": name, "proxied": true}, "ok")
	return D{"domain": D{"name": name, "proxied": true}, "dry_run": false}
}

// gatewayRecord is the grant's own A record once it points at the site.
func (e *Execution) gatewayRecord(z zoneAccess, g domainGrant) D {
	for _, r := range dicts(e.cfIn(z, "GET", "?name="+url.QueryEscape(g.Name), nil)["result"]) {
		if r["comment"] == g.owner() && r["type"] == "A" && r["content"] == e.P.Config["public_address"] {
			return r
		}
	}
	return nil
}

func (e *Execution) patchProxied(z zoneAccess, record D, on bool) {
	ttl := 120
	if on {
		ttl = 1
	}
	e.cfIn(z, "PATCH", "/"+str(record["id"]), D{"proxied": on, "ttl": ttl})
}

func (e *Execution) storeProxied(g domainGrant, on bool) {
	current, ok := rowOf[domainGrant](e.S, "domain_grants", g.ID)
	if !ok {
		fail("conflict", "The grant was released meanwhile")
	}
	current.Proxied = on
	e.S.Put("domain_grants", current.ID, current.TenantN, current.D())
}

// probeProxied asks https://name through Cloudflare and says why it failed,
// or "" when Cloudflare answered from the gateway.
func (e *Execution) probeProxied(name string) string {
	if e.P.proxyProbe != nil {
		return e.P.proxyProbe(name)
	}
	address := str(e.P.Config["public_address"])
	// Cloudflare's own resolver answers the proxied record at once; the
	// local one may still hold the old address for its TTL.
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, "1.1.1.1:53")
	}}
	var edge string
	for deadline := time.Now().Add(20 * time.Second); edge == "" && time.Now().Before(deadline); {
		ctx, cancel := context.WithTimeout(e.Ctx, 5*time.Second)
		ips, err := resolver.LookupHost(ctx, name)
		cancel()
		if err == nil && len(ips) > 0 && ips[0] != address {
			edge = ips[0]
		} else if !sleep(e.Ctx, 2*time.Second) {
			return "canceled"
		}
	}
	if edge == "" {
		return "the name still resolves to the gateway"
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	client := &http.Client{
		Timeout:       20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{ServerName: name},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, net.JoinHostPort(edge, "443"))
			},
		},
	}
	resp, err := client.Get("https://" + name + "/")
	if err != nil {
		return "no answer from Cloudflare"
	}
	resp.Body.Close()
	// Only Cloudflare's edge sets cf-ray: an old host the name still points
	// at proves nothing.
	if resp.Header.Get("Cf-Ray") == "" {
		return "the answer did not come from Cloudflare"
	}
	if resp.StatusCode >= 520 && resp.StatusCode <= 530 {
		return "Cloudflare answered " + resp.Status
	}
	// Cloudflare's own refusals carry cf-mitigated; the gateway sent none.
	if resp.Header.Get("Cf-Mitigated") != "" {
		return "Cloudflare answered with a challenge"
	}
	// The gateway's own redirect, back to the very URL asked for; an app's
	// redirect elsewhere on the name is an answer.
	if resp.StatusCode >= 300 && resp.StatusCode < 400 && resp.Header.Get("Location") == "https://"+name+"/" {
		return "a redirect to itself, as Flexible mode makes"
	}
	return ""
}
