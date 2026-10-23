package carrel

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Delegated names (PLAN 6.10): a grant *.<base> in a zone of one tenant
// alone, whose names one or two labels under base the gateway serves with
// certificates it obtains itself when a name is first asked for. Before each
// issuance Caddy asks GET /gateway/ask?domain=<name>; carrel answers 200 only
// for a name under a delegated grant with a ready route, within the grant's
// weekly budget, and after the tenant's machine agreed: its target port must
// answer GET /.well-known/carrel/ask?domain=<name> with 200. A name asked for
// before is answered from the record, so renewals spend no budget.

// delegatedWeeklyNames bounds the new names one grant may have issued in 7
// days; Let's Encrypt allows 50 certificates per registered domain a week.
const delegatedWeeklyNames = 20

// delegatedName records a name carrel agreed to once.
type delegatedName struct {
	Grant   string `json:"grant"`
	ID      string `json:"id"`
	FirstAt int64  `json:"first_at"`
	TenantN int    `json:"tenant_n"`
}

// gatewayAddress is where the gateway's own requests come from.
const gatewayAddress = "10.200.0.2"

// delegatedGrantFor finds the delegated grant serving name, one or two labels
// under its base.
func (e *Execution) delegatedGrantFor(name string) (domainGrant, bool) {
	for _, g := range e.grants() {
		if g.Kind != "delegated" {
			continue
		}
		rest, ok := strings.CutSuffix(name, "."+g.base())
		if !ok {
			continue
		}
		labels := strings.Split(rest, ".")
		if len(labels) > 2 {
			continue
		}
		valid := true
		for _, l := range labels {
			valid = valid && matches(`^`+specialLabel+`$`, l)
		}
		if valid {
			return g, true
		}
	}
	return domainGrant{}, false
}

// AskDelegated decides whether the gateway may obtain a certificate for name.
func (e *Execution) AskDelegated(name string) (bool, string) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if len(name) > 253 || !zonePattern.MatchString(name) {
		return false, "invalid_name"
	}
	g, ok := e.delegatedGrantFor(name)
	if !ok {
		return false, "no_grant"
	}
	if t := e.S.TenantN(g.TenantN); t == nil || t["status"] != "active" {
		return false, "tenant_inactive"
	}
	if _, seen := rowOf[delegatedName](e.S, "delegated_names", name); seen {
		return true, "known"
	}
	var route domainRecord
	for _, d := range e.grantDomains(g) {
		if d.State == "ready" && d.Name == g.Name {
			route = d
		}
	}
	if route.ID == "" {
		return false, "no_route"
	}
	recent := 0
	for _, n := range rowsOf[delegatedName](e.S, "delegated_names", g.TenantN) {
		if n.Grant == g.ID && float64(n.FirstAt) > now()-7*86400 {
			recent++
		}
	}
	if recent >= delegatedWeeklyNames {
		return false, "weekly_budget"
	}
	address := ""
	if route.VIP != "" {
		for _, v := range e.vips(g.TenantN) {
			if v.ID == route.VIP {
				address = v.Address
			}
		}
	} else if m := find(e.S.Objects("machines", g.TenantN), func(m D) bool { return integer(m["vmid"]) == route.VMID }); m != nil {
		address = str(m["ip"])
	}
	if address == "" {
		return false, "no_target"
	}
	if !e.tenantAgrees(address, route.TargetPort, name) {
		return false, "tenant_refused"
	}
	e.S.Put("delegated_names", name, g.TenantN, decode(string(encoded(delegatedName{ID: name, Grant: g.ID, TenantN: g.TenantN, FirstAt: time.Now().Unix()}))))
	e.S.Log("system", g.TenantN, "delegated_name_allowed", D{"grant": g.ID, "name": name}, "ok")
	return true, "allowed"
}

// tenantAgrees asks the tenant's ask_url, on the route's target.
func (e *Execution) tenantAgrees(address string, port int, name string) bool {
	if e.P.tenantAsk != nil {
		return e.P.tenantAsk(address, port, name)
	}
	ctx, cancel := context.WithTimeout(e.Ctx, 3*time.Second)
	defer cancel()
	u := "http://" + net.JoinHostPort(address, str(port)) + "/.well-known/carrel/ask?domain=" + url.QueryEscape(name)
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return false
	}
	// No redirects: the answer must come from the machine itself.
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == 200
}

// askRoute answers the gateway's on-demand TLS question. Only the gateway
// may ask: the path is not one the public origin forwards, and the source
// must be the gateway's address.
func (a *App) askRoute(mux *http.ServeMux, p *Platform) {
	mux.HandleFunc("GET /gateway/ask", func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		if host != gatewayAddress {
			jsonResponse(w, 403, D{"ok": false})
			return
		}
		var ok bool
		var why string
		// Outside the writer: the tenant's answer can take seconds, and the
		// record it leaves is no infrastructure state.
		err := attempt(func() { ok, why = p.execution(r.Context()).AskDelegated(r.URL.Query().Get("domain")) })
		if err != nil || !ok {
			jsonResponse(w, 404, D{"ok": false, "reason": why})
			return
		}
		jsonResponse(w, 200, D{"ok": true})
	})
}
