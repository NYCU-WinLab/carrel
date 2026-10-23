package carrel

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
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

// delegatedWeeklyNames bounds the new names one zone may have issued in 7
// days; Let's Encrypt allows 50 certificates per registered domain a week.
const delegatedWeeklyNames = 20

// Caddy neither throttles nor caches refusals (#166): every handshake for a
// new name asks again. A grant causes at most delegatedAsksPerMinute
// questions to its tenant a minute, and a refused name is answered from
// memory for delegatedRefusalSeconds.
const (
	delegatedAsksPerMinute  = 30
	delegatedRefusalSeconds = 60
	delegatedRefusalsKept   = 10000
)

// askLimiter holds the recent tenant questions per grant and the recent
// refusals per name.
type askLimiter struct {
	mu      sync.Mutex
	asks    map[string][]float64
	refused map[string]float64
}

// allow records a question to grant's tenant if the grant has room left this
// minute.
func (l *askLimiter) allow(grant string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.asks == nil {
		l.asks = map[string][]float64{}
	}
	t := now()
	recent := l.asks[grant][:0]
	for _, at := range l.asks[grant] {
		if at > t-60 {
			recent = append(recent, at)
		}
	}
	if len(recent) >= delegatedAsksPerMinute {
		l.asks[grant] = recent
		return false
	}
	l.asks[grant] = append(recent, t)
	return true
}

// refusal returns the reason name was refused recently, if it was.
func (l *askLimiter) refusal(name string) (string, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	until, ok := l.refused[name]
	if !ok || until < now() {
		return "", false
	}
	return "refused_recently", true
}

// refuse remembers a refusal of name.
func (l *askLimiter) refuse(name string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.refused == nil || len(l.refused) >= delegatedRefusalsKept {
		l.refused = map[string]float64{}
	}
	l.refused[name] = now() + delegatedRefusalSeconds
}

// delegatedName records a name carrel agreed to once. A pending one holds a
// place in the zone's budget while its tenant is asked.
type delegatedName struct {
	FirstAt int64  `json:"first_at"`
	Grant   string `json:"grant"`
	ID      string `json:"id"`
	Pending bool   `json:"pending,omitempty"`
	TenantN int    `json:"tenant_n"`
	Zone    string `json:"zone"`
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
	var route domainRecord
	for _, d := range e.grantDomains(g) {
		if d.State == "ready" && d.Name == g.Name {
			route = d
		}
	}
	if route.ID == "" {
		return false, "no_route"
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
	// A name agreed to before skips the limit, so renewals always pass.
	if n, seen := rowOf[delegatedName](e.S, "delegated_names", name); (!seen || n.Pending || n.Grant != g.ID) && !e.P.delegatedAsks.allow(g.ID) {
		return false, "rate_limited"
	}
	// The place in the budget is taken before the tenant is asked, under a
	// lock of its own, so concurrent asks cannot pass it together.
	if ok, why := e.reserveDelegated(g, name); !ok || why == "known" {
		return ok, why
	}
	agreed := e.tenantAgrees(address, route.TargetPort, name)
	e.P.delegated.Lock()
	defer e.P.delegated.Unlock()
	n, held := rowOf[delegatedName](e.S, "delegated_names", name)
	if !held || !n.Pending || n.Grant != g.ID {
		return false, "released"
	}
	if !agreed {
		e.S.Remove("delegated_names", name)
		return false, "tenant_refused"
	}
	n.Pending = false
	e.S.Put("delegated_names", name, g.TenantN, decode(string(encoded(n))))
	e.S.Log("system", g.TenantN, "delegated_name_allowed", D{"grant": g.ID, "name": name}, "ok")
	return true, "allowed"
}

// reserveDelegated answers a name agreed to before, or holds a place for it
// in the zone's weekly budget.
func (e *Execution) reserveDelegated(g domainGrant, name string) (bool, string) {
	e.P.delegated.Lock()
	defer e.P.delegated.Unlock()
	if n, seen := rowOf[delegatedName](e.S, "delegated_names", name); seen {
		switch {
		case n.Grant != g.ID:
			// Left by a released grant: this one has not agreed yet.
			e.S.Remove("delegated_names", name)
		case n.Pending && now()-float64(n.FirstAt) < 60:
			return false, "in_progress"
		case n.Pending:
			// An ask that never finished, such as across a restart.
			e.S.Remove("delegated_names", name)
		default:
			return true, "known"
		}
	}
	recent := 0
	for _, n := range rowsOf[delegatedName](e.S, "delegated_names") {
		if n.Zone == g.zone() && float64(n.FirstAt) > now()-7*86400 {
			recent++
		}
	}
	if recent >= delegatedWeeklyNames {
		return false, "weekly_budget"
	}
	e.S.Put("delegated_names", name, g.TenantN, decode(string(encoded(delegatedName{ID: name, Grant: g.ID, TenantN: g.TenantN, Zone: g.zone(), FirstAt: time.Now().Unix(), Pending: true}))))
	return true, "reserved"
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
		name := strings.ToLower(strings.TrimSuffix(r.URL.Query().Get("domain"), "."))
		if why, refused := p.delegatedAsks.refusal(name); refused {
			jsonResponse(w, 404, D{"ok": false, "reason": why})
			return
		}
		var ok bool
		var why string
		// Outside the writer: the tenant's answer can take seconds, and the
		// record it leaves is no infrastructure state.
		err := attempt(func() { ok, why = p.execution(r.Context()).AskDelegated(name) })
		// A pending name may still be agreed to, and a limited one is
		// asked again once the grant has room: neither is remembered.
		if err == nil && !ok && why != "in_progress" && why != "rate_limited" && len(name) <= 253 {
			p.delegatedAsks.refuse(name)
		}
		if err != nil || !ok {
			jsonResponse(w, 404, D{"ok": false, "reason": why})
			return
		}
		jsonResponse(w, 200, D{"ok": true})
	})
}
