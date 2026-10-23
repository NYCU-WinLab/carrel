package carrel

import (
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Special domains (PLAN 6.10): a name outside the tenant's own subtree
// *.<slug>.winlab.tw. A member files domain_request, an admin approves it,
// and the approved name becomes a grant of the tenant. domain_add with name
// then routes the granted name, or a name one label under a granted
// wildcard, to a machine like any other domain.
//
// Each grant has its own certificate lineage "_grant-<id>", issued through
// DNS-01 like the tenant wildcards. Its A record moves to the site only once
// the gateway holds that certificate, so a name taken over with adopt keeps
// answering where it did until carrel can serve it. A grant without domains
// stays the tenant's for grantUnusedDays, then it is released: its record and
// certificate go, and the name is free again.

const grantUnusedDays = 30

// maxPendingDomainRequests bounds the names one tenant can have waiting.
const maxPendingDomainRequests = 3

// domainGrant is one approved special name.
type domainGrant struct {
	Adopt       bool    `json:"adopt,omitempty"`
	GrantedAt   int64   `json:"granted_at"`
	ID          string  `json:"id"`
	IssuedAt    int64   `json:"issued_at,omitempty"`
	Kind        string  `json:"kind"`
	Name        string  `json:"name"`
	RequestID   string  `json:"request_id"`
	TenantN     int     `json:"tenant_n"`
	UnusedSince float64 `json:"unused_since,omitempty"`
	Zone        string  `json:"zone,omitempty"`
}

func (g domainGrant) D() D { return decode(string(encoded(g))) }

// zone is the managed zone the grant's name lives in; grants from before
// zones existed are in the site's own.
func (g domainGrant) zone() string { return or(g.Zone, specialZone) }

// lineage is the certificate name of the grant. "_" starts no tenant slug.
func (g domainGrant) lineage() string { return "_grant-" + g.ID }

// owner is the comment carrel writes on the grant's DNS record.
func (g domainGrant) owner() string { return "carrel:b09:grant:" + g.ID }

// base is the name a wildcard covers one label under; an exact grant is its
// own base.
func (g domainGrant) base() string { return strings.TrimPrefix(g.Name, "*.") }

// covers reports whether domain_add may publish name under this grant: the
// exact name, or for a wildcard the catch-all itself or one label under it.
func (g domainGrant) covers(name string) bool {
	if name == g.Name {
		return true
	}
	if g.Kind != "wildcard" {
		return false
	}
	label, rest, ok := strings.Cut(name, ".")
	return ok && rest == g.base() && labelPattern.MatchString(label)
}

func (e *Execution) grants(n ...int) []domainGrant {
	return rowsOf[domainGrant](e.S, "domain_grants", n...)
}

// grantCovering finds the tenant's grant that lets domain_add publish name:
// an exact grant of the name before a wildcard that covers it.
func (e *Execution) grantCovering(n int, name string) domainGrant {
	for _, g := range e.grants(n) {
		if g.Name == name {
			return g
		}
	}
	for _, g := range e.grants(n) {
		if g.covers(name) {
			return g
		}
	}
	fail("not_found", "No special domain grant of this tenant covers this name; file domain_request first", D{"recovery": "resolve_prerequisite"})
	return domainGrant{}
}

// specialZone is the site's own zone. Tenant slugs and platform names live in
// it; other zones are added with zone_add (zones.go).
const specialZone = "winlab.tw"

var specialLabel = `[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?`

// validSpecialName checks the shape of a requested name: lowercase DNS labels
// and a wildcard only as the first label. Which zone it belongs to is checked
// with the zones.
func validSpecialName(kind, name string) {
	rest := name
	if kind == "srv" {
		// _service._proto.<name>, as RFC 2782 names it.
		m := regexp.MustCompile(`^_[a-z0-9]([a-z0-9-]{0,13}[a-z0-9])?\._(tcp|udp)\.(.+)$`).FindStringSubmatch(name)
		if m == nil {
			fail("invalid", "An srv name is _service._tcp.<name> or _service._udp.<name>", D{"recovery": "revise_request"})
		}
		rest = m[3]
	} else if kind == "wildcard" {
		var ok bool
		if rest, ok = strings.CutPrefix(name, "*."); !ok {
			fail("invalid", "A wildcard name starts with *.", D{"recovery": "revise_request"})
		}
	} else if kind != "exact" {
		fail("invalid", "kind is exact, wildcard or srv", D{"recovery": "revise_request"})
	}
	if len(name) > 253 || !matches(`^(`+specialLabel+`\.)+[a-z]{2,63}$`, rest) {
		fail("invalid", "Name must be lowercase DNS labels", D{"recovery": "revise_request"})
	}
}

// relativeLabels gives the labels of a name above the site's zone, nearest
// the zone last: x.afc.winlab.tw -> [x afc].
func relativeLabels(name string) []string {
	return strings.Split(strings.TrimSuffix(strings.TrimPrefix(name, "*."), "."+specialZone), ".")
}

// under reports whether name is base or any name below it.
func under(name, base string) bool {
	name = strings.TrimPrefix(name, "*.")
	return name == base || strings.HasSuffix(name, "."+base)
}

// zoneRecords lists every record of a managed zone.
func (e *Execution) zoneRecords(z zoneAccess) []D {
	data := e.cfIn(z, "GET", "?per_page=5000", nil)
	if num(obj(data["result_info"])["total_pages"]) > 1 {
		fail("conflict", "Could not verify DNS namespace ownership")
	}
	return dicts(data["result"])
}

// addressRecord reports whether a record answers for a name the gateway
// would serve. TXT, MX and the rest of a name stay as they are.
func addressRecord(r D) bool {
	return r["type"] == "A" || r["type"] == "AAAA" || r["type"] == "CNAME"
}

// checkSpecialName applies the rules of PLAN 6.10 step 2 to a name tenant t
// wants. It returns the zone of the name and whether address records already
// exist at the name, which an approval must adopt. ignore is a request of t
// that the check is for.
func (e *Execution) checkSpecialName(t D, kind, name, ignore string) (string, bool) {
	validSpecialName(kind, name)
	zone, managed := e.zoneOf(name)
	if !managed {
		fail("invalid", "This name is in no zone carrel manages", D{"recovery": "revise_request"})
	}
	if !e.zoneOpen(zone, integer(t["n"])) {
		fail("forbidden", "This zone is not open to this tenant", D{"recovery": "revise_request"})
	}
	// Neither the zone's wildcard nor, in the site's zone, its apex: a
	// certificate for either would cover every name in the zone.
	if (strings.TrimPrefix(name, "*.") == zone && (kind == "wildcard" || zone == specialZone)) || (kind == "srv" && srvBase(name) == specialZone) {
		fail("invalid", "Request a name under the zone, not the zone itself", D{"recovery": "revise_request"})
	}
	if zone != specialZone {
		return zone, e.checkGrantOverlap(t, kind, name, ignore, zone)
	}
	labels := relativeLabels(name)
	top := labels[len(labels)-1]
	if contains(reservedLabels, top) || name == originHost(e.P.Config) || under(name, originHost(e.P.Config)) {
		fail("conflict", "This name is reserved for the platform", D{"recovery": "revise_request"})
	}
	for _, other := range e.S.Tenants() {
		owner := str(other["slug"]) + "." + specialZone
		if !under(name, owner) {
			continue
		}
		if integer(other["n"]) != integer(t["n"]) {
			fail("conflict", "This name is under another tenant's domain", D{"recovery": "revise_request"})
		}
		if name != owner && kind != "srv" {
			fail("invalid", "Names under "+owner+" need no request; use domain_add with sub", D{"recovery": "revise_request"})
		}
	}
	return zone, e.checkGrantOverlap(t, kind, name, ignore, zone)
}

// checkGrantOverlap refuses a name that overlaps another grant or pending
// request, or a wildcard over someone else's record, and reports whether
// address records exist at the name.
func (e *Execution) checkGrantOverlap(t D, kind, name, ignore, zone string) bool {
	// Another tenant's name, granted or asked for, may neither cover nor
	// sit under this one.
	overlaps := func(otherKind, other string) bool {
		if other == name {
			return true
		}
		if kind == "wildcard" && under(other, strings.TrimPrefix(name, "*.")) && other != strings.TrimPrefix(name, "*.") {
			return true
		}
		if otherKind == "wildcard" && under(name, strings.TrimPrefix(other, "*.")) && name != strings.TrimPrefix(other, "*.") {
			return true
		}
		// An SRV record speaks for the name it sits on: clients of that name
		// follow it. So the name, and everything under it, must be the
		// tenant's own.
		if kind == "srv" && otherKind != "srv" && under(srvBase(name), strings.TrimPrefix(other, "*.")) {
			return true
		}
		return kind != "srv" && otherKind == "srv" && under(srvBase(other), strings.TrimPrefix(name, "*."))
	}
	for _, g := range e.grants() {
		if overlaps(g.Kind, g.Name) && (g.TenantN != integer(t["n"]) || g.Name == name) {
			fail("conflict", "This name overlaps a granted special domain", D{"recovery": "revise_request"})
		}
	}
	for _, r := range e.S.Objects("requests") {
		if r["kind"] == "domain" && r["status"] == "pending" && r["id"] != ignore && overlaps(str(r["domain_kind"]), str(r["name"])) {
			fail("conflict", "A pending request already asks for an overlapping name", D{"recovery": "revise_request"})
		}
	}
	existing := false
	for _, r := range e.zoneRecords(e.zoneNamed(zone)) {
		if strings.HasPrefix(str(r["comment"]), "carrel:") {
			continue
		}
		recorded := str(r["name"])
		if kind == "wildcard" && under(recorded, strings.TrimPrefix(name, "*.")) && recorded != strings.TrimPrefix(name, "*.") && recorded != name {
			// A wildcard never covers a name that belongs to someone else.
			fail("conflict", "The wildcard would cover an existing name: "+recorded, D{"recovery": "revise_request"})
		}
		if recorded == name && (addressRecord(r) && kind != "srv" || r["type"] == "SRV" && kind == "srv") {
			existing = true
		}
		// Someone else's address at the name an SRV record would speak for
		// is taken over only with adopt.
		if kind == "srv" && recorded == srvBase(name) && addressRecord(r) {
			existing = true
		}
	}
	return existing
}

// DomainRequest files a request for a special domain (PLAN 6.10 step 1).
func (e *Execution) DomainRequest(a, w, t D) D {
	dry, n := boolean(a["dry_run"]), integer(t["n"])
	kind := str(fallback(a, "kind", "exact"))
	name := strings.ToLower(strings.TrimSuffix(str(a["name"]), "."))
	key := str(a["idempotency_key"])
	fingerprint := digest(string(encoded(D{"kind": kind, "name": name, "reason": a["reason"]})))
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
	zone, existing := e.checkSpecialName(t, kind, name, "")
	pending := filter(e.S.Objects("requests", n), func(r D) bool { return r["kind"] == "domain" && r["status"] == "pending" })
	if len(pending) >= maxPendingDomainRequests {
		fail("quota_exceeded", "A tenant has at most 3 pending domain requests; wait for a decision", D{"recovery": "revise_request"})
	}
	r := D{"id": randomID()[:16], "tenant_n": n, "kind": "domain", "status": "pending", "domain_kind": kind, "name": name, "zone": zone, "reason": a["reason"], "existing_record": existing, "actor": w["sub"], "created_at": time.Now().Unix()}
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

// approveDomain decides a domain request. The rules are checked again: the
// zone may have changed since the member asked.
func (e *Execution) approveDomain(tool string, a, w, r, t D) D {
	dry := boolean(a["dry_run"])
	if tool == "request_approve" {
		zone, existing := e.checkSpecialName(t, str(r["domain_kind"]), str(r["name"]), str(r["id"]))
		r["zone"] = zone
		if existing && !boolean(a["adopt"]) {
			if r["domain_kind"] == "srv" {
				fail("conflict", "The name already has records of someone else; approve with adopt to let this tenant's SRV record speak for it (other SRV records at the name are replaced, its address records stay)", D{"recovery": "revise_request"})
			}
			fail("conflict", "The name already has address records; approve with adopt to replace them", D{"recovery": "revise_request"})
		}
	}
	n := integer(t["n"])
	g := domainGrant{ID: randomID()[:16], TenantN: n, Kind: str(r["domain_kind"]), Name: str(r["name"]), RequestID: str(r["id"]), Adopt: boolean(a["adopt"]), GrantedAt: time.Now().Unix(), UnusedSince: now()}
	if zone := str(r["zone"]); zone != specialZone {
		g.Zone = zone
	}
	switch {
	case dry && tool == "request_approve":
		r["status"] = "planned_approval"
	case dry:
		r["status"] = "planned_rejection"
	default:
		e.Transaction(func(tx *Execution) {
			if tool == "request_approve" {
				tx.Put("domain_grants", g.ID, n, g)
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

// EnsureGrantCertificate issues or renews the grant's certificate. A first
// issuance waits while the 7-day budget is used up.
func (e *Execution) EnsureGrantCertificate(g domainGrant) D {
	if g.Kind == "srv" {
		// An SRV record names a public port; there is nothing to encrypt.
		return D{"state": "ready"}
	}
	e.P.certificates.Lock()
	defer e.P.certificates.Unlock()
	if e.P.certificatePrepare != nil {
		return e.P.certificatePrepare(merge(g.D(), D{"grant": true}))
	}
	crt, _, ok := e.livePair(g.lineage())
	if ok && !renewalDue(crt) {
		return D{"state": "ready"}
	}
	if !ok {
		if issued := recentIssuance(e.S); len(issued) >= 30 {
			earliest := now()
			for _, c := range issued {
				earliest = min(earliest, float64(c.IssuedAt))
			}
			return D{"state": "queued", "ready_at": earliest + 7*86400}
		}
	}
	e.issueCertificate(g.lineage(), g.Name)
	// The issuance counts against the budget from now on.
	if current, found := rowOf[domainGrant](e.S, "domain_grants", g.ID); found {
		current.IssuedAt = time.Now().Unix()
		e.S.Put("domain_grants", current.ID, current.TenantN, decode(string(encoded(current))))
	}
	return D{"state": "ready"}
}

// grantCertificateHeld reports whether the gateway confirmed the grant's
// current certificate.
func (e *Execution) grantCertificateHeld(g domainGrant) bool {
	crt, _, ok := e.livePair(g.lineage())
	return ok && e.gatewayHolds(g.lineage(), crt)
}

// GrantRecord points the grant's name at the site once the gateway holds its
// certificate, or removes the record carrel wrote. Address records someone
// else wrote are replaced only for a grant approved with adopt.
func (e *Execution) GrantRecord(g domainGrant, remove bool) {
	if g.Kind == "srv" {
		e.srvRecord(g, remove)
		return
	}
	z := e.zoneNamed(g.zone())
	records := dicts(e.cfIn(z, "GET", "?name="+url.QueryEscape(g.Name), nil)["result"])
	ours, foreign := []D{}, []D{}
	for _, r := range records {
		if r["comment"] == g.owner() {
			ours = append(ours, r)
		} else if addressRecord(r) {
			foreign = append(foreign, r)
		}
	}
	if remove {
		for _, r := range ours {
			e.cfIn(z, "DELETE", "/"+str(r["id"]), nil)
		}
		return
	}
	address := str(e.P.Config["public_address"])
	if len(ours) == 1 && len(foreign) == 0 && ours[0]["type"] == "A" && ours[0]["content"] == address {
		return
	}
	if !e.grantCertificateHeld(g) {
		return
	}
	if len(foreign) > 0 && !g.Adopt {
		fail("conflict", "Refusing DNS record owned outside carrel")
	}
	// One A record of someone else's changes in place, so the name never
	// stops resolving; anything else is replaced.
	if len(ours) == 0 && len(foreign) == 1 && foreign[0]["type"] == "A" {
		e.cfIn(z, "PATCH", "/"+str(foreign[0]["id"]), D{"content": address, "ttl": 120, "proxied": false, "comment": g.owner()})
		slog.Info("grant_record_adopted", "grant", g.ID, "name", g.Name, "previous", foreign[0]["content"])
		return
	}
	for _, r := range foreign {
		e.cfIn(z, "DELETE", "/"+str(r["id"]), nil)
		slog.Info("grant_record_adopted", "grant", g.ID, "name", g.Name, "previous", r["content"], "type", r["type"])
	}
	for i, r := range ours {
		if i == 0 && r["type"] == "A" {
			if r["content"] != address {
				e.cfIn(z, "PATCH", "/"+str(r["id"]), D{"content": address})
			}
			continue
		}
		e.cfIn(z, "DELETE", "/"+str(r["id"]), nil)
	}
	if len(ours) == 0 || ours[0]["type"] != "A" {
		e.cfIn(z, "POST", "", D{"type": "A", "name": g.Name, "content": address, "ttl": 120, "proxied": false, "comment": g.owner()})
	}
}

// grantDomains lists the live domains under a grant.
func (e *Execution) grantDomains(g domainGrant) []domainRecord {
	out := []domainRecord{}
	for _, d := range e.domains(g.TenantN) {
		if d.Grant == g.ID && d.State != "deleting" {
			out = append(out, d)
		}
	}
	return out
}

// MaintainGrants renews the certificates of grants in use, moves their
// records once the gateway holds them, and releases grants unused for
// grantUnusedDays. It runs without the writer, like MaintainDomains.
func (e *Execution) MaintainGrants() {
	for _, original := range e.grants() {
		err := attempt(func() {
			live := e.grantDomains(original)
			if len(live) > 0 {
				if crt, _, ok := e.livePair(original.lineage()); ok && renewalDue(crt) {
					e.EnsureGrantCertificate(original)
				}
			}
			e.P.writer.Lock()
			defer e.P.writer.Unlock()
			g, ok := rowOf[domainGrant](e.S, "domain_grants", original.ID)
			if !ok {
				return
			}
			live = e.grantDomains(g)
			switch {
			case len(live) > 0 && g.UnusedSince != 0:
				g.UnusedSince = 0
				e.S.Put("domain_grants", g.ID, g.TenantN, g.D())
			case len(live) == 0 && g.UnusedSince == 0:
				g.UnusedSince = now()
				e.S.Put("domain_grants", g.ID, g.TenantN, g.D())
			case len(live) == 0 && now()-g.UnusedSince > grantUnusedDays*86400:
				e.releaseGrant(g, "unused")
				return
			}
			if _, _, held := e.livePair(g.lineage()); held || g.Kind == "srv" {
				e.GrantRecord(g, false)
			}
		})
		if err != nil {
			failure := obj(failureResult(err)["error"])
			slog.Warn("grant_maintenance_failed", "grant", original.ID, "code", failure["code"], "backend_code", failure["backend_code"])
		}
	}
}

// releaseGrant gives a name back: its record goes first, then the grant and
// its request together, then the gateway stops serving it, then its
// certificate. A name taken over with adopt is not restored: the old records
// were replaced on purpose, and only the log keeps what they said.
func (e *Execution) releaseGrant(g domainGrant, why string) {
	e.GrantRecord(g, true)
	e.Transaction(func(tx *Execution) {
		tx.S.Remove("domain_grants", g.ID)
		if r := tx.S.Get("requests", g.RequestID); r != nil {
			r["status"] = "released"
			r["released_at"] = time.Now().Unix()
			tx.S.Put("requests", g.RequestID, g.TenantN, r)
		}
	})
	e.S.Log("system", g.TenantN, "domain_grant_released", D{"grant": g.ID, "name": g.Name, "reason": why}, "ok")
	// A failed pass leaves the site to the next reconcile, which no longer
	// has the grant; the pair goes only once the gateway dropped it.
	e.Reconcile()
	_ = os.RemoveAll(filepath.Join(e.CertificateDir(), "live", g.lineage()))
	_ = os.RemoveAll(filepath.Join(e.CertificateDir(), "archive", g.lineage()))
}

// publicGrants is the tenant's grants as domain_list shows them.
func (e *Execution) publicGrants(n int) []D {
	out := []D{}
	for _, g := range e.grants(n) {
		p := D{"name": g.Name, "kind": g.Kind, "state": "in_use"}
		if g.UnusedSince != 0 {
			p["state"] = "unused"
			p["release_at"] = time.Unix(int64(g.UnusedSince)+grantUnusedDays*86400, 0).UTC().Format(time.RFC3339)
		}
		out = append(out, p)
	}
	return out
}

// grantBundles gives the gateway the pairs of grants with ready domains.
func (e *Execution) grantBundles(domains []D) []D {
	wanted := map[string]bool{}
	for _, d := range domains {
		if d["state"] == "ready" && str(d["grant"]) != "" {
			wanted[str(d["grant"])] = true
		}
	}
	out := []D{}
	for _, g := range e.grants() {
		if !wanted[g.ID] || g.Kind == "srv" {
			continue
		}
		crt, key, ok := e.livePair(g.lineage())
		if !ok {
			fail("backend_unavailable", "A special domain certificate is missing", D{"component": "acme", "backend_code": "certificate_missing", "recovery": "retry_infrastructure"})
		}
		out = append(out, merge(D{"slug": g.lineage(), "grant": g.ID, "name": g.Name}, originPair(crt, key)))
	}
	return out
}

// srvBase is the name an SRV record is about: _mc._tcp.mc.winlab.tw ->
// mc.winlab.tw.
func srvBase(name string) string {
	parts := strings.SplitN(name, ".", 3)
	if len(parts) < 3 {
		return name
	}
	return parts[2]
}

// srvProto is the protocol an SRV name gives.
func srvProto(name string) string {
	if strings.Contains(name, "._udp.") {
		return "udp"
	}
	return "tcp"
}

// openPortFor finds the tenant's open public port that forwards to the
// target of a domain row or request.
func (e *Execution) openPortFor(n, vmid int, vip string, port int, proto string) (portGrant, bool) {
	for _, p := range e.ports(n) {
		if p.State != "deleting" && p.VMID == vmid && p.VIP == vip && p.Port == port && p.Proto == proto {
			return p, true
		}
	}
	return portGrant{}, false
}

// srvRecord points an SRV grant at the public port that forwards to its
// domain's target, on carrel's own host name, or removes the record carrel
// wrote once no port forwards there.
func (e *Execution) srvRecord(g domainGrant, remove bool) {
	z := e.zoneNamed(g.zone())
	records := dicts(e.cfIn(z, "GET", "?name="+url.QueryEscape(g.Name), nil)["result"])
	ours, foreign := []D{}, []D{}
	for _, r := range records {
		if r["comment"] == g.owner() {
			ours = append(ours, r)
		} else if r["type"] == "SRV" {
			foreign = append(foreign, r)
		}
	}
	port := 0
	if live := e.grantDomains(g); len(live) > 0 {
		if p, ok := e.openPortFor(g.TenantN, live[0].VMID, live[0].VIP, live[0].TargetPort, srvProto(g.Name)); ok {
			port = p.PublicPort
		}
	}
	if remove || port == 0 {
		for _, r := range ours {
			e.cfIn(z, "DELETE", "/"+str(r["id"]), nil)
		}
		return
	}
	if len(foreign) > 0 && !g.Adopt {
		fail("conflict", "Refusing DNS record owned outside carrel")
	}
	for _, r := range foreign {
		e.cfIn(z, "DELETE", "/"+str(r["id"]), nil)
		slog.Info("grant_record_adopted", "grant", g.ID, "name", g.Name, "previous", r["content"], "type", "SRV")
	}
	data := D{"priority": 0, "weight": 0, "port": port, "target": originHost(e.P.Config)}
	for i, r := range ours {
		if i == 0 {
			if current := obj(r["data"]); integer(current["port"]) != port || current["target"] != data["target"] {
				e.cfIn(z, "PATCH", "/"+str(r["id"]), D{"data": data})
			}
			continue
		}
		e.cfIn(z, "DELETE", "/"+str(r["id"]), nil)
	}
	if len(ours) == 0 {
		e.cfIn(z, "POST", "", D{"type": "SRV", "name": g.Name, "data": data, "ttl": 120, "proxied": false, "comment": g.owner()})
	}
}
