package carrel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Waiting struct {
	Phase   string
	ReadyAt float64
}

// CF reads or writes a DNS record of the site's own zone.
func (e *Execution) CF(method, path string, body any) D {
	return e.cfIn(e.siteZone(), method, path, body)
}

// cfIn reads or writes a DNS record of zone z.
func (e *Execution) cfIn(z zoneAccess, method, path string, body any) D {
	return e.cloudflare(z.Token, method, "/zones/"+z.ID+"/dns_records"+path, body)
}

// cloudflare calls the Cloudflare API with token.
func (e *Execution) cloudflare(token, method, path string, body any) D {
	base := textAt(e.P.Config, "cloudflare_api", "https://api.cloudflare.com/client/v4")
	var data io.Reader
	if body != nil {
		data = bytes.NewReader(encoded(body))
	}
	req, err := http.NewRequestWithContext(e.Ctx, method, base+path, data)
	must(err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.P.HTTP.Do(req)
	if err != nil {
		fail("backend_unavailable", "Cloudflare DNS request could not complete", D{"component": "cloudflare", "backend_code": "dns_transport_failed", "recovery": "retry_infrastructure"})
	}
	defer resp.Body.Close()
	var d D
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&d); err != nil {
		fail("backend_unavailable", "Cloudflare returned an invalid response", D{"component": "cloudflare", "backend_code": "dns_response_invalid", "recovery": "retry_infrastructure"})
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || !boolean(d["success"]) {
		fail("backend_unavailable", "Cloudflare DNS operation failed", D{"component": "cloudflare", "backend_code": "dns_request_failed", "http_status": resp.StatusCode, "recovery": "retry_infrastructure"})
	}
	return d
}
func (e *Execution) Reserved() map[string]bool {
	if str(e.P.Config["cloudflare_token"]) == "" || str(e.P.Config["cloudflare_zone"]) == "" {
		fail("conflict", "DNS ownership checks are not configured; registration is paused")
	}
	data := e.CF("GET", "?per_page=5000", nil)
	if num(obj(data["result_info"])["total_pages"]) > 1 {
		fail("conflict", "Could not verify DNS namespace ownership")
	}
	labels := map[string]bool{}
	for _, l := range reservedLabels {
		labels[l] = true
	}
	for _, r := range dicts(data["result"]) {
		parts := strings.Split(strings.TrimSuffix(str(r["name"]), ".winlab.tw"), ".")
		labels[parts[len(parts)-1]] = true
	}
	return labels
}
func (e *Execution) DomainRecord(t D, remove bool) {
	name := "*." + str(t["slug"]) + ".winlab.tw"
	owner := fmt.Sprintf("carrel:b09:tenant:%d", integer(t["n"]))
	records := dicts(e.CF("GET", "?name="+url.QueryEscape(name), nil)["result"])
	if len(records) > 0 && (len(records) != 1 || records[0]["comment"] != owner) {
		fail("conflict", "Refusing DNS record owned outside carrel")
	}
	address := str(e.P.Config["public_address"])
	if remove && len(records) > 0 {
		e.CF("DELETE", "/"+str(records[0]["id"]), nil)
	} else if !remove && len(records) == 0 {
		e.CF("POST", "", D{"type": "A", "name": name, "content": address, "ttl": 120, "proxied": false, "comment": owner})
	} else if !remove && records[0]["content"] != address && e.tenantCertificateHeld(t) {
		// A record that points elsewhere moves here only once the gateway
		// confirmed the tenant's certificate.
		e.CF("PATCH", "/"+str(records[0]["id"]), D{"content": address})
	}
}

func (e *Execution) tenantCertificateHeld(t D) bool {
	crt, _, ok := e.livePair(str(t["slug"]))
	return ok && e.gatewayHolds(str(t["slug"]), crt)
}

func (e *Execution) CertificateDir() string {
	return textAt(e.P.Config, "certificate_dir", "/var/lib/carrel/certificates")
}
func (e *Execution) EnsureCertificate(t D) D {
	// One issuance at a time, apart from the infrastructure writer, so DNS
	// propagation cannot block power jobs.
	e.P.certificates.Lock()
	defer e.P.certificates.Unlock()
	if e.P.certificatePrepare != nil {
		return e.P.certificatePrepare(t)
	}
	n := integer(t["n"])
	_, has := certificateOf(e.S, n, str(t["slug"]))
	if !has {
		if issued := recentIssuance(e.S); len(issued) >= 30 {
			earliest := now()
			for _, c := range issued {
				earliest = min(earliest, float64(c.IssuedAt))
			}
			return D{"state": "queued", "ready_at": earliest + 7*86400}
		}
	}
	e.DomainRecord(t, false)
	// A current pair is kept: each issuance of the same name counts against
	// Let's Encrypt's 5 per 7 days, and domain_add calls this every time.
	if crt, _, ok := e.livePair(str(t["slug"])); has && ok && !renewalDue(crt) {
		return D{"state": "ready"}
	}
	e.issueCertificate(str(t["slug"]), "*."+str(t["slug"])+".winlab.tw")
	if !has {
		e.Put("certificates", str(n), n, D{"id": str(n), "tenant_n": n, "slug": t["slug"], "issued_at": time.Now().Unix()})
	}
	return D{"state": "ready"}
}

func (e *Execution) CertificateBundles(domains []D) []D {
	wanted := map[int]bool{}
	for _, d := range domains {
		// A special domain uses its grant's pair (grantBundles).
		if d["state"] == "ready" && str(d["grant"]) == "" {
			wanted[integer(d["tenant_n"])] = true
		}
	}
	out := []D{}
	for _, c := range rowsOf[certificateRecord](e.S, "certificates") {
		if !wanted[c.TenantN] {
			continue
		}
		crt, key, ok := e.livePair(c.Slug)
		if !ok {
			fail("backend_unavailable", "A tenant certificate is missing", D{"component": "acme", "backend_code": "certificate_missing", "recovery": "retry_infrastructure"})
		}
		out = append(out, merge(D{"slug": c.Slug}, originPair(crt, key)))
	}
	return out
}
func (e *Execution) RenewCertificate(t D) {
	if len(filter(e.S.Objects("domains", integer(t["n"])), func(d D) bool { return str(d["grant"]) == "" })) == 0 {
		return
	}
	if crt, _, ok := e.livePair(str(t["slug"])); ok && renewalDue(crt) {
		e.EnsureCertificate(t)
	}
}
func (e *Execution) DomainAction(tool string, a, t D) D {
	dry, n := boolean(a["dry_run"]), integer(t["n"])
	domains := e.domains(n)
	if tool == "domain_list" {
		r := D{"domains": e.PublicGrants("domains", n)}
		if grants := e.publicGrants(n); len(grants) > 0 {
			r["special_domains"] = grants
		}
		return r
	}
	var domain, delta D
	if tool == "domain_add" {
		vmid, _, vip := e.publishTarget(t, a)
		if (a["sub"] == nil) == (a["name"] == nil) {
			fail("invalid", "Give exactly one of sub and name", D{"recovery": "revise_request"})
		}
		// sub names a domain in the tenant's subtree; name a special domain
		// under one of its grants (PLAN 6.10).
		name, grant := str(a["sub"])+"."+str(t["slug"])+".winlab.tw", ""
		if a["name"] != nil {
			name = strings.ToLower(strings.TrimSuffix(str(a["name"]), "."))
			grant = e.grantCovering(n, name).ID
		}
		record, found := domainNamed(domains, name)
		if found && record.State == "deleting" {
			fail("conflict", "Finish removing this domain before reusing it", D{"recovery": "finish_cleanup"})
		}
		if found && (record.VMID != vmid || record.VIP != vip.ID || float64(record.TargetPort) != num(a["target_port"])) {
			fail("conflict", "Domain already targets a different service; remove it explicitly first", D{"recovery": "revise_request"})
		}
		delta = D{"domains": 0}
		if !found {
			requireHolder(vip)
			delta["domains"] = 1
			e.Quota(t, delta)
			record = domainRecord{ID: randomID()[:16], TenantN: n, VMID: vmid, VIP: vip.ID, Sub: str(a["sub"]), Grant: grant, Slug: str(t["slug"]), Name: name, TargetPort: integer(a["target_port"]), State: "queued", ReadyAt: float64(time.Now().Unix())}
		}
		if dry {
			domain = D{"name": name, "target_port": a["target_port"], "state": "planned"}
			if vip.ID != "" {
				domain["vip"] = vip.ID
			} else {
				domain["machine"] = e.Machine(t, a["machine"])["name"]
			}
		} else {
			if e.Op != nil && e.Op["tool"] == "domain_add" {
				owner := e.Op["id"]
				if found {
					owner = orNil(record.OperationID)
				}
				identity := []any{record.ID, owner}
				if e.Op["domain_target"] != nil && !equal(e.Op["domain_target"], identity) {
					fail("conflict", "Domain was replaced; retry refused", D{"recovery": "revise_request"})
				}
				e.Op["domain_target"] = identity
				e.P.Operations.Save(e.Op)
			}
			e.Put("domains", record.ID, n, record)
			if e.Op != nil && !e.publicationPrepared {
				return D{"domain": e.PublicGrant("domains", record.D(), n), "quota_after": e.Quota(t)}
			}
			if record.State != "ready" && record.State != "configuring" {
				if record.ReadyAt > now() {
					panic(Waiting{"waiting_for_certificate", record.ReadyAt})
				}
				fail("conflict", "Certificate preparation must complete before publishing")
			}
			if record.Grant == "" {
				e.DomainRecord(t, false)
			}
			e.Reconcile()
			record.State = "ready"
			e.Put("domains", record.ID, n, record)
			if record.Grant != "" {
				// The gateway was given the routes, so the record may move.
				g, _ := rowOf[domainGrant](e.S, "domain_grants", record.Grant)
				e.GrantRecord(g, false)
			}
			domain = record.D()
		}
	} else {
		record, found := domainNamed(domains, str(a["name"]))
		if !found {
			fail("not_found", "Domain not found in this tenant")
		}
		delta = D{"domains": -1}
		if !dry {
			record.State = "deleting"
			e.Put("domains", record.ID, n, record)
			e.Reconcile()
			// The tenant's wildcard record goes with its last own domain;
			// a grant keeps its record until it is released.
			last := record.Grant == ""
			for _, d := range domains {
				if d.ID != record.ID && d.State != "deleting" && d.Grant == "" {
					last = false
				}
			}
			if last {
				e.DomainRecord(t, true)
			}
			e.S.Remove("domains", record.ID)
			record.State = "deleted"
		}
		domain = record.D()
	}
	q := e.Quota(t)
	if dry {
		q = e.Quota(t, delta)
	}
	return D{"domain": e.PublicGrant("domains", domain, n), "dry_run": dry, "quota_after": q}
}
