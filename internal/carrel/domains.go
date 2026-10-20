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

func (e *Execution) CF(method, path string, body any) D {
	base := textAt(e.P.Config, "cloudflare_api", "https://api.cloudflare.com/client/v4")
	var data io.Reader
	if body != nil {
		data = bytes.NewReader(encoded(body))
	}
	req, err := http.NewRequestWithContext(e.Ctx, method, base+"/zones/"+str(e.P.Config["cloudflare_zone"])+"/dns_records"+path, data)
	must(err)
	req.Header.Set("Authorization", "Bearer "+str(e.P.Config["cloudflare_token"]))
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
	cert := find(e.S.Objects("certificates", n), func(c D) bool { return c["slug"] == t["slug"] })
	if cert == nil {
		issued := filter(e.S.Objects("certificates"), func(c D) bool { return num(c["issued_at"]) > now()-7*86400 })
		if len(issued) >= 30 {
			earliest := now()
			for _, c := range issued {
				earliest = min(earliest, num(c["issued_at"]))
			}
			return D{"state": "queued", "ready_at": earliest + 7*86400}
		}
	}
	e.DomainRecord(t, false)
	// A current pair is kept: each issuance of the same name counts against
	// Let's Encrypt's 5 per 7 days, and domain_add calls this every time.
	if crt, _, ok := e.livePair(str(t["slug"])); cert != nil && ok && !renewalDue(crt) {
		return D{"state": "ready"}
	}
	e.issueCertificate(str(t["slug"]), "*."+str(t["slug"])+".winlab.tw")
	if cert == nil {
		e.Put("certificates", str(n), n, D{"id": str(n), "tenant_n": n, "slug": t["slug"], "issued_at": time.Now().Unix()})
	}
	return D{"state": "ready"}
}

func (e *Execution) CertificateBundles(domains []D) []D {
	wanted := map[int]bool{}
	for _, d := range domains {
		if d["state"] == "ready" {
			wanted[integer(d["tenant_n"])] = true
		}
	}
	out := []D{}
	for _, c := range e.S.Objects("certificates") {
		if !wanted[integer(c["tenant_n"])] {
			continue
		}
		crt, key, ok := e.livePair(str(c["slug"]))
		if !ok {
			fail("backend_unavailable", "A tenant certificate is missing", D{"component": "acme", "backend_code": "certificate_missing", "recovery": "retry_infrastructure"})
		}
		out = append(out, merge(D{"slug": c["slug"]}, originPair(crt, key)))
	}
	return out
}
func (e *Execution) RenewCertificate(t D) {
	if len(e.S.Objects("domains", integer(t["n"]))) == 0 {
		return
	}
	if crt, _, ok := e.livePair(str(t["slug"])); ok && renewalDue(crt) {
		e.EnsureCertificate(t)
	}
}
func (e *Execution) DomainAction(tool string, a, t D) D {
	dry, n := boolean(a["dry_run"]), integer(t["n"])
	domains := e.S.Objects("domains", n)
	if tool == "domain_list" {
		return D{"domains": e.PublicGrants("domains", n)}
	}
	var domain, delta D
	if tool == "domain_add" {
		m := e.Machine(t, a["machine"])
		name := str(a["sub"]) + "." + str(t["slug"]) + ".winlab.tw"
		old := find(domains, func(d D) bool { return d["name"] == name })
		if old != nil && old["state"] == "deleting" {
			fail("conflict", "Finish removing this domain before reusing it", D{"recovery": "finish_cleanup"})
		}
		if old != nil && (integer(old["vmid"]) != integer(m["vmid"]) || num(old["target_port"]) != num(a["target_port"])) {
			fail("conflict", "Domain already targets a different service; remove it explicitly first", D{"recovery": "revise_request"})
		}
		delta = D{"domains": 0}
		if old == nil {
			delta["domains"] = 1
			e.Quota(t, delta)
		}
		domain = old
		if domain == nil {
			domain = D{"id": randomID()[:16], "tenant_n": n, "vmid": m["vmid"], "sub": a["sub"], "slug": t["slug"], "name": name, "target_port": a["target_port"], "state": "queued", "ready_at": time.Now().Unix()}
		}
		if dry {
			domain = D{"name": name, "machine": m["name"], "target_port": a["target_port"], "state": "planned"}
		} else {
			if e.Op != nil && e.Op["tool"] == "domain_add" {
				owner := e.Op["id"]
				if old != nil {
					owner = old["operation_id"]
				}
				identity := []any{domain["id"], owner}
				if e.Op["domain_target"] != nil && !equal(e.Op["domain_target"], identity) {
					fail("conflict", "Domain was replaced; retry refused", D{"recovery": "revise_request"})
				}
				e.Op["domain_target"] = identity
				e.P.Operations.Save(e.Op)
			}
			e.Put("domains", domain["id"], n, domain)
			if e.Op != nil && !e.publicationPrepared {
				return D{"domain": e.PublicGrant("domains", domain, n), "quota_after": e.Quota(t)}
			}
			if domain["state"] != "ready" && domain["state"] != "configuring" {
				if num(domain["ready_at"]) > now() {
					panic(Waiting{"waiting_for_certificate", num(domain["ready_at"])})
				}
				fail("conflict", "Certificate preparation must complete before publishing")
			}
			e.DomainRecord(t, false)
			e.Reconcile()
			domain["state"] = "ready"
			e.Put("domains", domain["id"], n, domain)
		}
	} else {
		domain = find(domains, func(d D) bool { return d["name"] == a["name"] })
		if domain == nil {
			fail("not_found", "Domain not found in this tenant")
		}
		delta = D{"domains": -1}
		if !dry {
			domain["state"] = "deleting"
			e.Put("domains", domain["id"], n, domain)
			e.Reconcile()
			if find(domains, func(d D) bool { return d["id"] != domain["id"] && d["state"] != "deleting" }) == nil {
				e.DomainRecord(t, true)
			}
			e.S.Remove("domains", domain["id"])
			domain["state"] = "deleted"
		}
	}
	q := e.Quota(t)
	if dry {
		q = e.Quota(t, delta)
	}
	return D{"domain": e.PublicGrant("domains", domain, n), "dry_run": dry, "quota_after": q}
}
