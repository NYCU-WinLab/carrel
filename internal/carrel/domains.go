package carrel

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
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
	address, own := publicAddress(e.P.Config)
	if remove && len(records) > 0 {
		e.CF("DELETE", "/"+str(records[0]["id"]), nil)
	} else if !remove && len(records) == 0 {
		e.CF("POST", "", D{"type": "A", "name": name, "content": address, "ttl": 120, "proxied": false, "comment": owner})
	} else if !remove && own && records[0]["content"] != address {
		// A site with its own address takes over the records carrel owns. A
		// control plane without public_address never rewrites them back.
		e.CF("PATCH", "/"+str(records[0]["id"]), D{"content": address})
	}
}

// publicAddress is where carrel's records point: the site's own public
// address, or the external edge on sites that predate one.
func publicAddress(c D) (string, bool) {
	if a := str(c["public_address"]); a != "" {
		return a, true
	}
	return "140.113.194.229", false
}
func (e *Execution) CertificateDir() string {
	return textAt(e.P.Config, "certificate_dir", "/var/lib/carrel/certificates")
}
func (e *Execution) EnsureCertificate(t D) D {
	// Certbot uses shared work/config directories. Serialize issuers separately
	// from the infrastructure writer so DNS propagation cannot block power jobs.
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
	crt, key := e.issueCertificate(str(t["slug"]), "*."+str(t["slug"])+".winlab.tw")
	if cert == nil {
		cert = D{"id": str(n), "tenant_n": n, "slug": t["slug"], "issued_at": time.Now().Unix()}
	}
	cert["fullchain_path"], cert["private_key_path"] = crt, key
	e.Put("certificates", str(n), n, cert)
	return D{"state": "ready"}
}

// issueCertificate runs certbot's DNS-01 issuance for one name and returns the
// immutable archive pair it produced.
func (e *Execution) issueCertificate(name, domain string) (string, string) {
	base := e.CertificateDir()
	must(os.MkdirAll(base, 0700))
	credentials := filepath.Join(base, "cloudflare.ini")
	must(os.WriteFile(credentials, []byte("dns_cloudflare_api_token = "+str(e.P.Config["cloudflare_token"])+"\n"), 0600))
	must(os.Chmod(credentials, 0600))
	ctx, cancel := context.WithTimeout(e.Ctx, 300*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, textAt(e.P.Config, "certbot", "/opt/carrel/venv/bin/certbot"), "certonly", "--non-interactive", "--agree-tos", "--email", textAt(e.P.Config, "acme_email", "yongxiang.zhan@outlook.com"), "--dns-cloudflare", "--dns-cloudflare-credentials", credentials, "--dns-cloudflare-propagation-seconds", "30", "--cert-name", name, "--config-dir", filepath.Join(base, "config"), "--work-dir", filepath.Join(base, "work"), "--logs-dir", filepath.Join(base, "logs"), "--keep-until-expiring", "-d", domain)
	if err := cmd.Run(); err != nil {
		fail("backend_unavailable", "Certificate issuance failed; inspect control-plane ACME logs", D{"component": "certbot", "backend_code": "certificate_issuance_failed", "recovery": "retry_infrastructure"})
	}
	// Pin the matching immutable certbot archive pair. Reconciliation can keep
	// using the old generation while renewal rotates the live symlinks.
	path := filepath.Join(base, "config", "live", name)
	crt, err := filepath.EvalSymlinks(filepath.Join(path, "fullchain.pem"))
	must(err)
	key, err := filepath.EvalSymlinks(filepath.Join(path, "privkey.pem"))
	must(err)
	if _, err := tls.LoadX509KeyPair(crt, key); err != nil {
		fail("backend_unavailable", "Certificate files do not form a valid pair", D{"component": "certbot", "backend_code": "certificate_pair_invalid", "recovery": "retry_infrastructure"})
	}
	return crt, key
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
		path := filepath.Join(e.CertificateDir(), "config", "live", str(c["slug"]))
		crt, err := os.ReadFile(textAt(c, "fullchain_path", filepath.Join(path, "fullchain.pem")))
		must(err)
		key, err := os.ReadFile(textAt(c, "private_key_path", filepath.Join(path, "privkey.pem")))
		must(err)
		out = append(out, D{"slug": c["slug"], "fullchain": string(crt), "privkey": string(key)})
	}
	return out
}
func (e *Execution) RenewCertificate(t D) {
	if len(e.S.Objects("domains", integer(t["n"]))) == 0 {
		return
	}
	b, err := os.ReadFile(filepath.Join(e.CertificateDir(), "config", "live", str(t["slug"]), "fullchain.pem"))
	if os.IsNotExist(err) {
		return
	}
	must(err)
	block, _ := pem.Decode(b)
	if block == nil {
		fail("conflict", "Invalid stored certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	must(err)
	if time.Until(cert.NotAfter) < 30*24*time.Hour {
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
