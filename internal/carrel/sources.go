package carrel

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Sources (PLAN 10.6): Proxmox hosts outside carrel that machine_import can
// bring guests from. An admin registers one with source_add and an API token
// on that host. The token secret is a server secret, kept in a 0600 file
// under source_dir and never in the database, the audit log, a log line or a
// result. The host's TLS certificate is pinned by its SHA-256 fingerprint,
// because a Proxmox host usually has a self-signed one.

var (
	sourceNamePattern  = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	sourceTokenID      = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}@[A-Za-z0-9._-]{1,64}![A-Za-z0-9._-]{1,64}$`)
	sourceSecret       = regexp.MustCompile(`^[A-Za-z0-9-]{16,100}$`)
	sourceFingerprint  = regexp.MustCompile(`^([0-9A-Fa-f]{2}:){31}[0-9A-Fa-f]{2}$`)
	errSourceCertMatch = errors.New("source certificate does not match the fingerprint")
)

// sourceRecord is a registered source, kept in the site table. It holds no
// secret.
type sourceRecord struct {
	AddedAt      int64    `json:"added_at"`
	AddedBy      string   `json:"added_by"`
	APIURL       string   `json:"api_url"`
	Fingerprint  string   `json:"fingerprint"`
	Name         string   `json:"name"`
	StorageTypes []string `json:"storage_types"`
	TokenID      string   `json:"token_id"`
	Version      string   `json:"version"`
}

func (e *Execution) sourceDir() string { return e.P.Config.SourceDir }

func (e *Execution) sourceSecretPath(name string) string {
	return filepath.Join(e.sourceDir(), name+".secret")
}

// publicSource is a source as a result shows it: never the secret.
func publicSource(s sourceRecord) D {
	return D{"name": s.Name, "api_url": s.APIURL, "token_id": s.TokenID, "fingerprint": s.Fingerprint, "version": s.Version, "storage_types": s.StorageTypes, "added_at": s.AddedAt}
}

// sourceURL checks the API address: https, a host, an optional port, nothing
// else, so the token only ever goes to the host the admin named.
func sourceURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		fail("invalid", "Give api_url as https://host or https://host:8006", D{"recovery": "revise_request"})
	}
	if p := u.Port(); p != "" && !matches(`^[0-9]{1,5}$`, p) {
		fail("invalid", "Give api_url as https://host or https://host:8006", D{"recovery": "revise_request"})
	}
	host := strings.ToLower(u.Hostname())
	if ip := net.ParseIP(host); ip != nil && strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if u.Port() != "" {
		host += ":" + u.Port()
	}
	return "https://" + host
}

// sourceSecretOf reads the secret from the argument, or from its file so that
// it never passes through a client.
func (e *Execution) sourceSecretOf(a D, name string) (secret string, fromFile bool) {
	secret = strings.TrimSpace(str(a["secret"]))
	if secret == "" {
		b, err := readSmall(e.sourceSecretPath(name), 4096)
		if err != nil {
			fail("invalid", "Give secret, or first place it on the control plane as "+name+".secret in the source directory (source_dir, /var/lib/carrel/sources by default)", D{"recovery": "resolve_prerequisite"})
		}
		secret, fromFile = strings.TrimSpace(string(b)), true
	}
	if !sourceSecret.MatchString(secret) {
		fail("invalid", "The secret is not a Proxmox API token secret", D{"recovery": "revise_request"})
	}
	return secret, fromFile
}

// sourceClient talks to one source: no redirects, a short timeout, and the
// certificate must match the pinned fingerprint.
func sourceClient(fingerprint string) *http.Client {
	want := strings.ToLower(strings.ReplaceAll(fingerprint, ":", ""))
	return &http.Client{
		Timeout:       15 * time.Second,
		CheckRedirect: noRedirect,
		Transport: &http.Transport{
			Proxy: nil,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				// The chain is not checked: the pin below is the trust.
				InsecureSkipVerify: true,
				VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
					if len(raw) == 0 {
						return errSourceCertMatch
					}
					sum := sha256.Sum256(raw[0])
					if fmt.Sprintf("%x", sum[:]) != want {
						return errSourceCertMatch
					}
					return nil
				},
			},
			DisableKeepAlives: true,
		},
	}
}

// sourceGet reads one read-only API path of the source.
func sourceGet(ctx context.Context, client *http.Client, base, tokenID, secret, path string) D {
	req, err := http.NewRequestWithContext(ctx, "GET", base+"/api2/json"+path, nil)
	must(err)
	req.Header.Set("Authorization", "PVEAPIToken="+tokenID+"="+secret)
	resp, err := client.Do(req)
	if err != nil {
		if errors.Is(err, errSourceCertMatch) {
			fail("invalid", "The source's certificate does not match the fingerprint", D{"recovery": "revise_request"})
		}
		fail("backend_unavailable", "The source could not be reached", D{"component": "source", "backend_code": "source_transport_failed", "recovery": "retry_infrastructure"})
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		fail("invalid", "The source refused the token", D{"recovery": "revise_request"})
	}
	var d D
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&d) != nil || d["data"] == nil {
		fail("backend_unavailable", "The source did not answer as a Proxmox host", D{"component": "source", "backend_code": "source_response_invalid", "recovery": "retry_infrastructure"})
	}
	return d
}

// sourceProbe checks the token read-only: the version, then the storage list.
func (e *Execution) sourceProbe(s *sourceRecord, secret string) {
	client := sourceClient(s.Fingerprint)
	defer client.CloseIdleConnections()
	version := str(obj(sourceGet(e.Ctx, client, s.APIURL, s.TokenID, secret, "/version")["data"])["version"])
	if version == "" {
		fail("backend_unavailable", "The source did not answer as a Proxmox host", D{"component": "source", "backend_code": "source_response_invalid", "recovery": "retry_infrastructure"})
	}
	types := []string{}
	for _, st := range dicts(sourceGet(e.Ctx, client, s.APIURL, s.TokenID, secret, "/storage")["data"]) {
		if t := str(st["type"]); t != "" && matches(`^[a-z0-9]{1,32}$`, t) && !slices.Contains(types, t) {
			types = append(types, t)
		}
	}
	slices.Sort(types)
	s.Version, s.StorageTypes = version, types
}

// SourceAction runs source_add.
func (e *Execution) SourceAction(a, w D) D {
	dry := boolean(a["dry_run"])
	name := str(a["name"])
	if !sourceNamePattern.MatchString(name) {
		fail("invalid", "Give the source name as a lowercase label", D{"recovery": "revise_request"})
	}
	apiURL := sourceURL(str(a["api_url"]))
	tokenID := str(a["token_id"])
	if !sourceTokenID.MatchString(tokenID) {
		fail("invalid", "Give token_id as user@realm!tokenname", D{"recovery": "revise_request"})
	}
	fingerprint := strings.ToUpper(str(a["fingerprint"]))
	if !sourceFingerprint.MatchString(fingerprint) {
		fail("invalid", "Give fingerprint as the SHA-256 fingerprint of the source's certificate, 32 hex pairs separated by colons", D{"recovery": "revise_request"})
	}
	secret, fromFile := e.sourceSecretOf(a, name)
	old := e.S.SiteGet("source", name)
	s := sourceRecord{Name: name, APIURL: apiURL, TokenID: tokenID, Fingerprint: fingerprint, AddedBy: str(w["sub"]), AddedAt: time.Now().Unix()}
	e.sourceProbe(&s, secret)
	if old != nil {
		s.AddedAt, s.AddedBy = int64(num(old["added_at"])), str(old["added_by"])
	}
	if !dry {
		must(os.MkdirAll(e.sourceDir(), 0700))
		path := e.sourceSecretPath(name)
		if !fromFile {
			must(os.WriteFile(path+".next", bytes.TrimSpace([]byte(secret+"\n")), 0600))
			must(os.Rename(path+".next", path))
		}
		must(os.Chmod(path, 0600))
		e.S.SitePut("source", name, decode(string(encoded(s))))
	}
	return D{"source": publicSource(s), "dry_run": dry}
}
