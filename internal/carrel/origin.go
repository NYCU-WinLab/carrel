package carrel

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"time"
)

// carrel's own name on a site with its own public address (PLAN 15.15): the
// control plane issues the certificate through DNS-01, the gateway receives it
// on the next reconcile, and only then does the record move to the site.
//
// The certbot lineage "_origin" is the state: it belongs to no tenant, so it
// has no database object, and no tenant slug can take its name. Which pairs
// the gateway holds is kept in memory; after a restart the first reconcile
// delivers them again before any record can move.

const originOwner = "carrel:origin"

// The record publish-entry.py created for the external edge.
const edgeOriginOwner = "Owned by carrel B09 external edge"

const originLineage = "_origin"

// originFiles returns the pinned archive pair of the origin lineage. While
// certbot swaps the live links the two may not match; the last pair that did
// is used instead, since archive files never change.
func (e *Execution) originFiles() (string, string, bool) {
	live := filepath.Join(e.CertificateDir(), "config", "live", originLineage)
	crt, err1 := filepath.EvalSymlinks(filepath.Join(live, "fullchain.pem"))
	key, err2 := filepath.EvalSymlinks(filepath.Join(live, "privkey.pem"))
	if err1 == nil && err2 == nil {
		if _, err := tls.LoadX509KeyPair(crt, key); err == nil {
			e.P.originPair.Store([2]string{crt, key})
			return crt, key, true
		}
	}
	if last, ok := e.P.originPair.Load().([2]string); ok {
		return last[0], last[1], true
	}
	return "", "", false
}

// gatewayHolds reports whether the gateway confirmed the certificate in path
// under name on its last reconcile.
func (e *Execution) gatewayHolds(name, path string) bool {
	held, _ := e.P.delivered.Load().(map[string]any)
	b, err := os.ReadFile(path)
	return err == nil && held != nil && held[name] == fingerprint(string(b))
}

// EnsureOriginCertificate issues or renews carrel's own certificate. A first
// issuance waits while tenants have used the 7-day budget.
func (e *Execution) EnsureOriginCertificate() D {
	e.P.certificates.Lock()
	defer e.P.certificates.Unlock()
	host := originHost(e.P.Config)
	if host == "" {
		fail("conflict", "The control-plane origin is not configured")
	}
	if _, _, ok := e.originFiles(); !ok {
		issued := filter(e.S.Objects("certificates"), func(c D) bool { return num(c["issued_at"]) > now()-7*86400 })
		if len(issued) >= 30 {
			return D{"state": "queued"}
		}
	}
	e.issueCertificate(originLineage, host)
	return D{"state": "ready"}
}

// MaintainOrigin keeps the origin certificate fresh and moves carrel's record
// to the site's address once the gateway holds a valid certificate for it.
func (e *Execution) MaintainOrigin() {
	if str(e.P.Config["ingress"]) != "exit" {
		return
	}
	crt, _, ok := e.originFiles()
	if !ok || expiresWithin(crt, 30*24*time.Hour) {
		e.EnsureOriginCertificate()
		return
	}
	if !e.gatewayHolds("_origin", crt) {
		return
	}
	host := originHost(e.P.Config)
	address, _ := publicAddress(e.P.Config)
	records := dicts(e.CF("GET", "?name="+host, nil)["result"])
	switch {
	case len(records) == 0:
		e.CF("POST", "", D{"type": "A", "name": host, "content": address, "ttl": 120, "proxied": false, "comment": originOwner})
	case len(records) == 1 && (records[0]["comment"] == originOwner || records[0]["comment"] == edgeOriginOwner):
		if records[0]["content"] != address || records[0]["comment"] != originOwner {
			e.CF("PATCH", "/"+str(records[0]["id"]), D{"content": address, "comment": originOwner})
		}
	default:
		fail("conflict", "Refusing DNS record owned outside carrel")
	}
}

func expiresWithin(path string, d time.Duration) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return true
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return true
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	return err != nil || time.Until(cert.NotAfter) < d
}

// originPair reads the pinned origin pair for the gateway.
func originPair(crt, key string) D {
	c, err := os.ReadFile(crt)
	must(err)
	k, err := os.ReadFile(key)
	must(err)
	return D{"fullchain": string(c), "privkey": string(k)}
}

// fingerprint matches node-agent's confirmation of the pair the gateway holds.
func fingerprint(fullchain any) string {
	sum := sha256.Sum256([]byte(str(fullchain)))
	return hex.EncodeToString(sum[:])
}
