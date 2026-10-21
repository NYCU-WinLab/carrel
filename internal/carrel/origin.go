package carrel

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"time"
)

// carrel's own name on a site with its own public address (PLAN 15.15): the
// control plane issues the certificate through DNS-01, the gateway receives it
// on the next reconcile, and only then does the record move to the site.
//
// The live pair "_origin" is the state: it belongs to no tenant, so it has no
// database object, and no tenant slug can take its name. Which pairs the
// gateway holds is kept in memory; after a restart the first reconcile
// delivers them again before any record can move.

const originOwner = "carrel:origin"

const originLineage = "_origin"

// originFiles returns the current origin pair.
func (e *Execution) originFiles() (string, string, bool) {
	return e.livePair(originLineage)
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
	crt, _, ok := e.originFiles()
	if ok && !renewalDue(crt) {
		return D{"state": "ready"}
	}
	if !ok {
		if len(recentIssuance(e.S)) >= 30 {
			return D{"state": "queued"}
		}
	}
	e.issueCertificate(originLineage, host)
	return D{"state": "ready"}
}

// MaintainOrigin keeps the origin certificate fresh and moves carrel's record
// to the site's address once the gateway holds a valid certificate for it.
func (e *Execution) MaintainOrigin() {
	crt, _, ok := e.originFiles()
	if !ok || renewalDue(crt) {
		// A failed issuance waits longer each time (issue #51): Let's
		// Encrypt allows few failed validations per hostname and hour.
		if f := e.P.originRetry.try(time.Now(), func() { e.EnsureOriginCertificate() }); f != nil {
			panic(f)
		}
		return
	}
	if !e.gatewayHolds("_origin", crt) {
		return
	}
	host := originHost(e.P.Config)
	address := str(e.P.Config["public_address"])
	records := dicts(e.CF("GET", "?name="+host, nil)["result"])
	switch {
	case len(records) == 0:
		e.CF("POST", "", D{"type": "A", "name": host, "content": address, "ttl": 120, "proxied": false, "comment": originOwner})
	case len(records) == 1 && records[0]["comment"] == originOwner:
		if records[0]["content"] != address {
			e.CF("PATCH", "/"+str(records[0]["id"]), D{"content": address})
		}
	default:
		fail("conflict", "Refusing DNS record owned outside carrel")
	}
}

// originPair reads a pair for the gateway.
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

// backoff spaces out retries of one failing action: 10 minutes after the
// first failure, doubling to at most 6 hours; a success resets it.
type backoff struct {
	next time.Time
	wait time.Duration
}

// try runs fn unless it is too soon, and returns what fn raised.
func (b *backoff) try(now time.Time, fn func()) any {
	if now.Before(b.next) {
		return nil
	}
	if f := attempt(fn); f != nil {
		b.wait = min(max(2*b.wait, 10*time.Minute), 6*time.Hour)
		b.next = now.Add(b.wait)
		return f
	}
	b.wait, b.next = 0, time.Time{}
	return nil
}
