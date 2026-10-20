package carrel

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
)

// Certificates come from Let's Encrypt through DNS-01, inside the control
// plane: it writes the challenge TXT record in Cloudflare, waits until the
// resolver serves it, and keeps every issued pair in its own directory
// archive/<name>/<generation>. live/<name> is a relative symlink to the
// current one; a rename replaces it, so a reader that resolves it once always
// gets a matching pair, and a restored backup keeps working at another path.

const acmeOwner = "carrel:acme"

// issueCertificate obtains a certificate for domain and makes it the live
// pair of name.
func (e *Execution) issueCertificate(name, domain string) {
	ctx, cancel := context.WithTimeout(e.Ctx, 300*time.Second)
	defer cancel()
	issue := e.P.issue
	if issue == nil {
		issue = e.obtainCertificate
	}
	fullchain, key, err := issue(ctx, domain)
	if err != nil {
		slog.Error("certificate_issuance_failed", "name", name, "error", err.Error())
		fail("backend_unavailable", "Certificate issuance failed; inspect the control-plane log", D{"component": "acme", "backend_code": "certificate_issuance_failed", "recovery": "retry_infrastructure"})
	}
	e.storeCertificate(name, fullchain, key)
}

// obtainCertificate runs one ACME order for domain with a fresh P-256 key.
func (e *Execution) obtainCertificate(ctx context.Context, domain string) ([]byte, []byte, error) {
	client, err := e.acmeClient(ctx)
	if err != nil {
		return nil, nil, err
	}
	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(domain))
	if err != nil {
		return nil, nil, fmt.Errorf("order: %w", err)
	}
	for _, u := range order.AuthzURLs {
		if err := e.authorize(ctx, client, u); err != nil {
			return nil, nil, err
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{domain}}, key)
	if err != nil {
		return nil, nil, err
	}
	if order, err = client.WaitOrder(ctx, order.URI); err != nil {
		return nil, nil, fmt.Errorf("order not ready: %w", err)
	}
	chain, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return nil, nil, fmt.Errorf("finalize: %w", err)
	}
	var fullchain []byte
	for _, der := range chain {
		fullchain = append(fullchain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return fullchain, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// authorize answers one DNS-01 challenge. The TXT record lives only for the
// validation; one a failed run left behind is removed first.
func (e *Execution) authorize(ctx context.Context, client *acme.Client, u string) error {
	z, err := client.GetAuthorization(ctx, u)
	if err != nil {
		return fmt.Errorf("authorization: %w", err)
	}
	if z.Status == acme.StatusValid {
		return nil
	}
	i := slices.IndexFunc(z.Challenges, func(c *acme.Challenge) bool { return c.Type == "dns-01" })
	if i < 0 {
		return errors.New("no dns-01 challenge offered")
	}
	value, err := client.DNS01ChallengeRecord(z.Challenges[i].Token)
	if err != nil {
		return err
	}
	// A wildcard authorization names the base domain.
	record := "_acme-challenge." + strings.TrimPrefix(z.Identifier.Value, "*.")
	e.removeChallenges(record)
	created := e.CF("POST", "", D{"type": "TXT", "name": record, "content": value, "ttl": 60, "proxied": false, "comment": acmeOwner})
	defer func() {
		// A record left behind is removed by the next issuance.
		_ = attempt(func() { e.CF("DELETE", "/"+str(obj(created["result"])["id"]), nil) })
	}()
	if err := e.waitTXT(ctx, record, value); err != nil {
		return err
	}
	if _, err := client.Accept(ctx, z.Challenges[i]); err != nil {
		return fmt.Errorf("accept: %w", err)
	}
	if _, err := client.WaitAuthorization(ctx, z.URI); err != nil {
		return fmt.Errorf("validation: %w", err)
	}
	return nil
}

func (e *Execution) removeChallenges(record string) {
	for _, r := range dicts(e.CF("GET", "?type=TXT&name="+url.QueryEscape(record), nil)["result"]) {
		if r["comment"] == acmeOwner {
			e.CF("DELETE", "/"+str(r["id"]), nil)
		}
	}
}

// waitTXT polls the resolver until it serves the challenge value. It asks
// only after the record exists, so no negative answer is cached first.
func (e *Execution) waitTXT(ctx context.Context, record, value string) error {
	lookup := e.P.lookupTXT
	if lookup == nil {
		lookup = net.DefaultResolver.LookupTXT
	}
	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	for {
		// The trailing dot skips the resolv.conf search list.
		if values, err := lookup(ctx, record+"."); err == nil && slices.Contains(values, value) {
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.New("challenge record not visible through DNS")
		case <-time.After(2 * time.Second):
		}
	}
}

// acmeClient loads the account key, creating and registering it on first use.
func (e *Execution) acmeClient(ctx context.Context) (*acme.Client, error) {
	path := filepath.Join(e.CertificateDir(), "acme", "account.key")
	var key *ecdsa.PrivateKey
	if b, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(b)
		if block == nil {
			return nil, errors.New("invalid ACME account key")
		}
		if key, err = x509.ParseECPrivateKey(block.Bytes); err != nil {
			return nil, err
		}
	} else if os.IsNotExist(err) {
		if key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
			return nil, err
		}
		der, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0600); err != nil {
			return nil, err
		}
	} else {
		return nil, err
	}
	client := &acme.Client{Key: key, DirectoryURL: textAt(e.P.Config, "acme_directory", acme.LetsEncryptURL), HTTPClient: e.P.HTTP}
	account := &acme.Account{}
	if email := str(e.P.Config["acme_email"]); email != "" {
		account.Contact = []string{"mailto:" + email}
	}
	// Registering an existing key is a lookup; it costs one request per issuance.
	if _, err := client.Register(ctx, account, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return nil, fmt.Errorf("account: %w", err)
	}
	return client, nil
}

// storeCertificate writes a new generation of name and points live/<name> at
// it. The two generations before it stay for the gateway's current copy.
func (e *Execution) storeCertificate(name string, fullchain, key []byte) {
	if _, err := tls.X509KeyPair(fullchain, key); err != nil {
		fail("backend_unavailable", "Certificate files do not form a valid pair", D{"component": "acme", "backend_code": "certificate_pair_invalid", "recovery": "retry_infrastructure"})
	}
	base := e.CertificateDir()
	generation := strconv.FormatInt(time.Now().UnixNano(), 10)
	dir := filepath.Join(base, "archive", name, generation)
	must(os.MkdirAll(dir, 0700))
	must(os.WriteFile(filepath.Join(dir, "fullchain.pem"), fullchain, 0600))
	must(os.WriteFile(filepath.Join(dir, "privkey.pem"), key, 0600))
	link := filepath.Join(base, "live", name)
	must(os.MkdirAll(filepath.Dir(link), 0700))
	next := link + ".next"
	_ = os.Remove(next)
	must(os.Symlink(filepath.Join("..", "archive", name, generation), next))
	must(os.Rename(next, link))
	entries, err := os.ReadDir(filepath.Join(base, "archive", name))
	must(err)
	// Generation names are fixed-width nanosecond times, so they sort by age.
	for len(entries) > 3 {
		must(os.RemoveAll(filepath.Join(base, "archive", name, entries[0].Name())))
		entries = entries[1:]
	}
}

// livePair resolves the current pair of name.
func (e *Execution) livePair(name string) (string, string, bool) {
	dir, err := filepath.EvalSymlinks(filepath.Join(e.CertificateDir(), "live", name))
	if err != nil {
		return "", "", false
	}
	return filepath.Join(dir, "fullchain.pem"), filepath.Join(dir, "privkey.pem"), true
}

// renewalDue is true once a third of the certificate's lifetime is left, the
// point Let's Encrypt recommends for any validity period.
func renewalDue(path string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return true
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return true
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return true
	}
	return time.Until(cert.NotAfter) < cert.NotAfter.Sub(cert.NotBefore)/3
}
