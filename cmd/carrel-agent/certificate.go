package main

// Certificate sign-in (#601). The agent holds a client certificate from the
// lab step-ca for one name, <node>.<site>.agent.carrel.winlab.tw, issued by
// the carrel-agents provisioner. An operator enrols it once with a one-time
// token (carrel-agent -enroll); after that the agent renews it itself over
// mTLS, with no secret on the node but its own key. It presents the
// certificate on every connection to the control plane, beside its token
// while it still has one, so the control plane alone decides which it takes.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// renewCheck is how often the agent looks at its certificate. It renews once
// a third of the certificate's life has passed, so a 7 day certificate
// outlives a CA outage of over 4 days.
const renewCheck = time.Hour

// loadCertificate reads cert_file and key_file. No certificate yet is not an
// error: the agent signs in with its token until it is enrolled. A pair that
// does not load (an enrolment cut short) is reported and left unused, so the
// agent still starts with its token and can be enrolled again.
func (a *agent) loadCertificate() error {
	if a.cfg.CertFile == "" {
		return nil
	}
	pair, err := tls.LoadX509KeyPair(a.cfg.CertFile, a.cfg.KeyFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if pair.Leaf == nil {
		if pair.Leaf, err = x509.ParseCertificate(pair.Certificate[0]); err != nil {
			return err
		}
	}
	a.cert.Store(&pair)
	return nil
}

// clientCertificate presents the current certificate, or none once it has
// expired.
func (a *agent) clientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	if c := a.cert.Load(); c != nil && time.Now().Before(c.Leaf.NotAfter) {
		return c, nil
	}
	return &tls.Certificate{}, nil
}

// renewDue reports whether a third of the certificate's life has passed.
func renewDue(leaf *x509.Certificate, now time.Time) bool {
	life := leaf.NotAfter.Sub(leaf.NotBefore)
	return now.After(leaf.NotBefore.Add(life / 3))
}

// renewLoop renews the certificate when it is due, and picks up one an
// operator enrolled while the agent runs.
func (a *agent) renewLoop(ctx context.Context) {
	for ctx.Err() == nil {
		if err := a.loadCertificate(); err != nil {
			slog.Error("certificate_unreadable", "error", err)
		}
		if c := a.cert.Load(); c != nil {
			now := time.Now()
			switch {
			case now.After(c.Leaf.NotAfter):
				// The CA renews no expired certificate: an operator enrols again.
				slog.Error("certificate_expired", "expired", c.Leaf.NotAfter.UTC().Format(time.RFC3339))
			case renewDue(c.Leaf, now):
				if err := a.renew(ctx); err != nil {
					slog.Warn("certificate_renew_failed", "error", err, "expires", c.Leaf.NotAfter.UTC().Format(time.RFC3339))
				} else {
					slog.Info("certificate_renewed", "expires", a.cert.Load().Leaf.NotAfter.UTC().Format(time.RFC3339))
				}
			}
		}
		sleep(ctx, renewCheck)
	}
}

// caClient talks to the lab step-ca, trusting only the lab root.
func (a *agent) caClient(withCertificate bool) (*http.Client, error) {
	roots, err := os.ReadFile(a.cfg.LabRootFile)
	if err != nil {
		return nil, fmt.Errorf("lab_root_file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(roots) {
		return nil, errors.New("lab_root_file holds no certificate")
	}
	t := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	if withCertificate {
		t.GetClientCertificate = a.clientCertificate
	}
	return &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{TLSClientConfig: t},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

// caAnswer is step-ca's answer to /sign and /renew.
type caAnswer struct {
	Certificate string   `json:"crt"`
	CA          string   `json:"ca"`
	Chain       []string `json:"certChain"`
}

func (a *agent) caPost(ctx context.Context, client *http.Client, path string, body any) (caAnswer, error) {
	var out caAnswer
	content, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(a.cfg.CAURL, "/")+path, bytes.NewReader(content))
	if err != nil {
		return out, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	answer, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return out, err
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return out, fmt.Errorf("%s: %s %s", path, resp.Status, strings.TrimSpace(string(answer)))
	}
	if err := json.Unmarshal(answer, &out); err != nil {
		return out, err
	}
	return out, nil
}

// chainPEM is the leaf followed by its intermediates, as the control plane
// needs them to verify the leaf against the root alone.
func (c caAnswer) chainPEM() []byte {
	parts := c.Chain
	if len(parts) == 0 {
		parts = []string{c.Certificate, c.CA}
	}
	var b strings.Builder
	for _, p := range parts {
		b.WriteString(strings.TrimSpace(p) + "\n")
	}
	return []byte(b.String())
}

// renew asks the CA for a new certificate for the same key and name,
// signing in with the current one.
func (a *agent) renew(ctx context.Context) error {
	client, err := a.caClient(true)
	if err != nil {
		return err
	}
	answer, err := a.caPost(ctx, client, "/1.0/renew", map[string]any{})
	if err != nil {
		return err
	}
	if err := a.saveCertificate(answer.chainPEM(), nil); err != nil {
		return err
	}
	// The next connection to the control plane presents the new certificate.
	if t, ok := a.client.Transport.(*http.Transport); ok {
		t.CloseIdleConnections()
	}
	return nil
}

// saveCertificate writes a new key (when given) and chain, checks that they
// form a pair for this agent's name, and takes them into use.
func (a *agent) saveCertificate(chain, key []byte) error {
	keyPEM := key
	if keyPEM == nil {
		var err error
		if keyPEM, err = os.ReadFile(a.cfg.KeyFile); err != nil {
			return err
		}
	}
	pair, err := tls.X509KeyPair(chain, keyPEM)
	if err != nil {
		return err
	}
	if pair.Leaf, err = x509.ParseCertificate(pair.Certificate[0]); err != nil {
		return err
	}
	if len(pair.Leaf.DNSNames) != 1 || pair.Leaf.DNSNames[0] != a.cfg.CertificateName {
		return fmt.Errorf("the CA returned a certificate for %v, not %s", pair.Leaf.DNSNames, a.cfg.CertificateName)
	}
	// Both files are written in full before either is renamed, so only a
	// crash between the two renames leaves a mixed pair, which
	// loadCertificate leaves unused.
	var staged []string
	if key != nil {
		if err := stageFile(a.cfg.KeyFile, key, 0o600); err != nil {
			return err
		}
		staged = append(staged, a.cfg.KeyFile)
	}
	if err := stageFile(a.cfg.CertFile, chain, 0o644); err != nil {
		return err
	}
	staged = append(staged, a.cfg.CertFile)
	for _, path := range staged {
		if err := os.Rename(path+".next", path); err != nil {
			return err
		}
	}
	a.cert.Store(&pair)
	return nil
}

// stageFile writes path.next, to be renamed over path.
func stageFile(path string, content []byte, mode os.FileMode) error {
	next := path + ".next"
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(next, content, mode); err != nil {
		return err
	}
	return os.Chmod(next, mode)
}

// enroll takes a one-time token for certificate_name, makes a new key and
// asks the CA to sign it. The token comes on stdin, never in arguments.
func (a *agent) enroll(ctx context.Context, token string) error {
	if a.cfg.CertFile == "" || a.cfg.KeyFile == "" || a.cfg.CertificateName == "" || a.cfg.CAURL == "" {
		return errors.New("enrolling needs cert_file, key_file, certificate_name and ca_url")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: a.cfg.CertificateName}, DNSNames: []string{a.cfg.CertificateName}}, key)
	if err != nil {
		return err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	client, err := a.caClient(false)
	if err != nil {
		return err
	}
	answer, err := a.caPost(ctx, client, "/1.0/sign", map[string]any{
		"csr": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})), "ott": token})
	if err != nil {
		return err
	}
	return a.saveCertificate(answer.chainPEM(), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
}
