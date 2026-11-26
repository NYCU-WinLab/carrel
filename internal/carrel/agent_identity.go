package carrel

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"os"
	"regexp"
	"sync"
	"time"
)

// agentName is a lower-case DNS name of at least 3 labels.
var agentName = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?){2,}$`)

// A node agent on certificate sign-in (#601) presents a client certificate
// from the lab step-ca, issued by one provisioner (agent_provisioner) for one
// name (the node's agent_certificate). The control plane checks it on every
// request, not only at the handshake: a kept-alive connection or an open
// console outlives the handshake, and must not outlive the certificate.

// oidStepProvisioner is the extension step-ca adds to every certificate it
// signs: the provisioner's type, name and credential id (its key id for a
// JWK provisioner).
var oidStepProvisioner = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37476, 9000, 64, 1}

type stepProvisioner struct {
	Type          int
	Name          []byte
	CredentialID  []byte
	KeyValuePairs []string `asn1:"optional,omitempty"`
}

// stepProvisionerOf returns the provisioner's credential id a certificate
// names, or "" when it names none.
func stepProvisionerOf(c *x509.Certificate) string {
	for _, e := range c.Extensions {
		if !e.Id.Equal(oidStepProvisioner) {
			continue
		}
		var p stepProvisioner
		if rest, err := asn1.Unmarshal(e.Value, &p); err != nil || len(rest) != 0 {
			return ""
		}
		return string(p.CredentialID)
	}
	return ""
}

// LoadCertPool reads PEM certificates, failing when the file holds none.
func LoadCertPool(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New(path + " holds no certificate")
	}
	return pool, nil
}

type agentRoots struct {
	once sync.Once
	pool *x509.CertPool
}

func (p *Platform) agentClientRoots() *x509.CertPool {
	p.agentRoots.once.Do(func() {
		if p.Config.AgentClientCAFile == "" {
			return
		}
		pool, err := LoadCertPool(p.Config.AgentClientCAFile)
		if err != nil {
			// Config validation read it at start; a pool that cannot load
			// now admits no certificate.
			return
		}
		p.agentRoots.pool = pool
	})
	return p.agentRoots.pool
}

// agentCertificate checks the client certificate of a request from node n,
// at now: it chains to the lab root for client use, names exactly the
// node's agent_certificate, and comes from agent_provisioner. It returns
// when the certificate expires.
func (p *Platform) agentCertificate(n NodeConfig, state *tls.ConnectionState, now time.Time) (time.Time, bool) {
	roots := p.agentClientRoots()
	if roots == nil || state == nil || len(state.PeerCertificates) == 0 || n.AgentCertificate == "" {
		return time.Time{}, false
	}
	leaf := state.PeerCertificates[0]
	intermediates := x509.NewCertPool()
	for _, c := range state.PeerCertificates[1:] {
		intermediates.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now,
		DNSName: n.AgentCertificate, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return time.Time{}, false
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != n.AgentCertificate || len(leaf.IPAddresses)+len(leaf.URIs)+len(leaf.EmailAddresses) != 0 {
		return time.Time{}, false
	}
	if p.Config.AgentProvisioner == "" || !bytes.Equal([]byte(stepProvisionerOf(leaf)), []byte(p.Config.AgentProvisioner)) {
		return time.Time{}, false
	}
	return leaf.NotAfter, true
}
