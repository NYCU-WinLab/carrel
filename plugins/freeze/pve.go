package freeze

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

// pve is the Proxmox VE HTTP API of the node the plugin runs on. It acts
// with an API token, and verifies the node's certificate against the cluster CA.
type pve struct {
	base, token, node string
	client            *http.Client
}

// apiError is an answer PVE gave: the request reached it and was refused.
// Any other error says nothing of what PVE did. A status from 502 up is not
// PVE's answer: pveproxy gives 59x of its own when pvedaemon is slow, and
// pvedaemon may still start the task.
type apiError struct {
	Status  int
	Message string
}

func (e *apiError) Error() string { return fmt.Sprintf("PVE answered %d: %s", e.Status, e.Message) }

func newPVE(base, token, node, caFile string) (*pve, error) {
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read the PVE CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("the PVE CA file holds no certificate")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	return &pve{base: strings.TrimRight(base, "/"), token: token, node: node,
		client: &http.Client{Transport: transport, Timeout: 30 * time.Second}}, nil
}

// do sends one request and returns the answer's data.
func (p *pve) do(ctx context.Context, method, path string, form url.Values) (json.RawMessage, error) {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, p.base+"/api2/json"+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", p.token)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 502 {
		return nil, fmt.Errorf("PVE's proxy answered %s", resp.Status)
	}
	if resp.StatusCode >= 300 {
		// PVE puts the reason in the status line, and field errors in the body.
		message := strings.TrimSpace(strings.TrimPrefix(resp.Status, fmt.Sprint(resp.StatusCode)))
		var e struct {
			Errors map[string]string `json:"errors"`
		}
		if json.Unmarshal(raw, &e) == nil {
			for k, v := range e.Errors {
				message += fmt.Sprintf("; %s: %s", k, strings.TrimSpace(v))
			}
		}
		return nil, &apiError{Status: resp.StatusCode, Message: message}
	}
	var out struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("PVE answered with no JSON: %w", err)
	}
	return out.Data, nil
}

// version answers whether the API is reachable with the token.
func (p *pve) version(ctx context.Context) error {
	_, err := p.do(ctx, http.MethodGet, "/version", nil)
	return err
}

// needed are the privileges the token must hold, by the path they are held on.
func needed(storage string) map[string][]string {
	return map[string][]string{
		"/vms":                {"VM.Audit", "VM.Backup"},
		"/storage/" + storage: {"Datastore.Audit", "Datastore.AllocateSpace"},
	}
}

// missing are the needed privileges the token does not hold, as "<priv> on <path>".
func (p *pve) missing(ctx context.Context, storage string) ([]string, error) {
	need := needed(storage)
	paths := make([]string, 0, len(need))
	for path := range need {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	out := []string{}
	for _, path := range paths {
		raw, err := p.do(ctx, http.MethodGet, "/access/permissions?"+url.Values{"path": {path}}.Encode(), nil)
		if err != nil {
			return nil, err
		}
		var perms map[string]map[string]int
		if err := json.Unmarshal(raw, &perms); err != nil {
			return nil, fmt.Errorf("PVE's permissions: %w", err)
		}
		for _, priv := range need[path] {
			if _, ok := perms[path][priv]; !ok {
				out = append(out, priv+" on "+path)
			}
		}
	}
	return out, nil
}
