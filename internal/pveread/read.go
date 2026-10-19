// Package pveread exposes two fixed, authenticated local PVE observations.
// It never accepts an arbitrary API path or performs a mutation.
package pveread

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
	"regexp"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
)

type Config struct {
	Base          string `json:"base"`
	CA            string `json:"ca"`
	Authorization string `json:"authorization"`
	Node          string `json:"node"`
	// Storage is the guest storage id (PLAN 8.2). Readers configured before
	// the field existed keep local-lvm.
	Storage string `json:"storage"`
}
type Reader struct {
	client                             *http.Client
	base, authorization, node, storage string
}

func New(config Config) (*Reader, error) {
	u, err := url.Parse(config.Base)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("invalid PVE HTTPS origin")
	}
	if config.Storage == "" {
		config.Storage = "local-lvm"
	}
	if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,62}$`).MatchString(config.Node) || !regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,62}$`).MatchString(config.Storage) || config.Authorization == "" {
		return nil, errors.New("invalid PVE reader configuration")
	}
	ca, err := os.ReadFile(config.CA)
	if err != nil {
		return nil, errors.New("cannot read PVE CA")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, errors.New("invalid PVE CA")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, MaxConnsPerHost: 4, MaxIdleConnsPerHost: 4, IdleConnTimeout: 30 * time.Second}
	return &Reader{client: &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("PVE redirects refused") }}, base: config.Base, authorization: config.Authorization, node: config.Node, storage: config.Storage}, nil
}
func (r *Reader) Close() { r.client.CloseIdleConnections() }
func (r *Reader) get(ctx context.Context, path string) (any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.base+"/api2/json"+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", r.authorization)
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, errors.New("PVE HTTPS observation failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("PVE GET returned HTTP %d", resp.StatusCode)
	}
	var payload struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&payload); err != nil {
		return nil, errors.New("invalid PVE observation")
	}
	if len(payload.Data) == 0 || string(payload.Data) == "null" {
		return nil, errors.New("missing PVE observation")
	}
	var data any
	if err := json.Unmarshal(payload.Data, &data); err != nil {
		return nil, errors.New("invalid PVE data")
	}
	return data, nil
}
func (r *Reader) batch(ctx context.Context, paths map[string]string) (map[string]any, error) {
	group, ctx := errgroup.WithContext(ctx)
	group.SetLimit(4)
	out := map[string]any{}
	var mu sync.Mutex
	for key, path := range paths {
		group.Go(func() error {
			v, err := r.get(ctx, path)
			if err != nil {
				return err
			}
			mu.Lock()
			out[key] = v
			mu.Unlock()
			return nil
		})
	}
	return out, group.Wait()
}
func (r *Reader) Read(ctx context.Context, mode string) (map[string]any, error) {
	switch mode {
	case "inventory":
		// PVEAuditor alone silently omits volume contents. Refuse incomplete authority,
		// including an administrator downgrade, before using the list for admission.
		storagePath := "/storage/" + r.storage
		permissions, err := r.get(ctx, "/access/permissions?path="+url.QueryEscape(storagePath))
		if err != nil {
			return nil, err
		}
		paths, ok := permissions.(map[string]any)
		if !ok {
			return nil, errors.New("invalid storage permissions")
		}
		storage, _ := paths[storagePath].(map[string]any)
		if storage["Datastore.Audit"] != float64(1) || storage["Datastore.Allocate"] != float64(1) {
			return nil, errors.New("storage inventory authority is incomplete")
		}
		prefix := "/nodes/" + r.node
		return r.batch(ctx, map[string]string{"volumes": prefix + storagePath + "/content", "resources": "/cluster/resources", "storage": prefix + storagePath + "/status", "status": prefix + "/status"})
	case "topology":
		vnets, err := r.get(ctx, "/cluster/sdn/vnets")
		if err != nil {
			return nil, err
		}
		rows, ok := vnets.([]any)
		if !ok {
			return nil, errors.New("invalid VNet observation")
		}
		paths := map[string]string{}
		for _, v := range rows {
			row, ok := v.(map[string]any)
			if !ok {
				return nil, errors.New("invalid VNet")
			}
			name, _ := row["vnet"].(string)
			if regexp.MustCompile(`^t[0-9]{3}$`).MatchString(name) {
				paths[name] = "/cluster/sdn/vnets/" + name + "/subnets"
			}
		}
		subnets, err := r.batch(ctx, paths)
		if err != nil {
			return nil, err
		}
		return map[string]any{"vnets": vnets, "subnets": subnets}, nil
	default:
		return nil, errors.New("expected inventory or topology")
	}
}
