package snapshot

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
// with an API token that holds VM.Snapshot, VM.Snapshot.Rollback and
// VM.Audit only, and verifies the node's certificate against the cluster CA.
type pve struct {
	base, token, node string
	client            *http.Client
}

// apiError is an answer PVE gave: the request reached it and was refused.
// Any other error says nothing of what PVE did.
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

// guest is the API path of a guest on this node.
func (p *pve) guest(kind string, vmid int) string {
	kinds := map[string]string{"vm": "qemu", "ct": "lxc"}
	return fmt.Sprintf("/nodes/%s/%s/%d", url.PathEscape(p.node), kinds[kind], vmid)
}

// snapshots are the names of a guest's snapshots.
func (p *pve) snapshots(ctx context.Context, kind string, vmid int) (map[string]bool, error) {
	data, err := p.do(ctx, http.MethodGet, p.guest(kind, vmid)+"/snapshot", nil)
	if err != nil {
		return nil, err
	}
	var list []struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, s := range list {
		// "current" is the live state, not a snapshot.
		if s.Name != "current" {
			out[s.Name] = true
		}
	}
	return out, nil
}

// status is the guest's power state: running, stopped or paused.
func (p *pve) status(ctx context.Context, kind string, vmid int) (string, error) {
	data, err := p.do(ctx, http.MethodGet, p.guest(kind, vmid)+"/status/current", nil)
	if err != nil {
		return "", err
	}
	var s struct {
		Status    string `json:"status"`
		QMPStatus string `json:"qmpstatus"`
	}
	if err := json.Unmarshal(data, &s); err != nil {
		return "", err
	}
	if s.QMPStatus == "paused" || s.QMPStatus == "suspended" {
		return "paused", nil
	}
	return s.Status, nil
}

// start sends the request that starts a task, and returns its UPID.
func (p *pve) start(ctx context.Context, op, kind string, vmid int, name string) (string, error) {
	path := p.guest(kind, vmid) + "/snapshot"
	var data json.RawMessage
	var err error
	switch op {
	case "create":
		data, err = p.do(ctx, http.MethodPost, path, url.Values{"snapname": {name}})
	case "delete":
		data, err = p.do(ctx, http.MethodDelete, path+"/"+url.PathEscape(name), nil)
	case "rollback":
		data, err = p.do(ctx, http.MethodPost, path+"/"+url.PathEscape(name)+"/rollback", url.Values{})
	default:
		return "", fmt.Errorf("no task for %s", op)
	}
	if err != nil {
		return "", err
	}
	var upid string
	if err := json.Unmarshal(data, &upid); err != nil || !strings.HasPrefix(upid, "UPID:") {
		return "", fmt.Errorf("PVE answered with no task: %s", data)
	}
	return upid, nil
}

// taskTypes are the PVE task types of each operation, by guest kind.
var taskTypes = map[string]map[string]string{
	"vm": {"create": "qmsnapshot", "delete": "qmdelsnapshot", "rollback": "qmrollback"},
	"ct": {"create": "vzsnapshot", "delete": "vzdelsnapshot", "rollback": "vzrollback"},
}

// tasks are the UPIDs of the tasks of type op on the guest that this token
// started at or after since, running or ended, oldest first.
func (p *pve) tasks(ctx context.Context, op, kind string, vmid int, since int64) ([]string, error) {
	// source=all: the default lists only tasks that have ended.
	q := url.Values{"vmid": {fmt.Sprint(vmid)}, "typefilter": {taskTypes[kind][op]}, "since": {fmt.Sprint(since)}, "limit": {"500"}, "source": {"all"}}
	data, err := p.do(ctx, http.MethodGet, fmt.Sprintf("/nodes/%s/tasks?%s", url.PathEscape(p.node), q.Encode()), nil)
	if err != nil {
		return nil, err
	}
	var tasks []struct {
		UPID      string `json:"upid"`
		Type      string `json:"type"`
		ID        string `json:"id"`
		StartTime int64  `json:"starttime"`
	}
	if err := json.Unmarshal(data, &tasks); err != nil {
		return nil, err
	}
	// A UPID ends with the user that started the task.
	mine := ":" + p.tokenID() + ":"
	sort.SliceStable(tasks, func(i, j int) bool { return tasks[i].StartTime < tasks[j].StartTime })
	out := []string{}
	for _, t := range tasks {
		if t.Type == taskTypes[kind][op] && t.ID == fmt.Sprint(vmid) && t.StartTime >= since && strings.HasSuffix(t.UPID, mine) {
			out = append(out, t.UPID)
		}
	}
	return out, nil
}

// tokenID is the user part of the token, such as root@pam!carrel-snapshot.
func (p *pve) tokenID() string {
	id := strings.TrimPrefix(p.token, "PVEAPIToken=")
	if i := strings.LastIndex(id, "="); i >= 0 {
		id = id[:i]
	}
	return id
}

// taskStatus says whether a task has ended and, if so, its exit status.
func (p *pve) taskStatus(ctx context.Context, upid string) (ended bool, exit string, err error) {
	data, err := p.do(ctx, http.MethodGet, fmt.Sprintf("/nodes/%s/tasks/%s/status", url.PathEscape(p.node), url.PathEscape(upid)), nil)
	if err != nil {
		return false, "", err
	}
	var s struct {
		Status     string `json:"status"`
		ExitStatus string `json:"exitstatus"`
	}
	if err := json.Unmarshal(data, &s); err != nil {
		return false, "", err
	}
	return s.Status == "stopped", s.ExitStatus, nil
}

// version answers whether the API is reachable with the token.
func (p *pve) version(ctx context.Context) error {
	_, err := p.do(ctx, http.MethodGet, "/version", nil)
	return err
}
