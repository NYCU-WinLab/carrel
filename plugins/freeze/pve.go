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
		"/vms":                {"VM.Audit", "VM.Backup", "VM.Allocate"},
		"/storage/" + storage: {"Datastore.Audit", "Datastore.AllocateSpace", "Datastore.Allocate"},
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

// kinds are the API names of the guest kinds.
var kinds = map[string]string{"vm": "qemu", "ct": "lxc"}

// guest is the API path of a guest on this node.
func (p *pve) guest(kind string, vmid int) string {
	return fmt.Sprintf("/nodes/%s/%s/%d", url.PathEscape(p.node), kinds[kind], vmid)
}

// exists says whether the node has the guest.
func (p *pve) exists(ctx context.Context, kind string, vmid int) (bool, error) {
	data, err := p.do(ctx, http.MethodGet, fmt.Sprintf("/nodes/%s/%s", url.PathEscape(p.node), kinds[kind]), nil)
	if err != nil {
		return false, err
	}
	var list []struct {
		VMID int `json:"vmid"`
	}
	if err := json.Unmarshal(data, &list); err != nil {
		return false, err
	}
	for _, g := range list {
		if g.VMID == vmid {
			return true, nil
		}
	}
	return false, nil
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

// snapshots counts the guest's disk snapshots.
func (p *pve) snapshots(ctx context.Context, kind string, vmid int) (int, error) {
	data, err := p.do(ctx, http.MethodGet, p.guest(kind, vmid)+"/snapshot", nil)
	if err != nil {
		return 0, err
	}
	var list []struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(data, &list); err != nil {
		return 0, err
	}
	n := 0
	for _, s := range list {
		// "current" is the live state, not a snapshot.
		if s.Name != "current" {
			n++
		}
	}
	return n, nil
}

// upid reads the task a request started.
func upid(data json.RawMessage) (string, error) {
	var id string
	if err := json.Unmarshal(data, &id); err != nil || !strings.HasPrefix(id, "UPID:") {
		return "", fmt.Errorf("PVE answered with no task: %s", data)
	}
	return id, nil
}

// start sends the request that starts the task of the run's phase, and
// returns its UPID: a backup of the stopped guest, or its removal.
func (p *pve) start(ctx context.Context, r *run) (string, error) {
	var data json.RawMessage
	var err error
	switch r.Phase {
	case "backup":
		data, err = p.do(ctx, http.MethodPost, fmt.Sprintf("/nodes/%s/vzdump", url.PathEscape(p.node)), url.Values{
			"vmid": {fmt.Sprint(r.VMID)}, "storage": {r.Storage}, "mode": {"stop"}, "notes-template": {r.Note}})
	case "destroy":
		data, err = p.do(ctx, http.MethodDelete, p.guest(r.Kind, r.VMID)+"?"+url.Values{"purge": {"1"}, "destroy-unreferenced-disks": {"1"}}.Encode(), nil)
	default:
		return "", fmt.Errorf("no task for phase %q", r.Phase)
	}
	if err != nil {
		return "", err
	}
	return upid(data)
}

// taskType is the PVE type of the task of the run's phase.
func taskType(r *run) string {
	if r.Phase == "destroy" {
		return map[string]string{"vm": "qmdestroy", "ct": "vzdestroy"}[r.Kind]
	}
	return "vzdump"
}

// tasks are the UPIDs of the tasks of type tt on the guest that this token
// started at or after since, running or ended, oldest first.
func (p *pve) tasks(ctx context.Context, tt string, vmid int, since int64) ([]string, error) {
	// source=all: the default lists only tasks that have ended.
	q := url.Values{"vmid": {fmt.Sprint(vmid)}, "typefilter": {tt}, "since": {fmt.Sprint(since)}, "limit": {"500"}, "source": {"all"}}
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
		if t.Type == tt && t.ID == fmt.Sprint(vmid) && t.StartTime >= since && strings.HasSuffix(t.UPID, mine) {
			out = append(out, t.UPID)
		}
	}
	return out, nil
}

// tokenID is the user part of the token, such as root@pam!carrel-freeze.
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

// stopTask asks PVE to stop a running task.
func (p *pve) stopTask(ctx context.Context, upid string) error {
	_, err := p.do(ctx, http.MethodDelete, fmt.Sprintf("/nodes/%s/tasks/%s", url.PathEscape(p.node), url.PathEscape(upid)), nil)
	return err
}

// backup is a backup on the storage as PVE lists it.
type backup struct {
	Volid        string `json:"volid"`
	Notes        string `json:"notes"`
	Size         int64  `json:"size"`
	Protected    int    `json:"protected"`
	Verification struct {
		State string `json:"state"`
	} `json:"verification"`
}

// backupOf is the backup of the guest whose notes are exactly note, or nil.
// More than one is an error: which is the run's would be a guess.
func (p *pve) backupOf(ctx context.Context, storage string, vmid int, note string) (*backup, error) {
	q := url.Values{"content": {"backup"}, "vmid": {fmt.Sprint(vmid)}}
	data, err := p.do(ctx, http.MethodGet, fmt.Sprintf("/nodes/%s/storage/%s/content?%s", url.PathEscape(p.node), url.PathEscape(storage), q.Encode()), nil)
	if err != nil {
		return nil, err
	}
	var list []backup
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, err
	}
	var found *backup
	for i := range list {
		if strings.TrimSpace(list[i].Notes) == note {
			if found != nil {
				return nil, errors.New("more than one backup carries this run's note")
			}
			found = &list[i]
		}
	}
	return found, nil
}

// protect marks a backup protected, so a prune job cannot take it.
func (p *pve) protect(ctx context.Context, storage, volid string, on bool) error {
	v := "0"
	if on {
		v = "1"
	}
	_, err := p.do(ctx, http.MethodPut, fmt.Sprintf("/nodes/%s/storage/%s/content/%s", url.PathEscape(p.node), url.PathEscape(storage), url.PathEscape(volid)), url.Values{"protected": {v}})
	return err
}

// removeBackup deletes a backup, lifting its protection first.
func (p *pve) removeBackup(ctx context.Context, storage string, b *backup) error {
	if b.Protected != 0 {
		if err := p.protect(ctx, storage, b.Volid, false); err != nil {
			return err
		}
	}
	_, err := p.do(ctx, http.MethodDelete, fmt.Sprintf("/nodes/%s/storage/%s/content/%s", url.PathEscape(p.node), url.PathEscape(storage), url.PathEscape(b.Volid)), nil)
	return err
}
