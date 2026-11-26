package main

// Plugins (#564, #660): services on unix sockets in plugin_dir, one
// <name>.sock each, speaking the contract in proto/plugin/v1. The agent
// describes and probes them, reports them in every claim, and relays the
// control plane's plugin jobs to them. A plugin keeps its operations by
// idempotency key, so a plugin or agent restart loses none: the control
// plane asks again by key.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/NYCU-WinLab/carrel/internal/carrel"
	"github.com/NYCU-WinLab/carrel/internal/pluginpb"
)

const (
	defaultPluginDir = "/run/carrel/plugins"
	// pluginTimeout bounds one call to a plugin; long work is an operation
	// the plugin runs on its own, never a long call.
	pluginTimeout = 10 * time.Second
	// pluginRefresh is how old the plugin report in a claim may be.
	pluginRefresh = 30 * time.Second
)

// checkPluginDir refuses a directory another user could place a socket in:
// a socket there is trusted with root operations.
func checkPluginDir(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || !ok {
		return fmt.Errorf("%s is not a directory", dir)
	}
	if int(st.Uid) != os.Geteuid() || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s must be owned by the agent's user and writable by nobody else", dir)
	}
	return nil
}

func dialPlugin(dir, name string) (*grpc.ClientConn, pluginpb.PluginClient, error) {
	conn, err := grpc.NewClient("unix://"+filepath.Join(dir, name+".sock"),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, nil, err
	}
	return conn, pluginpb.NewPluginClient(conn), nil
}

func contracts() string {
	s := make([]string, len(carrel.PluginContracts))
	for i, c := range carrel.PluginContracts {
		s[i] = fmt.Sprint(c)
	}
	return strings.Join(s, ", ")
}

// describe asks one plugin what it is and whether this node can run it.
func describe(ctx context.Context, dir, name string) carrel.PluginInfo {
	info := carrel.PluginInfo{Name: name}
	conn, c, err := dialPlugin(dir, name)
	if err != nil {
		info.Reason = err.Error()
		return info
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(ctx, pluginTimeout)
	defer cancel()
	d, err := c.Describe(ctx, &pluginpb.DescribeRequest{})
	if err != nil {
		info.Reason = "not answering: " + status.Convert(err).Message()
		return info
	}
	info.Version, info.Contract = d.Version, d.Contract
	if d.Name != name {
		info.Reason = fmt.Sprintf("the plugin on %s.sock calls itself %q", name, d.Name)
		return info
	}
	if !slices.Contains(carrel.PluginContracts, d.Contract) {
		info.Reason = fmt.Sprintf("plugin %s %s speaks contract %d; this agent serves contracts %s: install a plugin release built for one of them",
			name, d.Version, d.Contract, contracts())
		return info
	}
	for _, op := range d.Operations {
		info.Operations = append(info.Operations, carrel.PluginOperation{Name: op.Name, Description: op.Description,
			Params: json.RawMessage(op.ParamsSchema)})
	}
	p, err := c.Probe(ctx, &pluginpb.ProbeRequest{})
	if err != nil {
		info.Reason = "probe failed: " + status.Convert(err).Message()
		return info
	}
	info.Supported, info.Reason = p.Supported, p.Reason
	// A report the control plane would refuse is refused here, for this
	// plugin alone, so one bad plugin does not stop the agent's claims.
	if msg := carrel.CheckPlugins([]carrel.PluginInfo{info}); msg != "" {
		return carrel.PluginInfo{Name: name, Version: d.Version, Contract: d.Contract, Reason: msg}
	}
	return info
}

// discover reports every plugin socket in dir, sorted by name.
func discover(ctx context.Context, dir string) []carrel.PluginInfo {
	if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err := checkPluginDir(dir); err != nil {
		return []carrel.PluginInfo{{Name: "plugin-dir", Reason: err.Error()}}
	}
	sockets, _ := filepath.Glob(filepath.Join(dir, "*.sock"))
	sort.Strings(sockets)
	var out []carrel.PluginInfo
	for _, s := range sockets {
		name := strings.TrimSuffix(filepath.Base(s), ".sock")
		if !carrel.PluginName(name) || len(out) == carrel.MaxPlugins {
			continue
		}
		out = append(out, describe(ctx, dir, name))
	}
	return out
}

// pluginReport is the report for the next claim, refreshed when it is
// older than pluginRefresh.
func (a *agent) pluginReport(ctx context.Context) []carrel.PluginInfo {
	a.mu.Lock()
	fresh := time.Since(a.pluginsAt) < pluginRefresh
	report := a.plugins
	a.mu.Unlock()
	if fresh {
		return report
	}
	report = discover(ctx, a.cfg.PluginDir)
	a.mu.Lock()
	a.plugins, a.pluginsAt = report, time.Now()
	a.mu.Unlock()
	return report
}

// pluginJob is a job with op "plugin".
type pluginJob struct {
	Plugin         string          `json:"plugin"`
	Call           string          `json:"call"`
	IdempotencyKey string          `json:"idempotency_key"`
	Operation      string          `json:"operation"`
	Params         json.RawMessage `json:"params"`
}

func reply(v any) ([]byte, bool) {
	b, _ := json.Marshal(v)
	return b, false
}

func refuse(code, message string) ([]byte, bool) {
	b, _ := json.Marshal(map[string]any{"ok": false, "error_code": code, "error": message})
	return b, true
}

// pluginCall relays one plugin job and answers as node-agent.py does: ok
// with a result, or an error_code. plugin_unavailable means ask again.
func (a *agent) pluginCall(ctx context.Context, request []byte) ([]byte, bool) {
	var j pluginJob
	if json.Unmarshal(request, &j) != nil || !carrel.PluginName(j.Plugin) || j.IdempotencyKey == "" {
		return refuse("invalid", "a plugin job needs plugin, call and idempotency_key")
	}
	// The contract is checked on every call: the socket may now hold a
	// different build than the last report saw.
	info := describe(ctx, a.cfg.PluginDir, j.Plugin)
	if info.Version == "" && info.Contract == 0 {
		return refuse("plugin_unavailable", fmt.Sprintf("plugin %s: %s", j.Plugin, info.Reason))
	}
	if !slices.Contains(carrel.PluginContracts, info.Contract) {
		return refuse("plugin_refused", info.Reason)
	}
	conn, c, err := dialPlugin(a.cfg.PluginDir, j.Plugin)
	if err != nil {
		return refuse("plugin_unavailable", err.Error())
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(ctx, pluginTimeout)
	defer cancel()
	var op *pluginpb.Operation
	switch j.Call {
	case "start":
		if !info.Supported {
			return refuse("plugin_refused", fmt.Sprintf("plugin %s does not run on this node: %s", j.Plugin, info.Reason))
		}
		params := string(j.Params)
		if params == "" {
			params = "{}"
		}
		op, err = c.StartOperation(ctx, &pluginpb.StartRequest{IdempotencyKey: j.IdempotencyKey, Operation: j.Operation, Params: params})
	case "get":
		op, err = c.GetOperation(ctx, &pluginpb.GetRequest{IdempotencyKey: j.IdempotencyKey})
	case "cancel":
		op, err = c.Cancel(ctx, &pluginpb.CancelRequest{IdempotencyKey: j.IdempotencyKey})
	default:
		return refuse("invalid", fmt.Sprintf("call must be start, get or cancel, not %q", j.Call))
	}
	if err != nil {
		s := status.Convert(err)
		code := map[codes.Code]string{codes.NotFound: "not_found", codes.InvalidArgument: "invalid",
			codes.FailedPrecondition: "conflict", codes.Unavailable: "plugin_unavailable",
			codes.DeadlineExceeded: "plugin_unavailable"}[s.Code()]
		if code == "" {
			code = "plugin_error"
		}
		return refuse(code, fmt.Sprintf("plugin %s: %s", j.Plugin, s.Message()))
	}
	var result any
	if op.Result != "" && json.Unmarshal([]byte(op.Result), &result) != nil {
		return refuse("plugin_error", fmt.Sprintf("plugin %s returned a result that is not JSON", j.Plugin))
	}
	return reply(map[string]any{"ok": true, "result": map[string]any{"idempotency_key": op.IdempotencyKey,
		"state": op.State, "done": op.Done, "progress": op.Progress, "result": result, "error": op.Error,
		"task": op.Task, "message": op.Message}})
}

// dispatch runs a job: plugin jobs here, everything else in node-agent.py.
func (a *agent) dispatch(ctx context.Context, request []byte) ([]byte, bool) {
	var head struct {
		Op string `json:"op"`
	}
	if json.Unmarshal(request, &head) == nil && head.Op == "plugin" {
		return a.pluginCall(ctx, request)
	}
	return a.nodeAgent(ctx, request)
}
