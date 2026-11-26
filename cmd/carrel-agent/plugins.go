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
	"sync"
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
	pluginTimeout = 5 * time.Second
	// maxPluginMessage bounds one answer from a plugin.
	maxPluginMessage = 1 << 20
	// maxPluginResult bounds an operation's result: a few ids, not data.
	maxPluginResult = 256 << 10
	// pluginRefresh is how old the plugin report in a claim may be.
	pluginRefresh = 30 * time.Second
)

// checkPluginDir refuses a directory another user could place a socket in,
// or a symlink to one: a socket there is trusted with root operations.
func checkPluginDir(dir string) error {
	info, err := os.Lstat(dir)
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

// checkSocket refuses anything but a socket the agent's user owns.
func checkSocket(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if info.Mode().Type() != os.ModeSocket || !ok || int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("%s must be a socket owned by the agent's user", filepath.Base(path))
	}
	return nil
}

// dialPlugin connects to a plugin after checking the directory and the
// socket, on every connection: discovery and jobs alike.
func dialPlugin(dir, name string) (*grpc.ClientConn, pluginpb.PluginClient, error) {
	path := filepath.Join(dir, name+".sock")
	if err := checkPluginDir(dir); err != nil {
		return nil, nil, err
	}
	if err := checkSocket(path); err != nil {
		return nil, nil, err
	}
	conn, err := grpc.NewClient("unix://"+path, grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxPluginMessage)))
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

// clip cuts s to MaxPluginText as JSON carries it, on a rune boundary.
func clip(s string) string {
	if carrel.WireLen(s) <= carrel.MaxPluginText {
		return s
	}
	n := 0
	for i, r := range s {
		w := carrel.WireLen(string(r))
		if n+w > carrel.MaxPluginText {
			return s[:i]
		}
		n += w
	}
	return s
}

// describe asks one plugin what it is and whether this node can run it.
// Whatever the plugin answers, the result passes CheckPlugins: a bad plugin
// is reported by name and reason alone.
func describe(ctx context.Context, dir, name string) carrel.PluginInfo {
	info := describeRaw(ctx, dir, name)
	info.Version, info.Reason = clip(info.Version), clip(info.Reason)
	if msg := carrel.CheckPlugins([]carrel.PluginInfo{info}); msg != "" {
		return carrel.PluginInfo{Name: name, Contract: info.Contract, Reason: clip(msg)}
	}
	return info
}

func describeRaw(ctx context.Context, dir, name string) carrel.PluginInfo {
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
		info.Reason = fmt.Sprintf("the plugin on %s.sock calls itself %q", name, clip(d.Name))
		return info
	}
	if !slices.Contains(carrel.PluginContracts, d.Contract) {
		info.Reason = fmt.Sprintf("plugin %s %s speaks contract %d; this agent serves contracts %s: install a plugin release built for one of them",
			name, clip(d.Version), d.Contract, contracts())
		return info
	}
	for _, op := range d.Operations {
		info.Operations = append(info.Operations, carrel.PluginOperation{Name: op.Name, Description: op.Description,
			Params: json.RawMessage(op.ParamsSchema), Member: op.Member, ReadOnly: op.ReadOnly,
			Destructive: op.Destructive, Idempotent: op.Idempotent, Toolset: clip(op.Toolset), DryRun: op.DryRun,
			ObjectKind: clip(op.ObjectKind), ObjectEffect: clip(op.ObjectEffect), ObjectParam: clip(op.ObjectParam)})
	}
	for _, q := range d.Quota {
		info.Quota = append(info.Quota, carrel.PluginQuota{Name: clip(q.Name), DefaultLimit: q.DefaultLimit, Unit: clip(q.Unit)})
	}
	for _, k := range d.Objects {
		kind := carrel.PluginObjectKind{Name: clip(k.Name), Disk: k.Disk}
		for _, c := range k.Charges {
			kind.Charges = append(kind.Charges, carrel.PluginCharge{Dimension: clip(c.Dimension), Amount: c.Amount, Per: clip(c.Per)})
		}
		for _, h := range k.Holds {
			kind.Holds = append(kind.Holds, clip(h))
		}
		info.Objects = append(info.Objects, kind)
	}
	p, err := c.Probe(ctx, &pluginpb.ProbeRequest{})
	if err != nil {
		info.Reason = "probe failed: " + status.Convert(err).Message()
		return info
	}
	info.Supported, info.Reason = p.Supported, p.Reason
	return info
}

// discover reports every plugin socket in dir, sorted by name. Plugins are
// asked at once, each within pluginTimeout, so a hung one costs no more.
// A report past MaxPluginReport keeps the first plugins whole and the rest
// by name and reason.
func discover(ctx context.Context, dir string) []carrel.PluginInfo {
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err := checkPluginDir(dir); err != nil {
		return []carrel.PluginInfo{{Name: "plugin-dir", Reason: clip(err.Error())}}
	}
	sockets, _ := filepath.Glob(filepath.Join(dir, "*.sock"))
	sort.Strings(sockets)
	var names []string
	for _, s := range sockets {
		if name := strings.TrimSuffix(filepath.Base(s), ".sock"); carrel.PluginName(name) && len(names) < carrel.MaxPlugins {
			names = append(names, name)
		}
	}
	out := make([]carrel.PluginInfo, len(names))
	var wg sync.WaitGroup
	for i, name := range names {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out[i] = describe(ctx, dir, name)
		}()
	}
	wg.Wait()
	size := 0
	for i := range out {
		b, _ := json.Marshal(out[i])
		if size+len(b) > carrel.MaxPluginReport-carrel.MaxPlugins*2*carrel.MaxPluginText {
			out[i] = carrel.PluginInfo{Name: out[i].Name, Contract: out[i].Contract, Reason: "left out: the plugin report is full"}
			b, _ = json.Marshal(out[i])
		}
		size += len(b)
	}
	return out
}

// pluginReport is the latest report, never waited for: refreshPlugins makes
// it in the background, so a slow plugin cannot hold up a claim.
func (a *agent) pluginReport() []carrel.PluginInfo {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.plugins
}

// refreshPlugins remakes the report every pluginRefresh until stop. The
// first report is made before it returns, so the first claim carries it;
// that costs one pluginTimeout at most.
func (a *agent) refreshPlugins(stop context.Context) {
	set := func() {
		report := discover(stop, a.cfg.PluginDir)
		a.mu.Lock()
		a.plugins, a.pluginsAt = report, time.Now()
		a.mu.Unlock()
	}
	set()
	go func() {
		for sleep(stop, pluginRefresh); stop.Err() == nil; sleep(stop, pluginRefresh) {
			set()
		}
	}()
}

// pluginJob is a job with op "plugin".
type pluginJob struct {
	Plugin         string          `json:"plugin"`
	Call           string          `json:"call"`
	IdempotencyKey string          `json:"idempotency_key"`
	Operation      string          `json:"operation"`
	Params         json.RawMessage `json:"params"`
	DryRun         bool            `json:"dry_run"`
	// Reservation is the record the control plane holds for an object
	// operation (#663).
	Reservation string `json:"reservation"`
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
		// The report the control plane sent this on may be older than the
		// plugin now on the socket: a dry run goes only to an operation that
		// says, now, that it honours one. Any other would run for real.
		if j.DryRun && !slices.ContainsFunc(info.Operations, func(op carrel.PluginOperation) bool { return op.Name == j.Operation && op.DryRun }) {
			return refuse("plugin_refused", fmt.Sprintf("plugin %s operation %s does not take a dry run", j.Plugin, j.Operation))
		}
		// An object operation runs only on the record the control plane
		// reserved for it, and a reserved one only on a plugin that, now,
		// says it acts on an object: either way round the count would be
		// wrong.
		if !j.DryRun && slices.ContainsFunc(info.Operations, func(op carrel.PluginOperation) bool { return op.Name == j.Operation && op.ObjectKind != "" }) != (j.Reservation != "") {
			return refuse("plugin_refused", fmt.Sprintf("plugin %s operation %s and the control plane disagree on its object record", j.Plugin, j.Operation))
		}
		params := string(j.Params)
		if params == "" {
			params = "{}"
		}
		op, err = c.StartOperation(ctx, &pluginpb.StartRequest{IdempotencyKey: j.IdempotencyKey, Operation: j.Operation, Params: params,
			DryRun: j.DryRun, Reservation: j.Reservation})
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
	if len(op.Result) > maxPluginResult {
		return refuse("plugin_error", fmt.Sprintf("plugin %s returned a result over %d bytes", j.Plugin, maxPluginResult))
	}
	var result any
	if op.Result != "" && json.Unmarshal([]byte(op.Result), &result) != nil {
		return refuse("plugin_error", fmt.Sprintf("plugin %s returned a result that is not JSON", j.Plugin))
	}
	// Details that are not a small JSON object are dropped, not refused:
	// the operation failed either way.
	var details map[string]any
	if len(op.ErrorDetails) > carrel.MaxPluginText || json.Unmarshal([]byte(op.ErrorDetails), &details) != nil {
		details = nil
	}
	return reply(map[string]any{"ok": true, "result": map[string]any{"idempotency_key": op.IdempotencyKey,
		"state": op.State, "done": op.Done, "progress": op.Progress, "result": result, "error": clip(op.Error),
		"error_code": clip(op.ErrorCode), "error_details": details, "task": op.Task, "message": op.Message}})
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
