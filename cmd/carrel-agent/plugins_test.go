package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/NYCU-WinLab/carrel/internal/carrel"
	"github.com/NYCU-WinLab/carrel/internal/pluginpb"
)

// fakePlugin keeps its operations in ops, which outlives a restart of the
// server as a plugin's state on disk would.
type fakePlugin struct {
	pluginpb.UnimplementedPluginServer
	name      string
	contract  uint32
	supported bool
	mu        *sync.Mutex
	ops       map[string]*pluginpb.Operation
	started   *atomic.Int32
	// types replaces the one snapshot operation; brokenProbe and hang make
	// a plugin misbehave.
	types   []*pluginpb.OperationType
	quota   []*pluginpb.QuotaDimension
	objects []*pluginpb.ObjectKind
	// reservations are what each start carried.
	reservations []string
	brokenProbe  bool
	hang         bool
}

func newFake(name string, contract uint32) *fakePlugin {
	return &fakePlugin{name: name, contract: contract, supported: true, mu: &sync.Mutex{},
		ops: map[string]*pluginpb.Operation{}, started: &atomic.Int32{}}
}

func (f *fakePlugin) Describe(ctx context.Context, _ *pluginpb.DescribeRequest) (*pluginpb.DescribeResponse, error) {
	if f.hang {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	types := f.types
	if types == nil {
		types = []*pluginpb.OperationType{{Name: "snapshot", ParamsSchema: `{"type":"object"}`}}
	}
	return &pluginpb.DescribeResponse{Name: f.name, Version: "1.0.0", Contract: f.contract, Operations: types, Quota: f.quota, Objects: f.objects}, nil
}

func (f *fakePlugin) Probe(context.Context, *pluginpb.ProbeRequest) (*pluginpb.ProbeResponse, error) {
	if f.brokenProbe {
		return nil, status.Error(codes.Internal, "probe broke")
	}
	if !f.supported {
		return &pluginpb.ProbeResponse{Reason: "no backup storage"}, nil
	}
	return &pluginpb.ProbeResponse{Supported: true}, nil
}

func (f *fakePlugin) StartOperation(_ context.Context, r *pluginpb.StartRequest) (*pluginpb.Operation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if op, ok := f.ops[r.IdempotencyKey]; ok {
		return op, nil
	}
	f.started.Add(1)
	f.reservations = append(f.reservations, r.Reservation)
	op := &pluginpb.Operation{IdempotencyKey: r.IdempotencyKey, State: "running", Task: "UPID:test:" + r.IdempotencyKey}
	f.ops[r.IdempotencyKey] = op
	return op, nil
}

func (f *fakePlugin) GetOperation(_ context.Context, r *pluginpb.GetRequest) (*pluginpb.Operation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	op, ok := f.ops[r.IdempotencyKey]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "no operation %q", r.IdempotencyKey)
	}
	return op, nil
}

func (f *fakePlugin) Cancel(_ context.Context, r *pluginpb.CancelRequest) (*pluginpb.Operation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	op, ok := f.ops[r.IdempotencyKey]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "no operation %q", r.IdempotencyKey)
	}
	op.State, op.Done = "cancelled", true
	return op, nil
}

// serve runs f on dir/<name>.sock until the returned stop is called.
func serve(t *testing.T, dir string, f *fakePlugin) func() {
	t.Helper()
	path := filepath.Join(dir, f.name+".sock")
	_ = os.Remove(path)
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	s := grpc.NewServer()
	pluginpb.RegisterPluginServer(s, f)
	go func() { _ = s.Serve(l) }()
	stopped := false
	stop := func() {
		if !stopped {
			stopped = true
			s.Stop()
		}
	}
	t.Cleanup(stop)
	return stop
}

// pluginDir is a short directory: a unix socket path has a 108 byte limit,
// which t.TempDir can pass.
func pluginDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "plugins")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func call(t *testing.T, a *agent, request string) map[string]any {
	t.Helper()
	out, _ := a.dispatch(context.Background(), []byte(request))
	var v map[string]any
	if err := json.Unmarshal(out, &v); err != nil {
		t.Fatalf("%s: %v", out, err)
	}
	return v
}

func TestTheAgentReportsItsPlugins(t *testing.T) {
	dir := pluginDir(t)
	serve(t, dir, newFake("snapshot", 1))
	serve(t, dir, newFake("old", 9))
	unsupported := newFake("freeze", 1)
	unsupported.supported = false
	serve(t, dir, unsupported)
	if err := os.WriteFile(filepath.Join(dir, "dead.sock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	report := discover(context.Background(), dir)
	byName := map[string]carrel.PluginInfo{}
	for _, p := range report {
		byName[p.Name] = p
	}
	if len(report) != 4 {
		t.Fatalf("%+v", report)
	}
	if s := byName["snapshot"]; !s.Supported || s.Contract != 1 || len(s.Operations) != 1 || s.Operations[0].Name != "snapshot" {
		t.Fatalf("snapshot: %+v", s)
	}
	if o := byName["old"]; o.Supported || !strings.Contains(o.Reason, "speaks contract 9") || !strings.Contains(o.Reason, "install a plugin release") {
		t.Fatalf("old: %+v", o)
	}
	if f := byName["freeze"]; f.Supported || f.Reason != "no backup storage" {
		t.Fatalf("freeze: %+v", f)
	}
	if d := byName["dead"]; d.Supported || !strings.Contains(d.Reason, "must be a socket") {
		t.Fatalf("dead: %+v", d)
	}
	if msg := carrel.CheckPlugins(report); msg != "" {
		t.Fatalf("the control plane would refuse the report: %s", msg)
	}
	// A directory another user can write to is not trusted.
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if r := discover(context.Background(), dir); len(r) != 1 || r[0].Supported || !strings.Contains(r[0].Reason, "writable by nobody else") {
		t.Fatalf("open directory: %+v", r)
	}
	if r := discover(context.Background(), filepath.Join(dir, "none")); r != nil {
		t.Fatalf("no directory: %+v", r)
	}
}

func TestAPluginRestartLosesNoOperation(t *testing.T) {
	dir := pluginDir(t)
	f := newFake("snapshot", 1)
	stop := serve(t, dir, f)
	a := &agent{cfg: config{PluginDir: dir}}
	start := `{"op":"plugin","plugin":"snapshot","call":"start","idempotency_key":"k1","operation":"snapshot","params":{}}`
	get := `{"op":"plugin","plugin":"snapshot","call":"get","idempotency_key":"k1"}`
	if v := call(t, a, start); v["ok"] != true || v["result"].(map[string]any)["state"] != "running" {
		t.Fatalf("start: %v", v)
	}
	stop()
	if v := call(t, a, get); v["ok"] != false || v["error_code"] != "plugin_unavailable" {
		t.Fatalf("plugin down: %v", v)
	}
	// The plugin comes back with its state: the same key, the same task.
	serve(t, dir, f)
	v := call(t, a, get)
	if v["ok"] != true || v["result"].(map[string]any)["task"] != "UPID:test:k1" {
		t.Fatalf("after restart: %v", v)
	}
	if v := call(t, a, start); v["result"].(map[string]any)["task"] != "UPID:test:k1" || f.started.Load() != 1 {
		t.Fatalf("start again: %v, started %d", v, f.started.Load())
	}
	// A new agent process asks by the same key.
	again := &agent{cfg: config{PluginDir: dir}}
	if v := call(t, again, get); v["result"].(map[string]any)["task"] != "UPID:test:k1" {
		t.Fatalf("new agent: %v", v)
	}
	if v := call(t, again, `{"op":"plugin","plugin":"snapshot","call":"cancel","idempotency_key":"k1"}`); v["result"].(map[string]any)["state"] != "cancelled" {
		t.Fatalf("cancel: %v", v)
	}
	if v := call(t, again, `{"op":"plugin","plugin":"snapshot","call":"get","idempotency_key":"nope"}`); v["error_code"] != "not_found" {
		t.Fatalf("unknown key: %v", v)
	}
}

func TestAPluginOutsideTheContractsIsRefused(t *testing.T) {
	dir := pluginDir(t)
	serve(t, dir, newFake("snapshot", 9))
	unsupported := newFake("freeze", 1)
	unsupported.supported = false
	serve(t, dir, unsupported)
	a := &agent{cfg: config{PluginDir: dir}}
	v := call(t, a, `{"op":"plugin","plugin":"snapshot","call":"start","idempotency_key":"k","operation":"snapshot"}`)
	if v["error_code"] != "plugin_refused" || !strings.Contains(v["error"].(string), "install a plugin release") {
		t.Fatalf("contract 9: %v", v)
	}
	// Reads and cancels too: only start needs Probe, so the contract check
	// is what stops these.
	v = call(t, a, `{"op":"plugin","plugin":"snapshot","call":"get","idempotency_key":"k"}`)
	if v["error_code"] != "plugin_refused" {
		t.Fatalf("contract 9 get: %v", v)
	}
	v = call(t, a, `{"op":"plugin","plugin":"freeze","call":"start","idempotency_key":"k","operation":"snapshot"}`)
	if v["error_code"] != "plugin_refused" || !strings.Contains(v["error"].(string), "no backup storage") {
		t.Fatalf("unsupported: %v", v)
	}
	for _, bad := range []string{
		`{"op":"plugin","plugin":"../x","call":"get","idempotency_key":"k"}`,
		`{"op":"plugin","plugin":"snapshot","call":"get"}`,
	} {
		if v := call(t, a, bad); v["error_code"] != "invalid" {
			t.Fatalf("%s: %v", bad, v)
		}
	}
}

// The real agent loop against a real control plane: the claim carries the
// plugin report, and a plugin job runs through the agent, not node-agent.py.
func TestAPluginJobRunsThroughTheAgentEndToEnd(t *testing.T) {
	dir := t.TempDir()
	plugins := pluginDir(t)
	serve(t, plugins, newFake("snapshot", 1))
	store, err := carrel.OpenStore(filepath.Join(dir, "carrel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.DB.Close()
	token := "agent-token"
	sum := sha256.Sum256([]byte(token))
	cfg := carrel.Config{Nodes: []carrel.NodeConfig{
		{Name: "pve1", Target: "carrel-node", Transport: "agent", AgentTokenSHA256: hex.EncodeToString(sum[:]), AgentSource: "127.0.0.1"},
	}}
	p := carrel.NewPlatform(store, sshOnly{}, cfg)
	p.UseAgents()
	server := httptest.NewTLSServer(p.AgentHandler())
	defer server.Close()
	ca := writeFile(t, dir, "ca.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})))
	conf, _ := json.Marshal(config{Control: server.URL, CAFile: ca, TokenFile: writeFile(t, dir, "token", token+"\n"),
		Node: "pve1", PluginDir: plugins, Lock: filepath.Join(dir, "lock")})
	a, err := load(writeFile(t, dir, "agent.json", string(conf)))
	if err != nil {
		t.Fatal(err)
	}
	a.session = "s1"
	ctx, stop := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.loop(ctx); close(done) }()
	defer func() { stop(); <-done }()

	call, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	v, err := p.Backend.Call(call, carrel.D{"op": "plugin", "plugin": "snapshot", "call": "start",
		"idempotency_key": "e2e", "operation": "snapshot", "params": carrel.D{}}, "carrel-node")
	if err != nil || v.(map[string]any)["task"] != "UPID:test:e2e" {
		t.Fatalf("plugin job: %v %v", v, err)
	}
	reported := p.Hub.Plugins("pve1", time.Now())
	if len(reported) != 1 || reported[0].Name != "snapshot" || !reported[0].Supported {
		t.Fatalf("hub: %+v", reported)
	}
	if s := p.Hub.Status("pve1", time.Now()); s["plugins"] == nil {
		t.Fatalf("node_list status has no plugins: %v", s)
	}
}

// A plugin's answer can never break the claim: a bad schema behind a broken
// Probe, or an oversized report, still yields a report the control plane
// takes.
func TestABadPluginCannotBreakTheReport(t *testing.T) {
	dir := pluginDir(t)
	bad := newFake("bad", 1)
	bad.types = []*pluginpb.OperationType{{Name: "snapshot", ParamsSchema: "{"}}
	bad.brokenProbe = true
	serve(t, dir, bad)
	big := strings.Repeat("x", carrel.MaxPluginSchema-64)
	var types []*pluginpb.OperationType
	for i := 0; i < carrel.MaxPluginOperations; i++ {
		types = append(types, &pluginpb.OperationType{Name: fmt.Sprintf("op%d", i), ParamsSchema: `{"description":"` + big + `"}`})
	}
	for _, name := range []string{"big1", "big2", "big3"} {
		f := newFake(name, 1)
		f.types = types
		serve(t, dir, f)
	}
	report := discover(context.Background(), dir)
	if msg := carrel.CheckPlugins(report); msg != "" {
		t.Fatalf("the control plane would refuse the report: %s", msg)
	}
	byName := map[string]carrel.PluginInfo{}
	for _, p := range report {
		byName[p.Name] = p
	}
	if b := byName["bad"]; b.Supported || len(b.Operations) != 0 || !strings.Contains(b.Reason, "JSON object schema") {
		t.Fatalf("bad: %+v", b)
	}
	if b := byName["big1"]; !b.Supported || len(b.Operations) != carrel.MaxPluginOperations {
		t.Fatalf("big1 should be whole: %+v", b.Reason)
	}
	if b := byName["big3"]; len(b.Operations) != 0 || !strings.Contains(b.Reason, "report is full") {
		t.Fatalf("big3 should be left out: %+v", b.Reason)
	}
	if _, err := json.Marshal(report); err != nil {
		t.Fatal(err)
	}
}

// Hung plugins are asked at once, so discovery takes one timeout, not one
// per plugin; and the claim never waits for discovery at all.
func TestHungPluginsDoNotHoldUpTheClaim(t *testing.T) {
	dir := pluginDir(t)
	for _, name := range []string{"h1", "h2", "h3", "h4"} {
		f := newFake(name, 1)
		f.hang = true
		serve(t, dir, f)
	}
	start := time.Now()
	report := discover(context.Background(), dir)
	if took := time.Since(start); took > pluginTimeout+2*time.Second || len(report) != 4 {
		t.Fatalf("discover took %s for %d plugins", took, len(report))
	}
	a := &agent{cfg: config{PluginDir: dir}}
	stop, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.refreshPlugins(stop)
	start = time.Now()
	_ = a.pluginReport()
	if took := time.Since(start); took > 100*time.Millisecond {
		t.Fatalf("pluginReport waited %s", took)
	}
}

// Every connection checks the socket, jobs as well as discovery: a symlink
// in place of a socket is refused.
func TestAJobRefusesASymlinkedSocket(t *testing.T) {
	dir, other := pluginDir(t), pluginDir(t)
	serve(t, other, newFake("snapshot", 1))
	if err := os.Symlink(filepath.Join(other, "snapshot.sock"), filepath.Join(dir, "snapshot.sock")); err != nil {
		t.Fatal(err)
	}
	a := &agent{cfg: config{PluginDir: dir}}
	v := call(t, a, `{"op":"plugin","plugin":"snapshot","call":"get","idempotency_key":"k1"}`)
	if v["ok"] != false || v["error_code"] != "plugin_unavailable" || !strings.Contains(v["error"].(string), "must be a socket") {
		t.Fatalf("%v", v)
	}
}

// Text and schemas are measured as JSON carries them: a reason of CJK
// characters cut at the limit, or a schema of escaped characters, still
// passes the control plane's check after the trip.
func TestThePluginReportSurvivesTheWire(t *testing.T) {
	reason := clip("xx" + strings.Repeat("中", 600))
	if !utf8.ValidString(reason) || carrel.WireLen(reason) > carrel.MaxPluginText {
		t.Fatalf("clip: valid %v, %d bytes", utf8.ValidString(reason), carrel.WireLen(reason))
	}
	info := []carrel.PluginInfo{{Name: "a", Contract: 1, Reason: reason, Version: clip(strings.Repeat("<", 2000)),
		Operations: []carrel.PluginOperation{{Name: "x", Params: json.RawMessage(`{"d":"` + strings.Repeat("<", 4000) + `"}`)}}}}
	if carrel.CheckPlugins(info) == "" {
		t.Fatal("a schema 6 times its size on the wire was taken")
	}
	info[0].Operations = nil
	b, _ := json.Marshal(info)
	var back []carrel.PluginInfo
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if msg := carrel.CheckPlugins(back); msg != "" {
		t.Fatalf("the control plane would refuse it: %s", msg)
	}
}

// A dry run reaches only an operation the plugin on the socket now says
// takes one: a plugin downgraded since the last report would run it.
func TestADryRunReachesOnlyAPluginThatTakesOne(t *testing.T) {
	dir := pluginDir(t)
	old := newFake("snapshot", 1)
	serve(t, dir, old)
	a := &agent{cfg: config{PluginDir: dir}}
	job := `{"op":"plugin","plugin":"snapshot","call":"start","operation":"snapshot","idempotency_key":"k1","dry_run":true}`
	if r := call(t, a, job); r["ok"] != false || old.started.Load() != 0 || !strings.Contains(fmt.Sprint(r), "does not take a dry run") {
		t.Fatalf("undeclared dry run: %v, %d started", r, old.started.Load())
	}
	dir2 := pluginDir(t)
	current := newFake("snapshot", 1)
	current.types = []*pluginpb.OperationType{{Name: "snapshot", ParamsSchema: `{"type":"object"}`, DryRun: true}}
	serve(t, dir2, current)
	b := &agent{cfg: config{PluginDir: dir2}}
	if r := call(t, b, job); r["ok"] != true || current.started.Load() != 1 {
		t.Fatalf("declared dry run: %v", r)
	}
}

// An object operation starts only with the record the control plane
// reserved, and a reservation only reaches a plugin that, now, says the
// operation acts on an object (#663). The report carries the declaration.
func TestAnObjectOperationStartsOnlyOnItsReservation(t *testing.T) {
	dir := pluginDir(t)
	p := newFake("copies", 1)
	p.types = []*pluginpb.OperationType{{Name: "take", ParamsSchema: `{"type":"object"}`, ObjectKind: "copy", ObjectEffect: "create", ObjectParam: "name"}}
	p.quota = []*pluginpb.QuotaDimension{{Name: "copies", DefaultLimit: 2}}
	p.objects = []*pluginpb.ObjectKind{{Name: "copy", Holds: []string{"freeze"}, Charges: []*pluginpb.Charge{{Dimension: "copies", Amount: 1}}}}
	serve(t, dir, p)
	a := &agent{cfg: config{PluginDir: dir}}
	info := describe(context.Background(), dir, "copies")
	if !info.Supported || len(info.Objects) != 1 || info.Objects[0].Holds[0] != "freeze" || info.Quota[0].DefaultLimit != 2 || info.Operations[0].ObjectEffect != "create" {
		t.Fatalf("report: %+v", info)
	}
	bare := `{"op":"plugin","plugin":"copies","call":"start","operation":"take","idempotency_key":"k1"}`
	if r := call(t, a, bare); r["ok"] != false || p.started.Load() != 0 {
		t.Fatalf("no reservation: %v", r)
	}
	spec := carrel.PluginObjectSpec(info, info.Operations[0])
	reserved := `{"op":"plugin","plugin":"copies","call":"start","operation":"take","idempotency_key":"k2","reservation":"copies/copy/10100/a","object_spec":"` + spec + `"}`
	if r := call(t, a, reserved); r["ok"] != true || p.started.Load() != 1 || p.reservations[0] != "copies/copy/10100/a" {
		t.Fatalf("reserved: %v, %v", r, p.reservations)
	}
	// The plugin changed what a copy holds since the control plane charged
	// by its report: the start is refused.
	p.mu.Lock()
	p.objects[0].Holds = nil
	p.mu.Unlock()
	again := strings.Replace(reserved, `"k2"`, `"k3"`, 1)
	if r := call(t, a, again); r["ok"] != false || p.started.Load() != 1 {
		t.Fatalf("a changed declaration started: %v", r)
	}

	dir2 := pluginDir(t)
	plain := newFake("copies", 1)
	plain.types = []*pluginpb.OperationType{{Name: "take", ParamsSchema: `{"type":"object"}`}}
	serve(t, dir2, plain)
	b := &agent{cfg: config{PluginDir: dir2}}
	if r := call(t, b, reserved); r["ok"] != false || plain.started.Load() != 0 {
		t.Fatalf("a reservation reached a plugin without objects: %v", r)
	}
}
