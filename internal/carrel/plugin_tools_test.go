package carrel

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakePlugins answers plugin jobs as an agent with one plugin would: it
// keeps operations by key, finishes each on its second get, and records
// every job.
type fakePlugins struct {
	mu     sync.Mutex
	ops    map[string]D
	gets   map[string]int
	starts []D
	// fail, when set, is the backend_code every call fails with; outcome,
	// when set, is the state an operation ends in instead of succeeded.
	fail, outcome string
}

func (f *fakePlugins) call(r D, target string) (any, error) {
	if r["op"] != "plugin" {
		return D{"status": "running"}, nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != "" {
		return nil, Failure{D{"ok": false, "error": D{"code": "backend_unavailable", "backend_code": f.fail}}}
	}
	key := str(r["idempotency_key"])
	switch r["call"] {
	case "start":
		f.starts = append(f.starts, clone(r))
		if f.ops[key] == nil {
			f.ops[key] = D{"idempotency_key": key, "state": "running", "done": false, "progress": 10, "task": "UPID:test:" + key, "message": "copying"}
		}
	case "get":
		if f.ops[key] == nil {
			return nil, Failure{D{"ok": false, "error": D{"code": "backend_unavailable", "backend_code": "not_found"}}}
		}
		if f.gets[key]++; f.gets[key] >= 2 {
			if f.outcome != "" {
				f.ops[key] = merge(f.ops[key], D{"state": f.outcome, "done": true, "error": "disk full"})
			} else {
				f.ops[key] = merge(f.ops[key], D{"state": "succeeded", "done": true, "progress": 100, "result": D{"snapshot": "s-" + key}})
			}
		}
	}
	return clone(f.ops[key]), nil
}

// withPlugin makes node carrel01 an agent that reports a snapshot plugin
// with a member operation and an admin one, and answers its jobs.
func withPlugin(t *testing.T, p *Platform, b *fakeBackend) *fakePlugins {
	t.Helper()
	f := &fakePlugins{ops: map[string]D{}, gets: map[string]int{}}
	b.call = f.call
	pluginPoll, pluginRecheck = 5*time.Millisecond, 0.05
	t.Cleanup(func() { pluginPoll, pluginRecheck = 2*time.Second, 10 })
	reportPlugins(p, testPlugin())
	return f
}

func testPlugin() []PluginInfo {
	return []PluginInfo{{Name: "backup", Version: "1.0.0", Contract: 1, Supported: true, Operations: []PluginOperation{
		{Name: "take", Description: "Take a backup of a machine.", Member: true,
			Params: json.RawMessage(`{"type":"object","properties":{"machine":{"type":"string"},"label":{"type":"string","maxLength":8}},"required":["machine"],"additionalProperties":false}`)},
		{Name: "prune", Description: "Prune old backups on the node.",
			Params: json.RawMessage(`{"type":"object","properties":{"keep":{"type":"integer","minimum":1}},"required":["keep"]}`)},
	}}}
}

func reportPlugins(p *Platform, plugins []PluginInfo) {
	p.Hub.Hello("carrel01", "s", AgentProtocol, "test", plugins)
	p.Hub.Heartbeat("carrel01", "s", uint64(time.Now().UnixNano()), nil)
}

func listedNames(t *testing.T, app *App, target string) []string {
	tools, _ := listedTools(t, app, target, nil)
	names := []string{}
	for _, tool := range tools {
		if strings.HasPrefix(str(tool["name"]), "backup_") {
			names = append(names, str(tool["name"]))
		}
	}
	return names
}

func mcpCall(t *testing.T, app *App, name string, args D) D {
	t.Helper()
	body := string(encoded(D{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": D{"name": name, "arguments": args}}))
	w := requestApp(app, "POST", "/mcp", body, map[string]string{"Authorization": "Bearer test", "Content-Type": "application/json", "Accept": "application/json, text/event-stream"})
	var result D
	must(json.Unmarshal(w.Body.Bytes(), &result))
	if result["error"] != nil {
		return D{"rpc_error": result["error"]}
	}
	return obj(obj(result["result"])["structuredContent"])
}

// The acceptance test of #661: a plugin a node reports becomes tools, runs
// as an operation with progress and a result, and its tools disappear when
// no node reports it.
func TestAPluginToolRegistersRunsAndDisappears(t *testing.T) {
	p, b := fixture(t)
	f := withPlugin(t, p, b)
	runQueue(p)
	seedMachine(p, "web", 10100)
	alice := NewApp(p, testVerifier{who: person("alice", false)})
	root := NewApp(p, testVerifier{who: person("root", true)})

	if got := listedNames(t, alice, "/mcp"); fmt.Sprint(got) != "[backup_take]" {
		t.Fatalf("member lists %v", got)
	}
	if got := listedNames(t, root, "/mcp"); fmt.Sprint(got) != "[backup_prune backup_take]" {
		t.Fatalf("admin lists %v", got)
	}
	if got := listedNames(t, alice, "/mcp?toolsets=core"); len(got) != 0 {
		t.Fatalf("toolsets=core lists %v", got)
	}
	if got := listedNames(t, alice, "/mcp?toolsets=plugins"); len(got) != 1 {
		t.Fatalf("toolsets=plugins lists %v", got)
	}
	if got := listedNames(t, alice, "/mcp/read-only"); len(got) != 0 {
		t.Fatalf("read-only lists %v", got)
	}

	r := mcpCall(t, alice, "backup_take", D{"machine": "web", "label": "nightly", "wait_seconds": 5})
	op := obj(r["operation"])
	if op["state"] != "succeeded" || obj(obj(op["result"])["result"])["snapshot"] == nil || p.Store.Get("operations", str(op["id"]))["progress"] != float64(100) {
		t.Fatalf("run: %s", encoded(r))
	}
	start := f.starts[0]
	params := obj(start["params"])
	if params["machine"] != "10100" || params["label"] != "nightly" || params["wait_seconds"] != nil || params["tenant"] != nil {
		t.Fatalf("the plugin got %v", params)
	}
	if str(start["idempotency_key"]) != str(op["id"])+"-1" || start["operation"] != "take" {
		t.Fatalf("start %v", start)
	}

	reportPlugins(p, nil)
	if got := listedNames(t, root, "/mcp"); len(got) != 0 {
		t.Fatalf("tools left after the node stopped reporting: %v", got)
	}
	if r := mcpCall(t, alice, "backup_take", D{"machine": "web"}); r["rpc_error"] == nil && boolean(r["ok"]) {
		t.Fatalf("a gone tool ran: %v", r)
	}
}

// Every gate holds before a call reaches a node: the schema, admin-only
// operations, another tenant's machine and the read-only endpoint.
func TestAPluginToolIsGatedLikeAnyTool(t *testing.T) {
	p, b := fixture(t)
	f := withPlugin(t, p, b)
	runQueue(p)
	m := seedMachine(p, "theirs", 10200)
	p.Store.Remove("machines", 10200)
	m["tenant_n"] = 2
	p.Store.Put("machines", 10200, 2, m)
	ctx := context.Background()
	alice := NewApp(p, testVerifier{who: person("alice", false)})
	for _, tc := range []struct {
		tool string
		args D
		code string
	}{
		{"backup_take", D{"machine": "web", "label": "much-too-long"}, "invalid"},
		{"backup_take", D{"machine": "web", "extra": 1}, "invalid"},
		{"backup_take", D{"label": "x"}, "invalid"},
		{"backup_prune", D{"keep": 2}, "forbidden"},
		{"backup_take", D{"machine": "theirs", "wait_seconds": 5}, "not_found"},
	} {
		if r := alice.Call(ctx, tc.tool, tc.args, person("alice", false)); str(failure(r)["code"]) != tc.code {
			t.Fatalf("%s %v: %s", tc.tool, tc.args, encoded(r))
		}
	}
	if len(f.starts) != 0 || len(p.Store.Objects("operations")) != 0 {
		t.Fatalf("a refused call was queued or reached the node: %v", f.starts)
	}
	readOnly := context.WithValue(ctx, selectionKey{}, selection{readOnly: true})
	if code := str(obj(p.Execute(readOnly, "backup_take", D{"machine": "web"}, person("alice", false))["error"])["code"]); code != "forbidden" {
		t.Fatalf("read-only endpoint: %s", code)
	}
	r := p.Execute(ctx, "backup_prune", D{"keep": 2, "wait_seconds": 5}, person("alice", true))
	if obj(r["operation"])["state"] != "succeeded" {
		t.Fatalf("admin: %s", encoded(r))
	}
}

// A plugin operation outlives a control plane restart: it is polled again
// with the same key, never started anew, and never marked succeeded without
// asking. One queued before the agents reconnect waits for them.
func TestAPluginOperationSurvivesARestart(t *testing.T) {
	p, b := fixture(t)
	f := withPlugin(t, p, b)
	seedMachine(p, "web", 10100)
	// Queued, not run: the worker is not started yet.
	r := member(p, "backup_take", D{"machine": "web", "wait_seconds": 0})
	id := str(obj(r["operation"])["id"])
	// The restart: no agent has reported yet.
	reportPlugins(p, nil)
	runQueue(p)
	awaitState(t, p, id, "waiting_for_plugin")
	reportPlugins(p, testPlugin())
	op := awaitState(t, p, id, "succeeded")
	if len(f.starts) != 1 || obj(op["plugin"])["key"] != id+"-1" {
		t.Fatalf("starts %v, op %s", f.starts, encoded(op))
	}

	// Cut off while the plugin runs: the record says so, and Recover asks
	// the plugin again by the same key.
	op = p.Store.Get("operations", id)
	op["state"], op["phase"] = "running", "waiting_for_guest"
	op["prepared_result"] = D{"plugin": "backup"}
	delete(op, "result")
	p.Store.Put("operations", id, 1, op)
	f.mu.Lock()
	f.ops[id+"-1"] = merge(f.ops[id+"-1"], D{"state": "running", "done": false})
	f.gets[id+"-1"] = 0
	f.mu.Unlock()
	p.Operations.Recover()
	awaitState(t, p, id, "succeeded")
	if len(f.starts) != 2 || f.starts[1]["idempotency_key"] != id+"-1" || f.gets[id+"-1"] < 2 {
		t.Fatalf("after restart: starts %v gets %v", f.starts, f.gets)
	}
}

// A plugin error maps to what the caller should do. operation_retry asks
// again under the same key while the run may still be going, and starts a
// new run only once the last one is known to have ended.
func TestAPluginErrorMapsAndRetriesUnderTheRightKey(t *testing.T) {
	p, b := fixture(t)
	f := withPlugin(t, p, b)
	runQueue(p)
	seedMachine(p, "web", 10100)
	set := func(fail, outcome string) {
		f.mu.Lock()
		f.fail, f.outcome = fail, outcome
		f.mu.Unlock()
	}
	set("invalid", "")
	op := obj(member(p, "backup_take", D{"machine": "web", "wait_seconds": 5})["operation"])
	if op["state"] != "failed" || obj(op["error"])["code"] != "invalid" || op["next_action"] != "revise_request" {
		t.Fatalf("invalid: %s", encoded(op))
	}
	// The start's answer is lost: the run may be going, so a retry asks
	// after the same key and starts nothing new.
	set("plugin_error", "")
	op = obj(member(p, "backup_take", D{"machine": "web", "label": "b", "wait_seconds": 5})["operation"])
	if obj(op["error"])["code"] != "plugin_failed" {
		t.Fatalf("plugin_error: %s", encoded(op))
	}
	id := str(op["id"])
	set("", "")
	member(p, "operation_retry", D{"id": id})
	awaitState(t, p, id, "succeeded")
	if last := f.starts[len(f.starts)-1]; last["idempotency_key"] != id+"-1" {
		t.Fatalf("retry after an unknown outcome used key %v", last["idempotency_key"])
	}
	// The plugin reports the run failed: it has ended, so a retry is a new run.
	set("", "failed")
	op = obj(member(p, "backup_take", D{"machine": "web", "label": "c", "wait_seconds": 5})["operation"])
	if obj(op["error"])["code"] != "plugin_failed" || !strings.Contains(str(obj(op["error"])["message"]), "disk full") {
		t.Fatalf("failed run: %s", encoded(op))
	}
	id = str(op["id"])
	set("", "")
	member(p, "operation_retry", D{"id": id})
	awaitState(t, p, id, "succeeded")
	if last := f.starts[len(f.starts)-1]; last["idempotency_key"] != id+"-2" {
		t.Fatalf("retry after a failed run used key %v", last["idempotency_key"])
	}
}

// A member operation runs only on a machine bound to the caller's tenant:
// a null machine is refused, whatever the schema allows.
func TestAMemberPluginOperationNeedsAMachine(t *testing.T) {
	p, b := fixture(t)
	f := withPlugin(t, p, b)
	runQueue(p)
	reportPlugins(p, []PluginInfo{{Name: "backup", Contract: 1, Supported: true, Operations: []PluginOperation{
		{Name: "take", Member: true, Params: json.RawMessage(`{"type":"object","properties":{"machine":{}},"required":["machine"]}`)}}}})
	for _, machine := range []any{nil, "", 7} {
		r := member(p, "backup_take", D{"machine": machine, "wait_seconds": 5})
		if code := str(failure(r)["code"]); code != "invalid" && code != "not_found" {
			t.Fatalf("machine %v: %s", machine, encoded(r))
		}
	}
	if len(f.starts) != 0 || len(p.Store.Objects("operations")) != 0 {
		t.Fatalf("a call without a bound machine was queued or reached the node: %v", f.starts)
	}
}

// The node that runs a call decides its access: a node that reports the
// operation admin-only does not run a member's call, even when another
// node reports it member.
func TestTheRunningNodeDecidesAccess(t *testing.T) {
	p, b := fixture(t)
	p.Config.Nodes = append(p.Config.Nodes, NodeConfig{Name: "carrel02", Target: "carrel-node-2"})
	f := withPlugin(t, p, b)
	pluginWaitForNode = 0.2
	t.Cleanup(func() { pluginWaitForNode = 300 })
	strict := testPlugin()
	strict[0].Operations[0].Member = false
	p.Hub.Hello("carrel02", "s2", AgentProtocol, "test", strict)
	p.Hub.Heartbeat("carrel02", "s2", 1, nil)
	runQueue(p)
	m := seedMachine(p, "far", 10300)
	m["node"] = "carrel02"
	p.Store.Put("machines", 10300, 1, m)
	if nodes := p.pluginTools()["backup_take"].Nodes; fmt.Sprint(nodes) != "[carrel01]" {
		t.Fatalf("nodes %v", nodes)
	}
	r := member(p, "backup_take", D{"machine": "far", "wait_seconds": 0})
	op := awaitState(t, p, str(obj(r["operation"])["id"]), "waiting_for_plugin")
	deadline := time.Now().Add(3 * time.Second)
	for !contains(terminal, op["state"]) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
		op = p.Store.Get("operations", str(op["id"]))
	}
	if op["state"] != "failed" || obj(op["error"])["code"] != "unsupported" || len(f.starts) != 0 {
		t.Fatalf("op %s, starts %v", encoded(op), f.starts)
	}
}

// A plugin cannot take a core tool's name, declare carrel's own arguments,
// or reach outside its schema with $ref; each is left out with the reason.
func TestABadPluginOperationIsLeftOutWithAReason(t *testing.T) {
	p, b := fixture(t)
	withPlugin(t, p, b)
	reportPlugins(p, []PluginInfo{{Name: "snapshot", Contract: 1, Supported: true, Operations: []PluginOperation{
		{Name: "create", Params: json.RawMessage(`{"type":"object"}`)},
		{Name: "steal", Params: json.RawMessage(`{"type":"object","properties":{"tenant":{"type":"string"}}}`)},
		{Name: "peek", Params: json.RawMessage(`{"type":"object","properties":{"x":{"$ref":"file:///etc/passwd"}}}`)},
		{Name: "loose", Member: true, Params: json.RawMessage(`{"type":"object","properties":{"vmid":{"type":"integer"}}}`)},
		{Name: "inspect", ReadOnly: true, Params: json.RawMessage(`{"type":"object"}`)},
	}}})
	cat := p.pluginCatalog()
	left := obj(cat["left_out"])
	for name, want := range map[string]string{"snapshot_create": "core tool", "snapshot_steal": `"tenant"`, "snapshot_peek": "may not refer to file", "snapshot_loose": `require a top-level "machine"`} {
		if !strings.Contains(str(left[name]), want) {
			t.Fatalf("%s: %q", name, left[name])
		}
	}
	if tools := dicts(cat["tools"]); len(tools) != 1 || tools[0]["tool"] != "snapshot_inspect" {
		t.Fatalf("tools %v", tools)
	}
	root := NewApp(p, testVerifier{who: person("root", true)})
	tools, _ := listedTools(t, root, "/mcp/read-only", nil)
	found := false
	for _, tool := range tools {
		found = found || tool["name"] == "snapshot_inspect"
	}
	if !found {
		t.Fatal("a read-only plugin tool is missing from the read-only endpoint")
	}
}
