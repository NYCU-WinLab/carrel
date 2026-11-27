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
	// inline, when set, is the reply to every read and dry run; failure,
	// when set, is merged into an operation that ends failed.
	inline, failure D
	// result, when set, is the result of every operation that succeeds.
	result D
	// forget: a start answers running and keeps nothing, as a plugin that
	// lost its state.
	forget bool
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
	// A read or a dry run answers done at once, and is not kept.
	if strings.HasPrefix(key, "inline-") {
		f.starts = append(f.starts, clone(r))
		if f.inline != nil {
			return clone(f.inline), nil
		}
		return D{"idempotency_key": key, "state": "succeeded", "done": true,
			"result": D{"items": []any{"a", "b"}, "dry": r["dry_run"], "vmid": obj(r["params"])["machine"]}}, nil
	}
	switch r["call"] {
	case "start":
		f.starts = append(f.starts, clone(r))
		if f.forget {
			return D{"idempotency_key": key, "state": "running", "done": false}, nil
		}
		if f.ops[key] == nil {
			f.ops[key] = D{"idempotency_key": key, "state": "running", "done": false, "progress": 10, "task": "UPID:test:" + key, "message": "copying"}
		}
	case "get":
		if f.ops[key] == nil {
			return nil, Failure{D{"ok": false, "error": D{"code": "backend_unavailable", "backend_code": "not_found"}}}
		}
		if f.gets[key]++; f.gets[key] >= 2 {
			if f.outcome != "" {
				f.ops[key] = merge(f.ops[key], D{"state": f.outcome, "done": true, "error": "disk full"}, f.failure)
			} else {
				result := D{"snapshot": "s-" + key}
				if f.result != nil {
					result = f.result
				}
				f.ops[key] = merge(f.ops[key], D{"state": "succeeded", "done": true, "progress": 100, "result": result})
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
		{Name: "take", Description: "Take a backup of a machine.", Member: true, DryRun: true,
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
	if op["state"] != "succeeded" || obj(op["result"])["snapshot"] == nil || p.Store.Get("operations", str(op["id"]))["progress"] != float64(100) {
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
	// Cut off before the run was recorded as succeeded.
	delete(obj(op["plugin"]), "succeeded")
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
	reportPlugins(p, []PluginInfo{{Name: "port", Contract: 1, Supported: true, Operations: []PluginOperation{
		{Name: "open", Params: json.RawMessage(`{"type":"object"}`)},
		{Name: "steal", Params: json.RawMessage(`{"type":"object","properties":{"tenant":{"type":"string"}}}`)},
		{Name: "peek", Params: json.RawMessage(`{"type":"object","properties":{"x":{"$ref":"file:///etc/passwd"}}}`)},
		{Name: "loose", Member: true, Params: json.RawMessage(`{"type":"object","properties":{"vmid":{"type":"integer"}}}`)},
		{Name: "inspect", ReadOnly: true, Params: json.RawMessage(`{"type":"object"}`)},
	}}})
	cat := p.pluginCatalog()
	left := obj(cat["left_out"])
	for name, want := range map[string]string{"port_open": "core tool", "port_steal": `"tenant"`, "port_peek": "may not refer to file", "port_loose": `require a top-level "machine"`} {
		if !strings.Contains(str(left[name]), want) {
			t.Fatalf("%s: %q", name, left[name])
		}
	}
	if tools := dicts(cat["tools"]); len(tools) != 1 || tools[0]["tool"] != "port_inspect" {
		t.Fatalf("tools %v", tools)
	}
	root := NewApp(p, testVerifier{who: person("root", true)})
	tools, _ := listedTools(t, root, "/mcp/read-only", nil)
	found := false
	for _, tool := range tools {
		found = found || tool["name"] == "port_inspect"
	}
	if !found {
		t.Fatal("a read-only plugin tool is missing from the read-only endpoint")
	}
}

// A member cannot cancel an admin-only plugin operation queued in their
// tenant, as with a core admin tool.
func TestAMemberCannotCancelAnAdminPluginOperation(t *testing.T) {
	p, b := fixture(t)
	withPlugin(t, p, b)
	reportPlugins(p, nil)
	runQueue(p)
	// Registered while no node reports it, then queued while it waits.
	reportPlugins(p, testPlugin())
	r := p.Execute(context.Background(), "backup_prune", D{"keep": 2, "wait_seconds": 0}, person("alice", true))
	id := str(obj(r["operation"])["id"])
	reportPlugins(p, nil)
	if code := str(failure(member(p, "operation_cancel", D{"id": id}))["code"]); code != "forbidden" {
		t.Fatalf("member cancel: %s", code)
	}
	if r := p.Execute(context.Background(), "operation_cancel", D{"id": id}, person("alice", true)); !boolean(r["ok"]) {
		t.Fatalf("admin cancel: %s", encoded(r))
	}
}

// A start whose answer is lost may have begun the run. When the plugin then
// refuses the same key, as while its node cannot run it, the run's fate is
// still unknown: a retry asks after the same key and the work runs once.
func TestARefusalAfterALostStartKeepsTheKey(t *testing.T) {
	p, b := fixture(t)
	f := withPlugin(t, p, b)
	pluginPatience = time.Hour
	t.Cleanup(func() { pluginPatience = 10 * time.Minute })
	runQueue(p)
	seedMachine(p, "web", 10100)
	var calls int
	b.call = func(r D, target string) (any, error) {
		if r["op"] == "plugin" && r["call"] == "start" {
			f.mu.Lock()
			calls++
			n := calls
			f.mu.Unlock()
			switch n {
			case 1:
				// The plugin starts the run, and the answer is lost.
				f.call(r, target)
				return nil, Failure{D{"ok": false, "error": D{"code": "backend_unavailable", "backend_code": "plugin_unavailable"}}}
			case 2:
				return nil, Failure{D{"ok": false, "error": D{"code": "backend_unavailable", "backend_code": "plugin_refused"}}}
			}
		}
		return f.call(r, target)
	}
	op := obj(member(p, "backup_take", D{"machine": "web", "wait_seconds": 5})["operation"])
	if obj(op["error"])["code"] != "unsupported" {
		t.Fatalf("refused: %s", encoded(op))
	}
	id := str(op["id"])
	member(p, "operation_retry", D{"id": id})
	awaitState(t, p, id, "succeeded")
	keys := map[any]bool{}
	for _, s := range f.starts {
		keys[s["idempotency_key"]] = true
	}
	if len(keys) != 1 || !keys[id+"-1"] {
		t.Fatalf("the work ran under %v", keys)
	}
}

// The HTTP routes serve the same plugin tools as /mcp, with the same gates,
// and a status that matches the error.
func TestPluginToolsOverHTTP(t *testing.T) {
	p, b := fixture(t)
	withPlugin(t, p, b)
	runQueue(p)
	seedMachine(p, "web", 10100)
	alice := NewApp(p, testVerifier{who: person("alice", false)})
	headers := map[string]string{"Authorization": "Bearer test", "Content-Type": "application/json"}
	do := func(method, path, body string, h map[string]string) (int, D) {
		w := requestApp(alice, method, path, body, h)
		var v D
		_ = json.Unmarshal(w.Body.Bytes(), &v)
		return w.Code, v
	}
	code, v := do("GET", "/plugins/v1/tools", "", headers)
	if tools := dicts(v["tools"]); code != 200 || len(tools) != 1 || tools[0]["name"] != "backup_take" || obj(tools[0]["input_schema"])["type"] != "object" {
		t.Fatalf("list: %d %v", code, v)
	}
	code, v = do("POST", "/plugins/v1/tools/backup_take", `{"machine":"web","idempotency_key":"http-call-1","wait_seconds":5}`, headers)
	if code != 200 || obj(v["operation"])["state"] != "succeeded" {
		t.Fatalf("call: %d %v", code, v)
	}
	// The same key and arguments return the same operation: that is the poll.
	_, again := do("POST", "/plugins/v1/tools/backup_take", `{"machine":"web","idempotency_key":"http-call-1","wait_seconds":0}`, headers)
	if obj(again["operation"])["id"] != obj(v["operation"])["id"] {
		t.Fatalf("poll: %v", again)
	}
	for _, tc := range []struct {
		path, body string
		h          map[string]string
		status     int
	}{
		{"/plugins/v1/tools/backup_prune", `{"keep":1,"idempotency_key":"http-call-2"}`, headers, 403},
		{"/plugins/v1/tools/backup_take", `{"machine":"web","label":"much-too-long","idempotency_key":"http-call-3"}`, headers, 400},
		{"/plugins/v1/tools/backup_take", `[1]`, headers, 400},
		{"/plugins/v1/tools/backup_take", `{"machine":"web","idempotency_key":"http-call-4"} junk`, headers, 400},
		{"/plugins/v1/tools/backup_take", `{"machine":"web"}`, headers, 400},
		{"/plugins/v1/tools/backup_take", `null`, headers, 400},
		{"/plugins/v1/tools/machine_create", `{"name":"x"}`, headers, 404},
		{"/plugins/v1/tools/backup_gone", `{}`, headers, 404},
		{"/plugins/v1/tools/backup_take", `{"machine":"web"}`, map[string]string{"Content-Type": "application/json"}, 401},
	} {
		if code, v := do("POST", tc.path, tc.body, tc.h); code != tc.status {
			t.Fatalf("%s %s: %d %v", tc.path, tc.body, code, v)
		}
	}
	if w := requestApp(alice, "POST", "/plugins/v1/tools/backup_take", "{}", map[string]string{}); !strings.Contains(w.Header().Get("WWW-Authenticate"), "resource_metadata") {
		t.Fatalf("401 without a sign-in hint: %v", w.Header())
	}
	if len(p.Store.Objects("operations")) != 1 {
		t.Fatalf("a refused request queued work: %d operations", len(p.Store.Objects("operations")))
	}
}

func auditCount(t *testing.T, p *Platform, tool, outcome string) int {
	t.Helper()
	var n int
	must(p.Store.DB.QueryRow("SELECT count(*) FROM audit WHERE tool=? AND outcome=?", tool, outcome).Scan(&n))
	return n
}

// readPlugin adds a read_only member operation listed under machines and a
// destructive admin one to the test plugin.
func readPlugin() []PluginInfo {
	pl := testPlugin()
	pl[0].Operations = append(pl[0].Operations,
		PluginOperation{Name: "list", Member: true, ReadOnly: true, Toolset: "machines",
			Params: json.RawMessage(`{"type":"object","properties":{"machine":{"type":"string"}},"required":["machine"]}`)},
		PluginOperation{Name: "wipe", Destructive: true, Idempotent: true, Params: json.RawMessage(`{"type":"object"}`)},
		PluginOperation{Name: "odd", Toolset: "no-such-set", Params: json.RawMessage(`{"type":"object"}`)})
	return pl
}

// A read_only operation answers at once, as a core read: no operation, an
// audit row, the result's keys at the top, and no idempotency key over HTTP.
func TestAPluginReadAnswersAtOnce(t *testing.T) {
	p, b := fixture(t)
	f := withPlugin(t, p, b)
	reportPlugins(p, readPlugin())
	runQueue(p)
	seedMachine(p, "web", 10100)
	alice := NewApp(p, testVerifier{who: person("alice", false)})
	before := len(p.Store.Objects("operations", 0))

	r := mcpCall(t, alice, "backup_list", D{"machine": "web"})
	if r["ok"] != true || fmt.Sprint(r["items"]) != "[a b]" || r["vmid"] != "10100" || r["operation"] != nil {
		t.Fatalf("read: %s", encoded(r))
	}
	if n := len(p.Store.Objects("operations", 0)); n != before {
		t.Fatalf("a read queued an operation: %d to %d", before, n)
	}
	if auditCount(t, p, "backup_list", "ok") != 1 {
		t.Fatal("a read logs one ok audit row")
	}
	if got := listedNames(t, alice, "/mcp/read-only"); fmt.Sprint(got) != "[backup_list]" {
		t.Fatalf("read-only lists %v", got)
	}
	w := requestApp(alice, "POST", "/plugins/v1/tools/backup_list", `{"machine":"web"}`, map[string]string{"Authorization": "Bearer test", "Content-Type": "application/json"})
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"items"`) {
		t.Fatalf("HTTP read: %d %s", w.Code, w.Body.String())
	}

	// A plugin that does not answer a read at once fails it.
	f.inline = D{"state": "running", "done": false}
	if r := mcpCall(t, alice, "backup_list", D{"machine": "web"}); obj(r["error"])["code"] != "plugin_failed" {
		t.Fatalf("slow read: %s", encoded(r))
	}
	f.inline = nil
	// Another tenant's machine, or none, is refused before any node is asked.
	bob := NewApp(p, testVerifier{who: person("bob", false)})
	starts := len(f.starts)
	for _, call := range []D{{"machine": "web"}, {"machine": "web", "dry_run": true}} {
		tool := map[bool]string{true: "backup_take", false: "backup_list"}[call["dry_run"] == true]
		if r := mcpCall(t, bob, tool, call); obj(r["error"])["code"] != "not_found" || len(f.starts) != starts {
			t.Fatalf("bob on alice's machine: %s", encoded(r))
		}
	}
	if r := mcpCall(t, alice, "backup_list", D{"machine": "nobody"}); obj(r["error"])["code"] != "not_found" || len(f.starts) != starts {
		t.Fatalf("no such machine: %s", encoded(r))
	}
}

// A dry run reaches the plugin with dry_run set and answers at once.
func TestAPluginDryRunReachesThePlugin(t *testing.T) {
	p, b := fixture(t)
	f := withPlugin(t, p, b)
	runQueue(p)
	seedMachine(p, "web", 10100)
	alice := NewApp(p, testVerifier{who: person("alice", false)})
	r := mcpCall(t, alice, "backup_take", D{"machine": "web", "dry_run": true})
	if r["ok"] != true || r["dry"] != true || r["dry_run"] != true || r["reserved"] != false || r["operation"] != nil {
		t.Fatalf("dry run: %s", encoded(r))
	}
	if last := f.starts[len(f.starts)-1]; last["dry_run"] != true || obj(last["params"])["dry_run"] != nil {
		t.Fatalf("the plugin got %s", encoded(last))
	}
	if auditCount(t, p, "backup_take", "ok") != 1 {
		t.Fatal("a dry run logs one ok audit row")
	}

	// An operation whose plugin does not say it honours dry_run is planned
	// by carrel: the plugin, which would run it, is never asked.
	admin := NewApp(p, testVerifier{who: person("alice", true)})
	starts := len(f.starts)
	r = mcpCall(t, admin, "backup_prune", D{"keep": 2, "dry_run": true})
	if r["ok"] != true || r["state"] != "planned" || len(f.starts) != starts {
		t.Fatalf("dry run without plugin support: %s, %d starts", encoded(r), len(f.starts)-starts)
	}
}

// A plugin's result cannot set carrel's keys, inline or as an operation.
func TestAPluginResultCannotClaimCarrelKeys(t *testing.T) {
	p, b := fixture(t)
	f := withPlugin(t, p, b)
	runQueue(p)
	seedMachine(p, "web", 10100)
	alice := NewApp(p, testVerifier{who: person("alice", false)})
	forged := D{"ok": false, "error": D{"code": "forbidden", "message": "forged"}, "operation": "x", "state": "failed", "kept": 1,
		"suggestions": []any{"x"}, "next_action": "x"}
	f.inline = D{"state": "succeeded", "done": true, "result": forged}
	r := mcpCall(t, alice, "backup_take", D{"machine": "web", "dry_run": true})
	if r["ok"] != true || r["error"] != nil || r["operation"] != nil || r["suggestions"] != nil || r["next_action"] != nil || r["kept"] != float64(1) {
		t.Fatalf("inline: %s", encoded(r))
	}
	f.inline, f.result = nil, forged
	op := obj(mcpCall(t, alice, "backup_take", D{"machine": "web", "wait_seconds": 5})["operation"])
	res := obj(op["result"])
	if op["state"] != "succeeded" || res["ok"] != true || res["error"] != nil || res["kept"] != float64(1) {
		t.Fatalf("operation: %s", encoded(op))
	}
}

// A plugin fails with a carrel error code, its message and details; an
// unknown code is plugin_failed, and details cannot replace code or message.
func TestAPluginFailsWithACarrelErrorCode(t *testing.T) {
	p, b := fixture(t)
	f := withPlugin(t, p, b)
	runQueue(p)
	seedMachine(p, "web", 10100)
	alice := NewApp(p, testVerifier{who: person("alice", false)})

	f.inline = D{"state": "failed", "done": true, "error": "Snapshot not found", "error_code": "not_found",
		"error_details": D{"recovery": "revise_request", "code": "internal", "message": "x", "Bad-Key": 1}}
	e := obj(mcpCall(t, alice, "backup_take", D{"machine": "web", "dry_run": true})["error"])
	if e["code"] != "not_found" || e["message"] != "Snapshot not found" || e["recovery"] != "revise_request" || e["Bad-Key"] != nil {
		t.Fatalf("dry run error: %s", encoded(e))
	}
	f.inline = nil

	f.outcome, f.failure = "failed", D{"error": "Snapshot exists", "error_code": "conflict"}
	op := obj(mcpCall(t, alice, "backup_take", D{"machine": "web", "wait_seconds": 5})["operation"])
	if op["state"] != "failed" || obj(op["error"])["code"] != "conflict" || obj(op["error"])["message"] != "Snapshot exists" {
		t.Fatalf("operation error: %s", encoded(op))
	}
	f.failure = D{"error": "boom", "error_code": "internal"}
	op = obj(mcpCall(t, alice, "backup_take", D{"machine": "web", "label": "b", "wait_seconds": 5})["operation"])
	if obj(op["error"])["code"] != "plugin_failed" {
		t.Fatalf("unknown code: %s", encoded(op))
	}
}

// A plugin tool is listed under the toolset it names and carries its hints;
// an unknown toolset leaves the operation out.
func TestAPluginToolNamesItsToolsetAndHints(t *testing.T) {
	p, b := fixture(t)
	withPlugin(t, p, b)
	reportPlugins(p, readPlugin())
	root := NewApp(p, testVerifier{who: person("root", true)})
	if got := listedNames(t, root, "/mcp?toolsets=machines"); fmt.Sprint(got) != "[backup_list]" {
		t.Fatalf("toolsets=machines lists %v", got)
	}
	tools, _ := listedTools(t, root, "/mcp", nil)
	for _, tool := range tools {
		a := obj(tool["annotations"])
		switch tool["name"] {
		case "backup_wipe":
			if a["destructiveHint"] != true || a["idempotentHint"] != true {
				t.Fatalf("wipe hints %v", a)
			}
		case "backup_take":
			if a["destructiveHint"] != false {
				t.Fatalf("take hints %v", a)
			}
		case "backup_odd":
			t.Fatal("an unknown toolset is listed")
		}
	}
	if left := fmt.Sprint(p.pluginCatalog()); !strings.Contains(left, "toolset no-such-set") {
		t.Fatalf("left out: %s", left)
	}
}
