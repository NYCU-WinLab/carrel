package carrel

// Plugin tools (#564, #661): every operation a node's plugin declares is a
// tool named <plugin>_<operation>, listed, gated and run as an async tool
// like any other, with no core change per plugin. The registry is what the
// agents report now (Hub.Plugins), so a tool appears when a node reports
// its plugin and disappears when no node does.
//
// Access: an operation is admin-only unless the plugin marks it member, and
// a member operation must require a top-level "machine": the control plane
// cannot tell what any other parameter points at, but it binds a machine to
// the caller's tenant (BindMachine) and hands the plugin its VMID.

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// pluginEnvelope are the arguments every async tool takes from carrel; a
// plugin's schema may not declare them, and the plugin never sees them.
var pluginEnvelope = []string{"tenant", "idempotency_key", "dry_run", "detail", "wait_seconds"}

// pluginWaitForNode is how long a queued plugin operation waits for a node
// to report its plugin, as after a control plane restart, before it fails.
// pluginPoll is how often a running plugin operation is asked how it is;
// pluginPatience is how long a plugin may stay unreachable before the
// operation fails. Tests shorten them.
var (
	pluginWaitForNode = 300.0
	pluginPoll        = 2 * time.Second
	pluginPatience    = 10 * time.Minute
	// pluginRecheck is how often, in seconds, a queued operation looks for
	// a node that reports its plugin.
	pluginRecheck = 10.0
)

type pluginTool struct {
	Name, Plugin, Operation, Description string
	// Schema is the plugin's own schema, as the first node in the
	// configuration reports it; a call is checked again against the schema
	// of the node that runs it.
	Schema           json.RawMessage
	Member, ReadOnly bool
	// Hints for clients and the toolset it is also listed under.
	Destructive, Idempotent bool
	Toolset                 string
	// The object the operation acts on, and its declaration as the first
	// node reports it (pluginObjectSpec).
	ObjectKind, ObjectEffect, Spec string
	// Nodes report the plugin supported with this operation, in
	// configuration order.
	Nodes []string
}

func pluginToolName(plugin, operation string) string { return plugin + "_" + operation }

var coreTools = func() map[string]bool {
	out := map[string]bool{}
	for _, d := range dicts(Contract["tools"]) {
		out[str(d["name"])] = true
	}
	return out
}()

// pluginSchemaProblem says why an operation cannot be a tool, or "".
func pluginSchemaProblem(op PluginOperation) string {
	var s map[string]any
	if json.Unmarshal(op.Params, &s) != nil || s["type"] != "object" {
		return `its schema must have type "object"`
	}
	props, _ := s["properties"].(map[string]any)
	for _, k := range pluginEnvelope {
		if _, ok := props[k]; ok {
			return fmt.Sprintf("its schema declares %q, which every tool takes from carrel", k)
		}
	}
	if op.Member {
		required, _ := s["required"].([]any)
		if _, ok := props["machine"]; !ok || !contains(required, "machine") {
			return `a member operation must require a top-level "machine"`
		}
	}
	if _, err := pluginSchema(op.Params); err != nil {
		return "its schema does not compile: " + err.Error()
	}
	return ""
}

// pluginRegistry is every plugin tool some node reports supported now, by
// name, and why each other reported operation is not a tool.
func (p *Platform) pluginRegistry() (map[string]*pluginTool, map[string]string) {
	tools, left := map[string]*pluginTool{}, map[string]string{}
	now := time.Now()
	for _, n := range p.Config.Nodes {
		for _, pl := range p.Hub.Plugins(n.Name, now) {
			if !pl.Supported {
				continue
			}
			for _, op := range pl.Operations {
				name := pluginToolName(pl.Name, op.Name)
				if t := tools[name]; t != nil {
					// A node that grants other access, or declares the
					// object otherwise, is not one this tool runs on, as
					// during a rolling update of the plugin.
					if op.Member == t.Member && op.ReadOnly == t.ReadOnly && pluginObjectSpec(pl, op) == t.Spec {
						t.Nodes = append(t.Nodes, n.Name)
					}
					continue
				}
				if coreTools[name] {
					left[name] = "a core tool has this name"
				} else if problem := pluginSchemaProblem(op); problem != "" {
					left[name] = problem
				} else if problem := pluginObjectProblem(pl, op); problem != "" {
					left[name] = problem
				} else if problem := pluginPowerProblem(op); problem != "" {
					left[name] = problem
				} else if op.Toolset != "" && obj(Contract["toolsets"])[op.Toolset] == nil {
					left[name] = fmt.Sprintf("toolset %s is not one of the tool contract", op.Toolset)
				} else {
					delete(left, name)
					tools[name] = &pluginTool{Name: name, Plugin: pl.Name, Operation: op.Name, Description: op.Description,
						Schema: op.Params, Member: op.Member, ReadOnly: op.ReadOnly, Destructive: op.Destructive,
						Idempotent: op.Idempotent, Toolset: op.Toolset, ObjectKind: op.ObjectKind, ObjectEffect: op.ObjectEffect,
						Spec: pluginObjectSpec(pl, op), Nodes: []string{n.Name}}
				}
			}
		}
	}
	return tools, left
}

func (p *Platform) pluginTools() map[string]*pluginTool {
	tools, _ := p.pluginRegistry()
	return tools
}

// pluginOperation is the operation as one node reports it.
func (p *Platform) pluginOperation(node, plugin, operation string) (PluginOperation, bool) {
	for _, pl := range p.Hub.Plugins(node, time.Now()) {
		if pl.Name != plugin || !pl.Supported {
			continue
		}
		for _, op := range pl.Operations {
			if op.Name == operation {
				return op, true
			}
		}
	}
	return PluginOperation{}, false
}

// pluginCatalog is what catalog_get shows of plugins: the tools, and the
// reported operations left out with the reason.
func (p *Platform) pluginCatalog() D {
	tools, left := p.pluginRegistry()
	list := []D{}
	for _, t := range tools {
		access := "admin"
		if t.Member {
			access = "member"
		}
		entry := D{"tool": t.Name, "plugin": t.Plugin, "operation": t.Operation, "access": access, "read_only": t.ReadOnly, "nodes": t.Nodes}
		if t.ObjectKind != "" {
			entry["object"] = D{"kind": t.ObjectKind, "effect": t.ObjectEffect}
		}
		list = append(list, entry)
	}
	sort.Slice(list, func(i, j int) bool { return str(list[i]["tool"]) < str(list[j]["tool"]) })
	out := D{"tools": list}
	if len(left) > 0 {
		reasons := D{}
		for k, v := range left {
			reasons[k] = v
		}
		out["left_out"] = reasons
	}
	return out
}

// envelopeProperties are the core definitions of the envelope arguments.
var envelopeProperties = func() D {
	for _, d := range dicts(Contract["tools"]) {
		if d["name"] == "machine_freeze" {
			return pick(obj(obj(d["inputSchema"])["properties"]), pluginEnvelope...)
		}
	}
	panic("machine_freeze is not in the contract")
}()

// pluginInputSchema is the tool's schema: the plugin's with the envelope.
func pluginInputSchema(schema json.RawMessage) D {
	var s D
	must(json.Unmarshal(schema, &s))
	s["properties"] = merge(obj(s["properties"]), clone(envelopeProperties))
	return s
}

// A plugin schema is compiled without a loader: a $ref outside the schema
// would make the control plane read a file or a URL a plugin chose.
type denyLoader struct{}

func (denyLoader) Load(url string) (any, error) {
	return nil, fmt.Errorf("a plugin schema may not refer to %s", url)
}

var pluginSchemaCache = struct {
	sync.Mutex
	m map[string]*jsonschema.Schema
}{m: map[string]*jsonschema.Schema{}}

// pluginSchema compiles a plugin's schema with the envelope added, once per
// distinct schema.
func pluginSchema(schema json.RawMessage) (*jsonschema.Schema, error) {
	key := digest(string(schema))
	pluginSchemaCache.Lock()
	defer pluginSchemaCache.Unlock()
	if s := pluginSchemaCache.m[key]; s != nil {
		return s, nil
	}
	doc, err := jsonschema.UnmarshalJSON(strings.NewReader(string(encoded(pluginInputSchema(schema)))))
	if err != nil {
		return nil, err
	}
	c := jsonschema.NewCompiler()
	c.UseLoader(denyLoader{})
	url := "https://carrel.invalid/plugin/" + key
	if err := c.AddResource(url, doc); err != nil {
		return nil, err
	}
	s, err := c.Compile(url)
	if err != nil {
		return nil, err
	}
	if len(pluginSchemaCache.m) >= 1024 {
		pluginSchemaCache.m = map[string]*jsonschema.Schema{}
	}
	pluginSchemaCache.m[key] = s
	return s, nil
}

func checkPluginArgs(schema json.RawMessage, a D) {
	s, err := pluginSchema(schema)
	if err != nil {
		fail("unsupported", "The plugin's schema does not compile", D{"recovery": "retry_infrastructure"})
	}
	if err := s.Validate(map[string]any(clone(a))); err != nil {
		fail("invalid", "Invalid tool arguments", D{"details": err.Error()})
	}
}

// submitPlugin queues a call of a plugin tool as an operation.
func (e *Execution) submitPlugin(pt *pluginTool, a, w D) D {
	p := e.P
	if !pt.Member && !boolean(w["admin"]) {
		fail("forbidden", "winlab-admin membership required")
	}
	sel, _ := e.Ctx.Value(selectionKey{}).(selection)
	if sel.readOnly && !pt.ReadOnly {
		fail("forbidden", "This tool changes state; call it on /mcp")
	}
	checkPluginArgs(pt.Schema, a)
	if pt.Member && str(a["machine"]) == "" {
		fail("invalid", "machine must name one of your machines")
	}
	if !sel.readOnly {
		e.Register(w, str(a["tenant"]), false)
	}
	t := e.Tenant(w, str(a["tenant"]))
	if t["status"] != "active" {
		fail("forbidden", "Tenant is suspended")
	}
	// Refused here, a call on another tenant's machine queues nothing.
	if a["machine"] != nil {
		e.Machine(t, a["machine"])
	}
	if pt.ReadOnly || boolean(a["dry_run"]) {
		return e.pluginInline(pt, a, w, t)
	}
	p.writer.Lock()
	var op D
	err := attempt(func() {
		op = p.Operations.Submit(pt.Name, a, w, t, D{"plugin": D{"plugin": pt.Plugin, "operation": pt.Operation, "caller_read_only": sel.readOnly, "admin_only": !pt.Member}})
		e.S.Log(str(w["sub"]), t["n"], pt.Name, a, "queued")
	})
	p.writer.Unlock()
	if err != nil {
		panic(err)
	}
	return D{"ok": true, "operation": p.Operations.Wait(e.Ctx, t, str(op["id"]), intAt(a, "wait_seconds", 55))}
}

// pluginErrorCodes are the codes a plugin may fail an operation with; the
// caller acts on them as on a core tool's.
var pluginErrorCodes = map[string]bool{"invalid": true, "conflict": true, "not_found": true,
	"quota_exceeded": true, "capacity_exhausted": true, "unsupported": true}

var pluginDetailKey = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

// pluginFailure fails a plugin operation that ended in state failed. A
// plugin that names one of pluginErrorCodes is passed through with its own
// message and details; any other failure is plugin_failed.
func pluginFailure(name string, r D) {
	message := textAt(r, "error", "")
	if len(message) > MaxPluginText {
		message = strings.ToValidUTF8(message[:MaxPluginText], "")
	}
	code := str(r["error_code"])
	if !pluginErrorCodes[code] {
		fail("plugin_failed", fmt.Sprintf("Plugin %s failed: %s", name, message), D{"recovery": "retry_infrastructure"})
	}
	if message == "" {
		message = fmt.Sprintf("Plugin %s refused the operation", name)
	}
	details := D{}
	for k, v := range obj(r["error_details"]) {
		if k != "code" && k != "message" && pluginDetailKey.MatchString(k) {
			details[k] = v
		}
	}
	fail(code, message, details)
}

// pluginRefusal fails a call the agent or the plugin refused before it ran.
func pluginRefusal(code, name, node string) {
	switch code {
	case "invalid":
		fail("invalid", fmt.Sprintf("Plugin %s refused the arguments", name), D{"recovery": "revise_request"})
	case "conflict":
		fail("conflict", fmt.Sprintf("Plugin %s refused the operation in its current state", name), D{"recovery": "revise_request"})
	case "plugin_refused":
		fail("unsupported", fmt.Sprintf("Plugin %s does not run on node %s now", name, node), D{"recovery": "retry_infrastructure"})
	case "not_found", "plugin_error":
		fail("plugin_failed", fmt.Sprintf("Plugin %s failed", name), D{"recovery": "retry_infrastructure"})
	}
}

// pluginReserved are carrel's keys in an answer, which a plugin's result
// never sets: a result cannot claim a failure, or an error code, of carrel's.
var pluginReserved = []string{"ok", "error", "operation", "dry_run", "reserved", "resource_changes", "state",
	"plugin", "node", "task", "suggestions", "next_action", "object", "quota_after", "machine", "power_state",
	"power_state_restored", "downtime_expected"}

// pluginResult is what a plugin's result adds to carrel's answer: the keys
// of a JSON object but carrel's own, or the value under "result".
func pluginResult(v any) D {
	if m, ok := v.(map[string]any); ok {
		return without(D(m), pluginReserved...)
	}
	if v == nil {
		return D{}
	}
	return D{"result": v}
}

// pluginInline answers a read_only operation or a dry run at once on one
// node, as a core read does: no operation, no queue, an audit row.
func (e *Execution) pluginInline(pt *pluginTool, a, w, t D) D {
	node := ""
	var vmid any
	var m D
	if a["machine"] != nil {
		m = e.Machine(t, a["machine"])
		vmid = m["vmid"]
		if n := e.P.nodeOf(m).Name; contains(pt.Nodes, n) {
			node = n
		}
	} else {
		for _, n := range pt.Nodes {
			if !e.drained(n) {
				node = n
				break
			}
		}
	}
	if node == "" {
		fail("unsupported", fmt.Sprintf("No node that could run it reports plugin %s with operation %s", pt.Plugin, pt.Operation),
			D{"recovery": "retry_infrastructure"})
	}
	op, ok := e.P.pluginOperation(node, pt.Plugin, pt.Operation)
	// The node that runs it decides: one that no longer reports it, or now
	// reports it as a change, does not answer it inline.
	if !ok || pt.ReadOnly && !op.ReadOnly && !boolean(a["dry_run"]) {
		fail("unsupported", fmt.Sprintf("Node %s no longer reports plugin %s with operation %s as it was listed", node, pt.Plugin, pt.Operation),
			D{"recovery": "retry_infrastructure"})
	}
	sel, _ := e.Ctx.Value(selectionKey{}).(selection)
	if !op.Member && !boolean(w["admin"]) {
		fail("forbidden", "winlab-admin membership required")
	}
	if sel.readOnly && !op.ReadOnly {
		fail("forbidden", "This tool changes state; call it on /mcp")
	}
	if op.Member && vmid == nil {
		fail("invalid", "machine must name one of your machines")
	}
	checkPluginArgs(op.Params, a)
	params := without(a, pluginEnvelope...)
	if vmid != nil {
		params["machine"] = str(vmid)
	}
	dry := boolean(a["dry_run"])
	// An object operation is checked against the record, the quota and the
	// node first, as a core dry run is; nothing is reserved.
	planned := D{}
	job := D{"op": "plugin", "plugin": pt.Plugin, "operation": pt.Operation, "call": "start",
		"idempotency_key": "inline-" + randomID(), "params": params, "dry_run": dry}
	if m != nil {
		job["machine"] = pluginMachineFacts(m)
	}
	if pl, ok := e.P.pluginInfo(node, pt.Plugin); ok {
		job["operation_spec"] = PluginOperationSpec(pl, op)
	}
	if op.Stopped {
		if pluginPowerProblem(op) != "" {
			fail("unsupported", fmt.Sprintf("Node %s no longer reports plugin %s with operation %s as it was listed", node, pt.Plugin, pt.Operation),
				D{"recovery": "retry_infrastructure"})
		}
		planned["downtime_expected"], planned["power_state"] = true, "restored_to_previous"
	}
	if op.ObjectKind != "" {
		pl, _ := e.P.pluginInfo(node, pt.Plugin)
		if pluginObjectProblem(pl, op) != "" || m == nil {
			fail("unsupported", fmt.Sprintf("Node %s no longer reports plugin %s with operation %s as it was listed", node, pt.Plugin, pt.Operation),
				D{"recovery": "retry_infrastructure"})
		}
		id, row, charge := e.planPluginObject(pl, op, a, t, m)
		// A read of an object names the record and the declaration, as a
		// start does; a dry run reserves nothing.
		job["reservation"] = id
		object := D{"kind": op.ObjectKind, "name": a[op.ObjectParam], "state": "planned"}
		if row != nil {
			object["state"] = row.State
		}
		if charge != nil {
			object["charge"] = charge
			planned["quota_after"] = e.Quota(t, charge)
		}
		planned["object"] = object
	}
	// A plugin that does not say it honours dry_run is never sent one: it
	// would run the operation. carrel plans it without the plugin.
	if dry && !op.DryRun {
		e.S.Log(str(w["sub"]), t["n"], pt.Name, a, "ok")
		return merge(planned, D{"ok": true, "dry_run": true, "state": "planned", "plugin": pt.Plugin, "operation": pt.Operation,
			"node": node, "reserved": false, "resource_changes": false})
	}
	v, err := e.P.Backend.Call(e.Ctx, job, e.P.nodeTarget(node))
	if err != nil {
		pluginRefusal(str(obj(failureResult(err)["error"])["backend_code"]), pt.Plugin, node)
		fail("backend_unavailable", fmt.Sprintf("Plugin %s on node %s did not answer", pt.Plugin, node), D{"recovery": "retry_infrastructure"})
	}
	r := obj(v)
	if !boolean(r["done"]) {
		fail("plugin_failed", fmt.Sprintf("Plugin %s did not answer %s at once", pt.Plugin, map[bool]string{true: "a dry run", false: "a read"}[dry]),
			D{"recovery": "retry_infrastructure"})
	}
	switch r["state"] {
	case "succeeded":
	case "cancelled":
		fail("cancelled", fmt.Sprintf("Plugin %s cancelled the call", pt.Plugin), D{"recovery": "retry"})
	default:
		pluginFailure(pt.Plugin, r)
	}
	out := merge(pluginResult(r["result"]), merge(planned, D{"ok": true}))
	if dry {
		out = merge(out, D{"dry_run": true, "reserved": false, "resource_changes": false})
	}
	e.S.Log(str(w["sub"]), t["n"], pt.Name, a, "ok")
	return out
}

// dispatchPlugin runs under the writer when the worker takes the operation:
// it picks the node, checks the arguments against that node's schema and
// names the plugin operation. It calls no node; PerformPlugin does.
func (e *Execution) dispatchPlugin(a, w D) D {
	plug := obj(e.Op["plugin"])
	// The plugin ran and succeeded: a retry only brings the guest back.
	if boolean(plug["succeeded"]) {
		return D{"plugin": plug["plugin"], "operation": plug["operation"], "node": plug["node"]}
	}
	pt := e.P.pluginTools()[pluginToolName(str(plug["plugin"]), str(plug["operation"]))]
	node := ""
	if pt != nil {
		if !pt.Member && !boolean(w["admin"]) {
			fail("forbidden", "winlab-admin membership required")
		}
		if id := obj(e.Op["machine_target"])["vmid"]; id != nil {
			if n := e.P.nodeOf(e.S.Get("machines", str(id))).Name; contains(pt.Nodes, n) {
				node = n
			}
		} else {
			for _, n := range pt.Nodes {
				if !e.drained(n) {
					node = n
					break
				}
			}
		}
	}
	if node == "" {
		if now()-num(e.Op["queued_at"]) < pluginWaitForNode {
			panic(Waiting{"waiting_for_plugin", now() + pluginRecheck})
		}
		fail("unsupported", fmt.Sprintf("No node that could run it reports plugin %s with operation %s", plug["plugin"], plug["operation"]),
			D{"recovery": "retry_infrastructure"})
	}
	op, _ := e.P.pluginOperation(node, str(plug["plugin"]), str(plug["operation"]))
	// The node that runs it decides the access, whatever another node reports.
	if !op.Member && !boolean(w["admin"]) {
		fail("forbidden", "winlab-admin membership required")
	}
	if boolean(plug["caller_read_only"]) && !op.ReadOnly {
		fail("forbidden", "This tool changes state; call it on /mcp")
	}
	if op.Member && obj(e.Op["machine_target"])["vmid"] == nil {
		fail("invalid", "machine must name one of your machines")
	}
	checkPluginArgs(op.Params, a)
	// The key names one run of the plugin operation: the same across
	// restarts, re-queues and a retry whose run may still be going. Only a
	// run known to have ended gives way to a new key.
	if plug["key"] != nil && !boolean(plug["ended"]) {
		if plug["node"] != node {
			if now()-num(e.Op["queued_at"]) < pluginWaitForNode {
				panic(Waiting{"waiting_for_plugin", now() + pluginRecheck})
			}
			fail("unsupported", fmt.Sprintf("Node %s, which ran this operation, no longer reports plugin %s", plug["node"], plug["plugin"]),
				D{"recovery": "retry_infrastructure"})
		}
		e.resetPower(false)
		e.prepareRun(node, op, a)
		return D{"plugin": plug["plugin"], "operation": plug["operation"], "node": node}
	}
	runs := integer(plug["runs"]) + 1
	plug["node"], plug["runs"], plug["key"], plug["read_only"], plug["ended"], plug["start_sent"] = node, runs, fmt.Sprintf("%s-%d", e.Op["id"], runs), op.ReadOnly, false, false
	delete(plug, "refused")
	delete(plug, "plugin_code")
	e.resetPower(true)
	e.prepareRun(node, op, a)
	return D{"plugin": plug["plugin"], "operation": plug["operation"], "node": node}
}

// prepareRun readies a run after the last wait, so a waiting operation
// holds nothing: it reserves the record of an object operation, then
// records the guest's power for one that stops it. The checks and the
// quota come before the stop.
func (e *Execution) prepareRun(node string, op PluginOperation, a D) {
	plug := obj(e.Op["plugin"])
	pl, _ := e.P.pluginInfo(node, str(plug["plugin"]))
	if problem := pluginObjectProblem(pl, op) + pluginPowerProblem(op); problem != "" {
		fail("unsupported", fmt.Sprintf("Plugin %s on node %s: %s", plug["plugin"], node, problem), D{"recovery": "retry_infrastructure"})
	}
	plug["operation_spec"], plug["rewinds"] = PluginOperationSpec(pl, op), op.Rewinds
	var m D
	if id := obj(e.Op["machine_target"])["vmid"]; id != nil {
		if m = e.S.Get("machines", str(id)); m == nil {
			fail("not_found", "The operation's original machine no longer exists")
		}
	}
	if op.ObjectKind != "" {
		e.reservePluginObject(pl, op, a, e.S.TenantN(integer(e.Op["tenant_n"])), m)
	}
	if op.Stopped {
		e.preparePluginStop(op, m)
	}
}

func (p *Platform) nodeTarget(name string) string {
	for _, n := range p.Config.Nodes {
		if n.Name == name {
			return n.Target
		}
	}
	fail("backend_unavailable", "The plugin's node is not configured", D{"recovery": "retry_infrastructure"})
	return ""
}

// PerformPlugin starts the plugin operation and asks after it until it is
// done, outside the writer. A restart asks again with the same key, which
// returns the same operation.
func (e *Execution) PerformPlugin() {
	if !boolean(obj(e.Op["plugin"])["succeeded"]) {
		e.runPlugin()
	}
	// Only once the run has succeeded: a failed one restores in runPlugin.
	e.restorePluginPower()
}

// runPlugin stops the guest if the operation needs it, then runs the plugin
// operation to its end. A run that fails brings the guest back when it is
// known to have ended.
func (e *Execution) runPlugin() {
	defer func() {
		if r := recover(); r != nil {
			// A run that sent no start never began: a retry starts anew.
			if plug := obj(e.Op["plugin"]); !boolean(plug["start_sent"]) && e.Ctx.Err() == nil {
				plug["ended"] = true
			}
			e.restoreAfterFailure()
			panic(r)
		}
	}()
	e.stopForPlugin()
	plug := obj(e.Op["plugin"])
	target := e.P.nodeTarget(str(plug["node"]))
	job := D{"op": "plugin", "plugin": plug["plugin"], "operation": plug["operation"], "idempotency_key": plug["key"]}
	name := str(plug["plugin"])
	var unreachable time.Time
	// first: this is the first start ever sent for the key, so a refusal
	// proves the run never began. It is recorded before the start is sent,
	// so a restart or a lost answer never counts as a first start again.
	first := !boolean(plug["start_sent"])
	if first {
		e.P.writer.Lock()
		plug["start_sent"] = true
		e.P.Operations.Save(e.Op)
		e.P.writer.Unlock()
	}
	ask := func(call string) D {
		for {
			r := merge(job, D{"call": call})
			if call == "start" {
				params := without(obj(e.Op["args"]), pluginEnvelope...)
				// The plugin gets the machine bound to the caller's tenant
				// by its VMID, never the name the caller gave.
				if id := obj(e.Op["machine_target"])["vmid"]; id != nil {
					params["machine"] = str(id)
				}
				r["params"] = params
				r["operation_spec"] = plug["operation_spec"]
				if plug["object"] != nil {
					r["reservation"] = plug["object"]
				}
				if id := obj(e.Op["machine_target"])["vmid"]; id != nil {
					if m := e.S.Get("machines", str(id)); m != nil {
						r["machine"] = pluginMachineFacts(m)
					}
				}
			}
			v, err := e.P.Backend.Call(e.Ctx, r, target)
			if e.Ctx.Err() != nil {
				panic(e.Ctx.Err())
			}
			if err == nil {
				unreachable = time.Time{}
				return obj(v)
			}
			code := str(obj(failureResult(err)["error"])["backend_code"])
			// Only a refused first start proves the run never began; any
			// other failure leaves its fate unknown, so a retry asks after
			// the same key.
			if call == "start" && first && (code == "invalid" || code == "conflict" || code == "plugin_refused") {
				plug["ended"], plug["refused"] = true, true
			}
			first = false
			pluginRefusal(code, name, str(plug["node"]))
			// Unreachable: the plugin, its agent or the node. Ask again.
			if unreachable.IsZero() {
				unreachable = time.Now()
			} else if time.Since(unreachable) > pluginPatience {
				details := D{"recovery": "retry_infrastructure"}
				if boolean(obj(plug["power"])["stopping"]) {
					// The plugin may still be writing the disk.
					details["machine_left_stopped"] = true
				}
				fail("backend_unavailable", fmt.Sprintf("Plugin %s on node %s did not answer", name, plug["node"]), details)
			}
			if !sleep(e.Ctx, pluginPoll) {
				panic(e.Ctx.Err())
			}
		}
	}
	r := ask("start")
	for {
		if r["progress"] != e.Op["progress"] || r["message"] != e.Op["message"] {
			e.P.writer.Lock()
			e.Op["progress"], e.Op["message"] = r["progress"], r["message"]
			e.P.Operations.Save(e.Op)
			e.P.writer.Unlock()
		}
		if boolean(r["done"]) {
			plug["ended"] = true
			break
		}
		if !sleep(e.Ctx, pluginPoll) {
			panic(e.Ctx.Err())
		}
		r = ask("get")
	}
	switch r["state"] {
	case "succeeded":
		// Kept at once, with the record settled: whatever happens to the
		// guest's power, the run is not repeated.
		e.P.writer.Lock()
		e.Op["plugin_outcome"] = pick(r, "result", "task")
		plug["succeeded"] = true
		e.settlePluginObject(true)
		e.P.Operations.Save(e.Op)
		e.P.writer.Unlock()
	case "cancelled":
		fail("cancelled", fmt.Sprintf("Plugin %s cancelled the operation", name), D{"recovery": "retry"})
	default:
		// Kept for the record: a delete the plugin answers not_found has
		// nothing left to delete.
		plug["plugin_code"] = r["error_code"]
		pluginFailure(name, r)
	}
}

// FinishPlugin reports the plugin operation's result.
func (e *Execution) FinishPlugin() D {
	plug := obj(e.Op["plugin"])
	out := obj(e.Op["plugin_outcome"])
	e.settlePluginObject(true)
	// The plugin's result keys at the top, as a core tool's; carrel's own win.
	r := merge(pluginResult(out["result"]), D{"plugin": plug["plugin"], "operation": plug["operation"], "node": plug["node"],
		"task": out["task"], "resource_changes": !boolean(plug["read_only"])})
	if plug["object"] != nil {
		state := "deleted"
		if row, ok := rowOf[pluginObject](e.S, pluginObjectRows, str(plug["object"])); ok {
			state = row.State
		}
		r["object"] = D{"kind": plug["object_kind"], "name": plug["object_name"], "state": state}
	}
	e.pluginPowerResult(r)
	return r
}

var pluginPhases = Phases{Perform: (*Execution).PerformPlugin, Finish: func(e *Execution, _ D) D { return e.FinishPlugin() }}

// pluginListing is the tools/list entries of the plugin tools shows allows,
// sorted by name.
func pluginListing(tools map[string]*pluginTool, shows func(*pluginTool) bool) []*mcp.Tool {
	out := []*mcp.Tool{}
	for _, pt := range tools {
		if !shows(pt) {
			continue
		}
		description := pt.Description
		if description == "" {
			description = fmt.Sprintf("Operation %s of plugin %s.", pt.Operation, pt.Plugin)
		}
		if pt.ReadOnly {
			description += " Answers at once."
		} else {
			description += " Runs as an operation: poll operation_get until done; dry_run answers at once."
		}
		destructive := pt.Destructive
		out = append(out, &mcp.Tool{Name: pt.Name, Description: description, InputSchema: pluginInputSchema(pt.Schema),
			Annotations: &mcp.ToolAnnotations{ReadOnlyHint: pt.ReadOnly, DestructiveHint: &destructive, IdempotentHint: pt.Idempotent}})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
