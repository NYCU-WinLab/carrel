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
					// A node that grants other access is not one this tool
					// runs on, as during a rolling update of the plugin.
					if op.Member == t.Member && op.ReadOnly == t.ReadOnly {
						t.Nodes = append(t.Nodes, n.Name)
					}
					continue
				}
				if coreTools[name] {
					left[name] = "a core tool has this name"
				} else if problem := pluginSchemaProblem(op); problem != "" {
					left[name] = problem
				} else {
					delete(left, name)
					tools[name] = &pluginTool{Name: name, Plugin: pl.Name, Operation: op.Name, Description: op.Description,
						Schema: op.Params, Member: op.Member, ReadOnly: op.ReadOnly, Nodes: []string{n.Name}}
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
		list = append(list, D{"tool": t.Name, "plugin": t.Plugin, "operation": t.Operation, "access": access, "read_only": t.ReadOnly, "nodes": t.Nodes})
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
	if boolean(a["dry_run"]) {
		return D{"ok": true, "state": "planned", "plugin": pt.Plugin, "operation": pt.Operation, "nodes": pt.Nodes, "reserved": false, "resource_changes": false}
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

// dispatchPlugin runs under the writer when the worker takes the operation:
// it picks the node, checks the arguments against that node's schema and
// names the plugin operation. It calls no node; PerformPlugin does.
func (e *Execution) dispatchPlugin(a, w D) D {
	plug := obj(e.Op["plugin"])
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
		return D{"plugin": plug["plugin"], "operation": plug["operation"], "node": node}
	}
	runs := integer(plug["runs"]) + 1
	plug["node"], plug["runs"], plug["key"], plug["read_only"], plug["ended"], plug["start_sent"] = node, runs, fmt.Sprintf("%s-%d", e.Op["id"], runs), op.ReadOnly, false, false
	return D{"plugin": plug["plugin"], "operation": plug["operation"], "node": node}
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
				plug["ended"] = true
			}
			first = false
			switch code {
			case "invalid":
				fail("invalid", fmt.Sprintf("Plugin %s refused the arguments", name), D{"recovery": "revise_request"})
			case "conflict":
				fail("conflict", fmt.Sprintf("Plugin %s refused the operation in its current state", name), D{"recovery": "revise_request"})
			case "plugin_refused":
				fail("unsupported", fmt.Sprintf("Plugin %s does not run on node %s now", name, plug["node"]), D{"recovery": "retry_infrastructure"})
			case "not_found", "plugin_error":
				fail("plugin_failed", fmt.Sprintf("Plugin %s failed", name), D{"recovery": "retry_infrastructure"})
			}
			// Unreachable: the plugin, its agent or the node. Ask again.
			if unreachable.IsZero() {
				unreachable = time.Now()
			} else if time.Since(unreachable) > pluginPatience {
				fail("backend_unavailable", fmt.Sprintf("Plugin %s on node %s did not answer", name, plug["node"]), D{"recovery": "retry_infrastructure"})
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
		e.Op["plugin_outcome"] = pick(r, "result", "task")
	case "cancelled":
		fail("cancelled", fmt.Sprintf("Plugin %s cancelled the operation", name), D{"recovery": "retry"})
	default:
		message := textAt(r, "error", "")
		if len(message) > MaxPluginText {
			message = strings.ToValidUTF8(message[:MaxPluginText], "")
		}
		fail("plugin_failed", fmt.Sprintf("Plugin %s failed: %s", name, message), D{"recovery": "retry_infrastructure"})
	}
}

// FinishPlugin reports the plugin operation's result.
func (e *Execution) FinishPlugin() D {
	plug := obj(e.Op["plugin"])
	out := obj(e.Op["plugin_outcome"])
	return D{"plugin": plug["plugin"], "operation": plug["operation"], "node": plug["node"],
		"result": out["result"], "task": out["task"], "resource_changes": !boolean(plug["read_only"])}
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
		out = append(out, &mcp.Tool{Name: pt.Name, Description: description + " Runs as an operation: poll operation_get until done.",
			InputSchema: pluginInputSchema(pt.Schema), Annotations: &mcp.ToolAnnotations{ReadOnlyHint: pt.ReadOnly}})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
