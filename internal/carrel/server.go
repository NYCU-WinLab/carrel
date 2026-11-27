package carrel

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

type identityKey struct{}
type App struct {
	Platform *Platform
	handler  http.Handler
	verifier IdentityVerifier
	forges   OIDCVerifier
	mu       sync.Mutex
	minute   int64
	requests map[string]int
	hour     int64
	signUps  map[string]int
	schemas  map[string]*jsonschema.Schema
}

func NewApp(p *Platform, verifier IdentityVerifier) *App {
	origin := strings.TrimRight(p.Config.Origin, "/")
	issuer := strings.TrimRight(p.Config.Issuer, "/")
	ep := newEndpoints(issuer)
	if verifier == nil {
		verifier = NewVerifier(issuer, p.Config.OIDC, ep)
	}
	a := &App{Platform: p, verifier: verifier, forges: NewForgeVerifier(p.ciAudience(), p.Config.GitLabIssuers), schemas: map[string]*jsonschema.Schema{}}
	a.compileSchemas()
	mux := http.NewServeMux()
	a.oauthRoutes(mux, origin, issuer, ep)
	a.guestRoutes(mux)
	a.appRoutes(mux)
	a.functionRoutes(mux)
	a.keysRoutes(mux)
	a.statusRoute(mux, p)
	a.askRoute(mux, p)
	a.mcpRoutes(mux, origin)
	a.toolRoutes(mux, origin)
	a.pluginRoutes(mux)
	a.handler = chain(mux, a.networkGate(origin), originCheck(origin), a.oauthRateLimit, limitBody)
	return a
}

// chain wraps h so the first middleware runs outermost.
func chain(h http.Handler, middleware ...func(http.Handler) http.Handler) http.Handler {
	for i := len(middleware) - 1; i >= 0; i-- {
		h = middleware[i](h)
	}
	return h
}
func (a *App) compileSchemas() {
	compiler := jsonschema.NewCompiler()
	for _, d := range dicts(Contract["tools"]) {
		name := str(d["name"])
		must(compiler.AddResource("https://carrel.invalid/schema/"+name, d["inputSchema"]))
		schema, err := compiler.Compile("https://carrel.invalid/schema/" + name)
		must(err)
		a.schemas[name] = schema
	}
}
func (a *App) oauthRoutes(mux *http.ServeMux, origin, issuer string, ep *endpoints) {
	p := a.Platform
	oauth := &OAuth{Store: p.Store, Origin: origin, Issuer: issuer, ClientID: p.Config.OIDC.WithDefaults().ClientID, Hosted: []string{}, Verifier: a.verifier, endpoints: ep, HTTP: &http.Client{Timeout: 15 * time.Second, CheckRedirect: noRedirect}, ClientSecretFile: p.Config.OIDC.ClientSecretFile}
	oauth.Hosted = append(oauth.Hosted, p.Config.HostedRedirects...)
	console := consoleHandler{p: p, o: oauth}
	oauth.Console = console.finish
	mux.Handle("/oauth/", oauth)
	mux.Handle("/console/", console)
	mux.Handle("/.well-known/", oauth)
	mux.HandleFunc("GET /openapi.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(servedOpenAPI())
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		health := Build()
		health["status"], health["service"] = "ok", "carrel"
		jsonResponse(w, 200, health)
	})
}
func (a *App) guestRoutes(mux *http.ServeMux) {
	p := a.Platform
	mux.HandleFunc("/internal/guest-status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(405)
			return
		}
		var body, out D
		err := attempt(func() {
			must(json.NewDecoder(r.Body).Decode(&body))
			host, _, _ := net.SplitHostPort(r.RemoteAddr)
			out = p.execution(r.Context()).GuestReport(body, host)
		})
		if err != nil {
			jsonResponse(w, 403, D{"ok": false})
		} else {
			jsonResponse(w, 200, merge(out, D{"ok": true}))
		}
	})
	mux.HandleFunc("POST /internal/guest-keys", func(w http.ResponseWriter, r *http.Request) {
		var body D
		var keys string
		err := attempt(func() {
			must(json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body))
			host, _, _ := net.SplitHostPort(r.RemoteAddr)
			keys = p.execution(r.Context()).GuestKeys(body, host)
		})
		if err != nil {
			// Only a refused guest gets 403, which clears its keys; a server
			// fault must not log members out.
			status := 500
			if obj(failureResult(err)["error"])["code"] == "forbidden" {
				status = 403
			}
			jsonResponse(w, status, D{"ok": false})
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(keys))
	})
}
func (a *App) mcpRoutes(mux *http.ServeMux, origin string) {
	var serversMu sync.Mutex
	servers := map[string]*mcp.Server{}
	stream := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		admin := boolean(obj(r.Context().Value(identityKey{}))["admin"])
		sel, _ := r.Context().Value(selectionKey{}).(selection)
		key := sel.key(admin)
		serversMu.Lock()
		defer serversMu.Unlock()
		if servers[key] == nil {
			servers[key] = a.mcpServer(admin, sel)
		}
		return servers[key]
	}, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true, MaxRequestBodyBytes: 262144})
	mcpHandler := func(readOnly bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			who, ok := a.bearerMember(w, r, origin, strings.TrimSuffix(r.URL.Path, "/"))
			if !ok {
				return
			}
			query, err := url.ParseQuery(r.URL.RawQuery)
			var sel selection
			if err == nil {
				sel, err = parseSelection(readOnly, boolean(who["admin"]), append(query["toolsets"], r.Header.Values("X-Carrel-Toolsets")...)...)
			}
			if err != nil {
				jsonResponse(w, 400, D{"error": "invalid_toolsets", "message": err.Error()})
				return
			}
			ctx := context.WithValue(context.WithValue(r.Context(), identityKey{}, who), selectionKey{}, sel)
			stream.ServeHTTP(w, r.WithContext(ctx))
		}
	}
	mux.Handle("/mcp", mcpHandler(false))
	mux.Handle("/mcp/read-only", mcpHandler(true))
}
func (a *App) networkGate(origin string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host, _, _ := net.SplitHostPort(r.RemoteAddr)
			guest := strings.HasPrefix(r.URL.Path, "/internal/")
			internal := guest || r.URL.Path == "/gateway/ask" || strings.HasPrefix(r.URL.Path, "/functions/v1/agent/")
			// The gateway (10.200.0.2) forwards internet clients, so it is no
			// guest even though its address is on the infra network (#262).
			if internal && !strings.HasPrefix(host, "10.200.") || guest && host == "10.200.0.2" {
				jsonResponse(w, 403, D{"error": "forbidden"})
				return
			}
			if !internal && r.Host != strings.TrimPrefix(strings.TrimPrefix(origin, "https://"), "http://") {
				jsonResponse(w, 400, D{"error": "invalid_host"})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func originCheck(origin string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if v := r.Header.Get("Origin"); v != "" && v != origin {
				jsonResponse(w, 403, D{"error": "invalid_origin"})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
func (a *App) oauthRateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/oauth/") {
			// Per client address: one noisy client cannot lock everyone out of login.
			a.mu.Lock()
			minute := time.Now().Unix() / 60
			if minute != a.minute || a.requests == nil {
				a.minute = minute
				a.requests = map[string]int{}
			}
			ip := clientIP(r)
			a.requests[ip]++
			limited := a.requests[ip] > oauthRequestsPerMinute
			if r.URL.Path == "/oauth/register" {
				if hour := minute / 60; hour != a.hour || a.signUps == nil {
					a.hour, a.signUps = hour, map[string]int{}
				}
				a.signUps[ip]++
				limited = limited || a.signUps[ip] > registrationsPerHour
			}
			a.mu.Unlock()
			if limited {
				slog.Warn("oauth_rate_limited", "client", ip, "path", r.URL.Path)
				jsonResponse(w, 429, D{"error": "rate_limited"})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/apps/v1/") && strings.HasSuffix(r.URL.Path, "/releases"),
			r.Method == "POST" && r.URL.Path == "/apps/v1/agent/upload":
			// A release streams up to maxReleaseBytes; storeRelease bounds it.
		case r.URL.Path == "/functions/v1/agent/report":
			// A host reports every function it holds.
			r.Body = http.MaxBytesReader(w, r.Body, maxFunctionReport)
		case r.URL.Path == "/functions/v1/agent/logs":
			r.Body = http.MaxBytesReader(w, r.Body, maxFunctionLogReply)
		case r.URL.Path == "/apps/v1/agent/logs":
			r.Body = http.MaxBytesReader(w, r.Body, maxAppLogReply)
		default:
			r.Body = http.MaxBytesReader(w, r.Body, 262144)
		}
		next.ServeHTTP(w, r)
	})
}
func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) { a.handler.ServeHTTP(w, r) }

// oauthRequestsPerMinute bounds one client address on /oauth/*. A login takes
// about 4 requests and a refresh 1. registrationsPerHour bounds new clients
// from one address, so filling maxClients takes many addresses.
const oauthRequestsPerMinute = 60
const registrationsPerHour = 20

// clientIP is the address of the client. Requests arrive through the infra
// gateway, which sets X-Forwarded-For to the address it saw (it trusts no
// proxy, so a client cannot choose it); from anyone else the header is ignored.
func clientIP(r *http.Request) string {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if host == "10.200.0.2" {
		if f := r.Header.Get("X-Forwarded-For"); f != "" {
			parts := strings.Split(f, ",")
			return strings.TrimSpace(parts[len(parts)-1])
		}
	}
	return host
}
func (a *App) Call(ctx context.Context, name string, args, who D) D {
	start := time.Now()
	result := a.call(ctx, name, args, who)
	a.span(name, args, who, start, result)
	return result
}

func (a *App) call(ctx context.Context, name string, args, who D) D {
	schema := a.schemas[name]
	if schema == nil && (a.Platform.pluginTools()[name] != nil || a.Platform.rememberedTool(name) != nil) {
		// A plugin tool: Execute checks its arguments against its schema.
		return memberResponse(name, args, a.Platform.Execute(ctx, name, without(args, "detail"), who))
	}
	if schema == nil {
		return D{"ok": false, "error": D{"code": "invalid", "message": "Unknown tool or missing required field"}}
	}
	if err := schema.Validate(args); err != nil {
		return D{"ok": false, "error": D{"code": "invalid", "message": "Invalid tool arguments", "details": err.Error()}}
	}
	return memberResponse(name, args, a.Platform.Execute(ctx, name, without(args, "detail"), who))
}

// span reports the call to telemetry: the tool, the caller's tenant number
// when one can be named, and "ok" or the error code.
func (a *App) span(tool string, args, who D, start time.Time, result D) {
	t := a.Platform.Telemetry
	if t == nil {
		return
	}
	// A name nobody registered is caller input: one label, not one per guess.
	if a.schemas[tool] == nil && a.Platform.pluginTools()[tool] == nil {
		tool = "unknown"
	}
	outcome := "ok"
	if !boolean(result["ok"]) {
		outcome = str(obj(result["error"])["code"])
		if outcome == "" {
			outcome = "unknown"
		}
	}
	tenant := 0
	_ = attempt(func() { tenant = integer(a.Platform.execution(a.Platform.ctx).Tenant(who, str(args["tenant"]))["n"]) })
	t.Span(tool, tenant, start, outcome)
}
func (p *Platform) Start() {
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		for {
			select {
			case <-p.ctx.Done():
				return
			case <-p.domainKick:
				p.execution(p.ctx).MaintainDomains()
			}
		}
	}()
	p.wg.Add(1)
	go p.Operations.Loop()
	p.Operations.Recover()
	p.startNetBox()
	p.startTelemetry()
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		p.sweepAgents(p.ctx)
	}()
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		p.deliverWebhooks(p.ctx)
	}()
	// Push the jump state once at start, so a revoke committed around the last
	// shutdown does not wait for a node to answer the first reconcile.
	p.execution(p.ctx).syncJumpUntilSynced()
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		for {
			p.writer.Lock()
			// The jump push goes after the writer is released: it can wait on
			// jumpMu behind a send to a jump host that is down.
			pushJump := false
			err := attempt(func() {
				e := p.execution(p.ctx)
				if len(e.S.Tenants()) > 0 {
					e.ExpireGrants()
					e.ExpireVPNClients()
					e.ReapPreviews()
					e.deferJump = true
					pushJump = true
					e.Reconcile()
					// A record left in "deleting" whose VM is gone keeps its
					// reservation until the sweep removes it (#298).
					if problem := attemptLogged("sweep_deleted_machines", func() {
						if gone := e.SweepDeletedMachines(); len(gone) > 0 {
							slog.Warn("deleted_records_removed", "type", "maintenance", "count", len(gone))
						}
					}); problem != nil {
						slog.Error("sweep_deleted_machines_failed", "type", "maintenance", "error", describe(problem))
					}
				}
				e.S.PurgeOAuth()
				e.S.PruneOperations()
			})
			p.writer.Unlock()
			if pushJump {
				p.execution(p.ctx).syncJumpNow()
			}
			if err != nil {
				slog.Error("reconcile_failed", "type", "maintenance")
			}
			if p.ctx.Err() != nil {
				return
			}
			p.execution(p.ctx).MaintainDomains()
			p.execution(p.ctx).MaintainGrants()
			p.execution(p.ctx).MaintainSpecialPorts()
			if err := attempt(func() { p.execution(p.ctx).MaintainOrigin() }); err != nil {
				failure := obj(failureResult(err)["error"])
				slog.Log(p.ctx, levelUnlessStopping(p.ctx, slog.LevelError), "origin_maintenance_failed", "type", "maintenance", "code", failure["code"], "backend_code", failure["backend_code"])
			}
			p.execution(p.ctx).RefreshStorage()
			select {
			case <-p.ctx.Done():
				return
			case <-p.maintainKick:
			case <-time.After(300 * time.Second):
			}
		}
	}()
}
func (p *Platform) Close() {
	p.domainMu.Lock()
	if p.domainTimer != nil {
		p.domainTimer.Stop()
	}
	p.domainMu.Unlock()
	// Closing the jump queue first means no handler can p.wg.Add(1) while Wait runs.
	p.jumpQueueMu.Lock()
	p.jumpClosed = true
	p.jumpQueueMu.Unlock()
	p.cancel()
	p.wg.Wait()
}

// Slow certificate renewal runs without the infrastructure writer. Revalidate
// each domain under the writer before routing an orphaned publication.
func (e *Execution) MaintainDomains() {
	// The full pass and the domain loop both call this; one at a time.
	e.P.domainRun.Lock()
	defer e.P.domainRun.Unlock()
	for _, t := range e.S.Tenants() {
		n := integer(t["n"])
		err := attempt(func() {
			for _, original := range e.domains(n) {
				if (original.State != "queued" && original.State != "configuring") || original.ReadyAt > now() {
					continue
				}
				active := func() bool {
					return find(e.S.ActiveOperations(n), func(o D) bool {
						return (original.OperationID != "" && o["id"] == original.OperationID) || (o["tool"] == "domain_add" && len(arr(o["domain_target"])) > 0 && arr(o["domain_target"])[0] == original.ID)
					}) != nil
				}
				if active() || t["status"] != "active" {
					continue
				}
				var cert D
				if original.Grant == "" {
					cert = e.EnsureCertificate(t)
				} else if g, ok := rowOf[domainGrant](e.S, "domain_grants", original.Grant); ok {
					cert = e.EnsureGrantCertificate(g)
				} else {
					continue
				}
				if cert["state"] != "ready" {
					panic(Waiting{"waiting_for_certificate", num(cert["ready_at"])})
				}
				func() {
					e.P.writer.Lock()
					defer e.P.writer.Unlock()
					d, ok := rowOf[domainRecord](e.S, "domains", original.ID)
					if !ok || d.OperationID != original.OperationID || d.State == "deleting" || active() || e.S.TenantN(n)["status"] != "active" {
						return
					}
					d.State = "configuring"
					e.Put("domains", d.ID, n, d)
					e.DomainAction("domain_add", d.again(), t)
				}()
			}
			e.RenewCertificate(t)
			func() {
				e.P.writer.Lock()
				defer e.P.writer.Unlock()
				// The tenant's wildcard record follows its own domains;
				// grants keep records of their own (MaintainGrants).
				live, ready := 0, false
				for _, d := range e.domains(n) {
					if d.State != "deleting" && d.Grant == "" {
						live++
						ready = ready || d.State == "ready"
					}
				}
				if len(e.S.Objects("certificates", n)) > 0 || ready {
					e.DomainRecord(t, live == 0)
				}
			}()
		})
		// The next pass retries; operators read why in the log.
		if w, ok := err.(Waiting); ok {
			slog.Info("domain_maintenance_waiting", "tenant", n, "phase", w.Phase, "ready_at", w.ReadyAt)
			if w.Phase == "waiting_for_certificate" {
				e.P.kickDomainsAt(w.ReadyAt)
			}
		} else if err != nil {
			failure := obj(failureResult(err)["error"])
			slog.Warn("domain_maintenance_failed", "tenant", n, "code", failure["code"], "backend_code", failure["backend_code"])
		}
	}
}

type selectionKey struct{}

// selection is the part of the tool surface a caller asked for: the toolsets
// named in the URL or header, and whether only read-only tools are wanted.
// With none named, /mcp lists every toolset (admin only for an admin): a client
// such as Claude Code can call only tools it was listed, so a smaller default
// would cut members off from tools they use. Clients that load every listed
// tool on every turn can ask for fewer. Toolsets only shape tools/list; the
// admin and read-only filters in mcpServer decide what is callable.
type selection struct {
	readOnly bool
	sets     []string
}

func (s selection) key(admin bool) string {
	return strconv.FormatBool(admin) + "|" + strconv.FormatBool(s.readOnly) + "|" + strings.Join(s.sets, ",")
}

func parseSelection(readOnly, admin bool, values ...string) (selection, error) {
	known := obj(Contract["toolsets"])
	want := map[string]bool{}
	for _, value := range values {
		for _, name := range strings.Split(value, ",") {
			if name = strings.TrimSpace(name); name == "all" {
				for k := range known {
					want[k] = true
				}
			} else if name != "" {
				if known[name] == nil {
					return selection{}, errors.New("unknown toolset " + name)
				}
				want[name] = true
			}
		}
	}
	if len(want) == 0 && !readOnly {
		for k := range known {
			want[k] = k != "admin" || admin
		}
	}
	sel := selection{readOnly: readOnly}
	for k, ok := range want {
		if ok {
			sel.sets = append(sel.sets, k)
		}
	}
	sort.Strings(sel.sets)
	return sel, nil
}

// lists reports whether tools/list shows a tool. The read-only endpoint
// without toolsets lists every readOnlyHint tool.
func (s selection) lists(definition D) bool {
	if len(s.sets) == 0 {
		return true
	}
	for _, set := range s.sets {
		if contains(obj(Contract["toolsets"])[set], definition["name"]) {
			return true
		}
	}
	return false
}

// readOnlyInstructions replaces the full instructions on the read-only
// endpoint, where the write tools the routing lines name are not registered.
const readOnlyInstructions = "WinLab machines through MCP, read-only. Only tools that read state are available here (list, get, quota and catalog tools). Omit tenant for personal resources. Creating, changing or deleting anything needs the /mcp endpoint."

func instructionsFor(sel selection) string {
	if sel.readOnly {
		return readOnlyInstructions
	}
	return str(Contract["instructions"])
}

// mcpServer registers every tool the caller may call: admin tools only for an
// admin, and only readOnlyHint tools plus whoami on the read-only endpoint (whoami
// is not annotated read-only but only reports state there). A tool outside
// the selected toolsets stays callable by name but is left out of tools/list,
// for clients that ask for a smaller list and still call tools by name.
func (a *App) mcpServer(admin bool, sel selection) *mcp.Server {
	// Plugin tools change as nodes report plugins, so no list may be kept
	// for long or shared between callers.
	server := mcp.NewServer(&mcp.Implementation{Name: "carrel", Version: Version}, &mcp.ServerOptions{Instructions: instructionsFor(sel),
		SetCacheable: func(_ context.Context, _ mcp.Request, c *mcp.Cacheable) { c.CacheScope, c.TTLMs = "private", 0 }})
	listed := map[string]bool{}
	call := func(ctx context.Context, name string, raw json.RawMessage) *mcp.CallToolResult {
		args := D{}
		var result D
		if len(raw) > 0 {
			if json.Unmarshal(raw, &args) != nil {
				result = D{"ok": false, "error": D{"code": "invalid", "message": "Invalid arguments"}}
			}
		}
		if result == nil {
			result = a.Call(ctx, name, args, obj(ctx.Value(identityKey{})))
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(encoded(result))}}, StructuredContent: result, IsError: !boolean(result["ok"])}
	}
	for _, definition := range dicts(Contract["tools"]) {
		name := str(definition["name"])
		if !admin && named("admin_tools", name) || sel.readOnly && name != "whoami" && !boolean(obj(definition["annotations"])["readOnlyHint"]) {
			continue
		}
		listed[name] = sel.lists(definition)
		var tool mcp.Tool
		must(json.Unmarshal(encoded(definition), &tool))
		server.AddTool(&tool, func(ctx context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return call(ctx, name, request.Params.Arguments), nil
		})
	}
	// Plugin tools are not registered: the registry is read on every list
	// and call, so they come and go with the nodes' reports (#661).
	shows := func(pt *pluginTool) bool {
		return (admin || pt.Member) && (!sel.readOnly || pt.ReadOnly)
	}
	server.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, request mcp.Request) (mcp.Result, error) {
			if c, ok := request.(*mcp.CallToolRequest); ok && c.Params != nil {
				if _, core := listed[c.Params.Name]; !core && !coreTools[c.Params.Name] {
					if pt := a.Platform.pluginTools()[c.Params.Name]; pt != nil && shows(pt) {
						return call(ctx, pt.Name, c.Params.Arguments), nil
					}
					// A tool a node reported before answers that its plugin
					// is not reported now, not that it is unknown.
					if r := a.Platform.rememberedTool(c.Params.Name); r != nil && shows(&pluginTool{Member: boolean(r["member"]), ReadOnly: boolean(r["read_only"])}) {
						return call(ctx, c.Params.Name, c.Params.Arguments), nil
					}
				}
			}
			result, err := next(ctx, method, request)
			if list, ok := result.(*mcp.ListToolsResult); ok && err == nil {
				tools := []*mcp.Tool{}
				for _, tool := range list.Tools {
					if listed[tool.Name] {
						tools = append(tools, tool)
					}
				}
				// A plugin tool is in toolset plugins, and in the one it names.
				tools = append(tools, pluginListing(a.Platform.pluginTools(), func(pt *pluginTool) bool {
					return shows(pt) && (len(sel.sets) == 0 || contains(sel.sets, "plugins") || pt.Toolset != "" && contains(sel.sets, pt.Toolset))
				})...)
				list.Tools = tools
			}
			return result, err
		}
	})
	return server
}

// kickDomains runs only MaintainDomains now, without the full pass.
func (p *Platform) kickDomains() {
	select {
	case p.domainKick <- struct{}{}:
	default:
	}
}

// kickDomainsAt kicks the domain loop when a certificate becomes ready. It
// keeps the earliest pending time; a past or missing time retries in 5 s.
func (p *Platform) kickDomainsAt(readyAt float64) {
	delay := time.Duration((readyAt - now()) * float64(time.Second))
	if min := p.domainMinDelay; delay < min {
		delay = min
	} else if min == 0 && delay < 5*time.Second {
		delay = 5 * time.Second
	}
	at := time.Now().Add(delay)
	p.domainMu.Lock()
	defer p.domainMu.Unlock()
	if p.domainTimer != nil && !p.domainTimerAt.IsZero() && p.domainTimerAt.After(time.Now()) && !p.domainTimerAt.After(at) {
		return
	}
	if p.domainTimer != nil {
		p.domainTimer.Stop()
	}
	p.domainTimerAt = at
	p.domainTimer = time.AfterFunc(delay, p.kickDomains)
}

// kickMaintenance runs the maintenance loop's next pass now.
func (p *Platform) kickMaintenance() {
	select {
	case p.maintainKick <- struct{}{}:
	default:
	}
}
