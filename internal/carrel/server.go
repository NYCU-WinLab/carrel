package carrel

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
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
	github   OIDCVerifier
	mu       sync.Mutex
	minute   int64
	requests map[string]int
	hour     int64
	signUps  map[string]int
	schemas  map[string]*jsonschema.Schema
}

func NewApp(p *Platform, verifier IdentityVerifier) *App {
	origin := strings.TrimRight(str(p.Config["origin"]), "/")
	issuer := strings.TrimRight(str(p.Config["issuer"]), "/")
	if verifier == nil {
		verifier = NewVerifier(issuer)
	}
	a := &App{Platform: p, verifier: verifier, github: NewGitHubVerifier(strings.TrimPrefix(strings.TrimPrefix(origin, "https://"), "http://")), schemas: map[string]*jsonschema.Schema{}}
	compiler := jsonschema.NewCompiler()
	for _, d := range dicts(Contract["tools"]) {
		name := str(d["name"])
		must(compiler.AddResource("https://carrel.invalid/schema/"+name, d["inputSchema"]))
		schema, err := compiler.Compile("https://carrel.invalid/schema/" + name)
		must(err)
		a.schemas[name] = schema
	}
	servers := map[bool]*mcp.Server{}
	for _, admin := range []bool{false, true} {
		server := mcp.NewServer(&mcp.Implementation{Name: "carrel", Version: Version}, &mcp.ServerOptions{Instructions: str(Contract["instructions"])})
		for _, definition := range dicts(Contract["tools"]) {
			name := str(definition["name"])
			if !admin && named("admin_tools", name) {
				continue
			}
			var tool mcp.Tool
			must(json.Unmarshal(encoded(definition), &tool))
			server.AddTool(&tool, func(ctx context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				args := D{}
				var result D
				if len(request.Params.Arguments) > 0 {
					if json.Unmarshal(request.Params.Arguments, &args) != nil {
						result = D{"ok": false, "error": D{"code": "invalid", "message": "Invalid arguments"}}
					}
				}
				if result == nil {
					result = a.Call(ctx, name, args, obj(ctx.Value(identityKey{})))
				}
				return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(encoded(result))}}, StructuredContent: result, IsError: !boolean(result["ok"])}, nil
			})
		}
		server.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
			return func(ctx context.Context, method string, request mcp.Request) (mcp.Result, error) {
				result, err := next(ctx, method, request)
				if listed, ok := result.(*mcp.ListToolsResult); ok && err == nil {
					visible := make([]*mcp.Tool, 0, len(listed.Tools))
					for _, tool := range listed.Tools {
						if contains(Contract["visible"], tool.Name) {
							visible = append(visible, tool)
						}
					}
					listed.Tools = visible
				}
				return result, err
			}
		})
		servers[admin] = server
	}
	stream := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		return servers[boolean(obj(r.Context().Value(identityKey{}))["admin"])]
	}, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true, MaxRequestBodyBytes: 262144})
	oauth := &OAuth{Store: p.Store, Origin: origin, Issuer: issuer, ClientID: "carrel-mcp", Hosted: []string{}, Verifier: verifier, HTTP: &http.Client{Timeout: 15 * time.Second}}
	for _, v := range arr(p.Config["hosted_redirects"]) {
		oauth.Hosted = append(oauth.Hosted, str(v))
	}
	mux := http.NewServeMux()
	console := consoleHandler{p: p, o: oauth}
	oauth.Console = console.finish
	mux.Handle("/oauth/", oauth)
	mux.Handle("/console/", console)
	mux.Handle("/.well-known/", oauth)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, 200, D{"status": "ok", "service": "carrel", "version": Version})
	})
	mux.HandleFunc("/internal/guest-status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(405)
			return
		}
		var body D
		err := attempt(func() {
			must(json.NewDecoder(r.Body).Decode(&body))
			host, _, _ := net.SplitHostPort(r.RemoteAddr)
			p.execution(r.Context()).GuestReport(body, host)
		})
		if err != nil {
			jsonResponse(w, 403, D{"ok": false})
		} else {
			jsonResponse(w, 200, D{"ok": true})
		}
	})
	a.appRoutes(mux)
	a.statusRoute(mux, p)
	mux.Handle("/mcp", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization := r.Header.Get("Authorization")
		var who D
		var err error
		if !strings.HasPrefix(authorization, "Bearer ") {
			err = errors.New("missing token")
		} else {
			who, err = verifier.Verify(r.Context(), authorization[7:])
		}
		if err != nil {
			var unavailable IssuerUnavailable
			if errors.As(err, &unavailable) {
				jsonResponse(w, 503, D{"error": "temporarily_unavailable"})
			} else {
				w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+origin+`/.well-known/oauth-protected-resource/mcp"`)
				jsonResponse(w, 401, D{"error": "invalid_token"})
			}
			return
		}
		stream.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), identityKey{}, who)))
	}))
	a.handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		internal := r.URL.Path == "/internal/guest-status"
		if internal && !strings.HasPrefix(host, "10.200.") {
			jsonResponse(w, 403, D{"error": "forbidden"})
			return
		}
		if !internal && r.Host != strings.TrimPrefix(strings.TrimPrefix(origin, "https://"), "http://") {
			jsonResponse(w, 400, D{"error": "invalid_host"})
			return
		}
		if v := r.Header.Get("Origin"); v != "" && v != origin {
			jsonResponse(w, 403, D{"error": "invalid_origin"})
			return
		}
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
		if !(r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/apps/v1/") && strings.HasSuffix(r.URL.Path, "/releases")) {
			r.Body = http.MaxBytesReader(w, r.Body, 262144)
		}
		mux.ServeHTTP(w, r)
	})
	return a
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
	schema := a.schemas[name]
	if schema == nil {
		return D{"ok": false, "error": D{"code": "invalid", "message": "Unknown tool or missing required field"}}
	}
	if err := schema.Validate(args); err != nil {
		return D{"ok": false, "error": D{"code": "invalid", "message": "Invalid tool arguments", "details": err.Error()}}
	}
	return memberResponse(name, args, a.Platform.Execute(ctx, name, without(args, "detail"), who))
}
func (p *Platform) Start() {
	p.wg.Add(1)
	go p.Operations.Loop()
	p.Operations.Recover()
	p.startNetBox()
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		for {
			p.writer.Lock()
			err := attempt(func() {
				e := p.execution(p.ctx)
				if len(e.S.Tenants()) > 0 {
					e.ExpireGrants()
					e.Reconcile()
				}
				e.S.PurgeOAuth()
				e.S.PruneOperations()
			})
			p.writer.Unlock()
			if err != nil {
				slog.Error("reconcile_failed", "type", "maintenance")
			}
			if p.ctx.Err() != nil {
				return
			}
			p.execution(p.ctx).MaintainDomains()
			if err := attempt(func() { p.execution(p.ctx).MaintainOrigin() }); err != nil {
				failure := obj(failureResult(err)["error"])
				slog.Error("origin_maintenance_failed", "type", "maintenance", "code", failure["code"], "backend_code", failure["backend_code"])
			}
			p.execution(p.ctx).RefreshStorage()
			if !sleep(p.ctx, 300*time.Second) {
				return
			}
		}
	}()
}
func (p *Platform) Close() { p.cancel(); p.wg.Wait() }

// Slow certificate renewal runs without the infrastructure writer. Revalidate
// each domain under the writer before routing an orphaned publication.
func (e *Execution) MaintainDomains() {
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
				cert := e.EnsureCertificate(t)
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
					e.DomainAction("domain_add", merge(d.target(), D{"sub": d.Sub, "target_port": d.TargetPort}), t)
				}()
			}
			e.RenewCertificate(t)
			func() {
				e.P.writer.Lock()
				defer e.P.writer.Unlock()
				live, ready := 0, false
				for _, d := range e.domains(n) {
					if d.State != "deleting" {
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
		} else if err != nil {
			failure := obj(failureResult(err)["error"])
			slog.Warn("domain_maintenance_failed", "tenant", n, "code", failure["code"], "backend_code", failure["backend_code"])
		}
	}
}
