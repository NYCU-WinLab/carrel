package carrel

import (
	_ "embed"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
)

//go:embed apps_install.sh
var appsInstallScript string

//go:embed apps_deploy.sh
var appsDeployScript string

//go:embed runners_install.sh
var runnersInstallScript string

var appStatus = map[string]int{"forbidden": 403, "not_found": 404, "invalid": 400, "conflict": 409, "quota_exceeded": 409, "capacity_exhausted": 507}

// appHandler turns a failed call into a JSON error with a matching status.
func appHandler(f func(http.ResponseWriter, *http.Request) D) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var result D
		if err := attempt(func() { result = f(w, r) }); err != nil {
			failure := failureResult(err)
			code := str(obj(failure["error"])["code"])
			status, ok := appStatus[code]
			if !ok {
				status = 500
				failure = D{"ok": false, "error": D{"code": "internal", "message": "Request failed"}}
			}
			jsonResponse(w, status, failure)
			return
		}
		if result == nil {
			w.WriteHeader(204)
			return
		}
		jsonResponse(w, 200, merge(D{"ok": true}, result))
	}
}

func bearer(r *http.Request) string {
	v := r.Header.Get("Authorization")
	if !strings.HasPrefix(v, "Bearer ") {
		fail("forbidden", "Bearer token required")
	}
	return v[7:]
}

func (a *App) ciClaims(r *http.Request) CIClaims {
	c, err := a.forges.Verify(r.Context(), bearer(r))
	if err != nil {
		fail("forbidden", "Invalid CI OIDC token")
	}
	return c
}

func (a *App) appRoutes(mux *http.ServeMux) {
	p := a.Platform
	mux.HandleFunc("GET /apps/v1/install.sh", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
		_, _ = w.Write([]byte(strings.ReplaceAll(appsInstallScript, "@ORIGIN@", p.appOrigin())))
	})
	mux.HandleFunc("GET /apps/v1/deploy.sh", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
		_, _ = w.Write([]byte(strings.ReplaceAll(appsDeployScript, "@ORIGIN@", p.appOrigin())))
	})
	mux.HandleFunc("GET /apps/v1/runner.sh", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
		_, _ = w.Write([]byte(runnersInstallScript))
	})
	mux.HandleFunc("GET /apps/v1/carrel-deployd", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		http.ServeFile(w, r, p.Config.DeploydBinary)
	})
	mux.Handle("POST /apps/v1/{tenant}/{app}/releases", appHandler(func(w http.ResponseWriter, r *http.Request) D {
		c := a.ciClaims(r)
		return D{"release": p.ReceiveRelease(r.Context(), r.PathValue("tenant"), r.PathValue("app"), c, r.ContentLength, r.Body)}
	}))
	mux.Handle("GET /apps/v1/{tenant}/{app}/releases/{id}", appHandler(func(w http.ResponseWriter, r *http.Request) D {
		c := a.ciClaims(r)
		return D{"release": p.ReleaseStatus(r.Context(), r.PathValue("tenant"), r.PathValue("app"), r.PathValue("id"), c)}
	}))
	// Any forge, or a post-receive hook, calls a pull-mode app's webhook.
	mux.Handle("POST /apps/v1/hooks/{token}", appHandler(func(w http.ResponseWriter, r *http.Request) D {
		_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 1<<20))
		p.Poke(r.PathValue("token"))
		return D{"checking": true}
	}))
	mux.Handle("GET /apps/v1/agent/source", appHandler(func(w http.ResponseWriter, r *http.Request) D {
		return p.AgentSource(bearer(r))
	}))
	mux.Handle("POST /apps/v1/agent/upload", appHandler(func(w http.ResponseWriter, r *http.Request) D {
		return D{"release": p.ReceiveAgentRelease(r.Context(), bearer(r), r.Header.Get("X-Carrel-Sha"), r.ContentLength, r.Body)}
	}))
	mux.Handle("POST /apps/v1/agent/next", appHandler(func(w http.ResponseWriter, r *http.Request) D {
		return p.AgentNext(r.Context(), bearer(r))
	}))
	mux.HandleFunc("GET /apps/v1/agent/releases/{id}", func(w http.ResponseWriter, r *http.Request) {
		var path string
		if err := attempt(func() { path = p.AgentRelease(bearer(r), r.PathValue("id")) }); err != nil {
			appHandler(func(http.ResponseWriter, *http.Request) D { panic(err) })(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/gzip")
		http.ServeFile(w, r, path)
	})
	mux.Handle("POST /apps/v1/agent/report", appHandler(func(w http.ResponseWriter, r *http.Request) D {
		var body D
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			fail("invalid", "Invalid JSON body")
		}
		return p.AgentReport(r.Context(), bearer(r), body)
	}))
	mux.Handle("POST /apps/v1/agent/logs", appHandler(func(w http.ResponseWriter, r *http.Request) D {
		var body D
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			fail("invalid", "Invalid JSON body")
		}
		return p.AppLogAnswer(bearer(r), body)
	}))
}

// remoteIP is the connection's address, never a header: the agent paths are
// not behind the gateway.
func remoteIP(r *http.Request) string {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

// functionRoutes serve function hosts' agents, from the infra network only
// (the internal paths in NewApp).
func (a *App) functionRoutes(mux *http.ServeMux) {
	p := a.Platform
	mux.HandleFunc("GET /functions/v1/agent/state", func(w http.ResponseWriter, r *http.Request) {
		since, err := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
		if err != nil {
			since = -1
		}
		var result D
		if err := attempt(func() { result = p.FunctionState(r.Context(), bearer(r), remoteIP(r), since) }); err != nil {
			appHandler(func(http.ResponseWriter, *http.Request) D { panic(err) })(w, r)
			return
		}
		// The agent reads the state as is: no ok wrapper.
		jsonResponse(w, 200, result)
	})
	mux.Handle("POST /functions/v1/agent/report", appHandler(func(w http.ResponseWriter, r *http.Request) D {
		var body D
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			fail("invalid", "Invalid JSON body")
		}
		return p.FunctionReport(r.Context(), bearer(r), remoteIP(r), body)
	}))
	// A GitHub job deploys the image it pushed to a linked function.
	mux.Handle("POST /functions/v1/deploy/{tenant}/{function}", appHandler(func(w http.ResponseWriter, r *http.Request) D {
		c := a.ciClaims(r)
		return p.ReceiveFunctionImage(r.Context(), r.PathValue("tenant"), r.PathValue("function"), c, r.Body)
	}))
	// A closed pull request's job removes its preview (#645).
	mux.Handle("DELETE /functions/v1/deploy/{tenant}/{function}/preview", appHandler(func(w http.ResponseWriter, r *http.Request) D {
		c := a.ciClaims(r)
		return p.ClosePreview(r.Context(), r.PathValue("tenant"), r.PathValue("function"), c, r.Body)
	}))
	mux.Handle("GET /functions/v1/deploy/{tenant}/{function}/{version}", appHandler(func(w http.ResponseWriter, r *http.Request) D {
		c := a.ciClaims(r)
		return D{"version": p.FunctionImageStatus(r.Context(), r.PathValue("tenant"), r.PathValue("function"), r.PathValue("version"), c)}
	}))
	// A member's agent uploads an environment file to a function_env link.
	env := appHandler(func(w http.ResponseWriter, r *http.Request) D {
		return p.ReceiveFunctionEnv(r.Context(), r.PathValue("token"), r.Body)
	})
	mux.Handle("PUT /functions/v1/env/{token}", env)
	mux.Handle("POST /functions/v1/env/{token}", env)
	registry := appHandler(func(w http.ResponseWriter, r *http.Request) D {
		return p.ReceiveFunctionRegistry(r.Context(), r.PathValue("token"), r.Body)
	})
	mux.Handle("PUT /functions/v1/registry/{token}", registry)
	mux.Handle("POST /functions/v1/registry/{token}", registry)
	mux.HandleFunc("GET /functions/v1/agent/auth", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		var result D
		if err := attempt(func() { result = p.FunctionAuthFor(bearer(r), remoteIP(r), q.Get("function"), q.Get("version")) }); err != nil {
			appHandler(func(http.ResponseWriter, *http.Request) D { panic(err) })(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		jsonResponse(w, 200, result)
	})
	mux.HandleFunc("GET /functions/v1/agent/env", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		var result D
		if err := attempt(func() { result = p.FunctionEnvFor(bearer(r), remoteIP(r), q.Get("function"), q.Get("version")) }); err != nil {
			appHandler(func(http.ResponseWriter, *http.Request) D { panic(err) })(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		jsonResponse(w, 200, result)
	})
	mux.HandleFunc("GET /functions/v1/agent/logs", func(w http.ResponseWriter, r *http.Request) {
		var result D
		if err := attempt(func() { result = p.FunctionLogRequests(r.Context(), bearer(r), remoteIP(r)) }); err != nil {
			appHandler(func(http.ResponseWriter, *http.Request) D { panic(err) })(w, r)
			return
		}
		jsonResponse(w, 200, result)
	})
	mux.Handle("POST /functions/v1/agent/logs", appHandler(func(w http.ResponseWriter, r *http.Request) D {
		var body D
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			fail("invalid", "Invalid JSON body")
		}
		return p.FunctionLogAnswer(bearer(r), remoteIP(r), body)
	}))
}
