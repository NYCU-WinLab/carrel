package carrel

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
)

// Every MCP tool is also an HTTP route (#641): POST /v1/tools/{name} runs
// the same handler as tools/call (App.Call), with the same OAuth token, the
// same checks and the same audit record. Both read the one registry: the
// contract's tools and the plugin tools the nodes report.

// toolStatus maps a tool's error code to an HTTP status.
var toolStatus = map[string]int{"invalid": 400, "forbidden": 403, "not_found": 404, "conflict": 409, "quota_exceeded": 409, "unsupported": 409,
	"guest_not_ready": 409, "cancelled": 409, "plugin_failed": 502, "unavailable": 503, "backend_unavailable": 503, "capacity_exhausted": 507}

// bearerMember verifies the request's OAuth token as the MCP endpoint does.
// On failure it has written the response.
func (a *App) bearerMember(w http.ResponseWriter, r *http.Request, origin, resource string) (D, bool) {
	authorization := r.Header.Get("Authorization")
	var who D
	err := errors.New("missing token")
	if strings.HasPrefix(authorization, "Bearer ") {
		who, err = a.verifier.Verify(r.Context(), authorization[7:])
	}
	if err == nil {
		return who, true
	}
	var unavailable IssuerUnavailable
	if errors.As(err, &unavailable) {
		jsonResponse(w, 503, D{"error": "temporarily_unavailable"})
	} else {
		w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+origin+`/.well-known/oauth-protected-resource`+resource+`"`)
		jsonResponse(w, 401, D{"error": "invalid_token"})
	}
	return nil, false
}

// callable tells whether who may call tool by name, as tools/list on /mcp
// would show it: core tools minus admin tools for members, and the plugin
// tools the caller may see.
func (a *App) callable(name string, who D) bool {
	admin := boolean(who["admin"])
	if coreTools[name] {
		return admin || !named("admin_tools", name)
	}
	if pt := a.Platform.pluginTools()[name]; pt != nil {
		return admin || pt.Member
	}
	if r := a.Platform.rememberedTool(name); r != nil {
		return admin || boolean(r["member"])
	}
	return false
}

func (a *App) toolRoutes(mux *http.ServeMux, origin string) {
	mux.HandleFunc("GET /v1/tools", func(w http.ResponseWriter, r *http.Request) {
		who, ok := a.bearerMember(w, r, origin, "/mcp")
		if !ok {
			return
		}
		tools := []D{}
		for _, d := range dicts(Contract["tools"]) {
			if a.callable(str(d["name"]), who) {
				tools = append(tools, pick(d, "name", "description", "inputSchema", "annotations"))
			}
		}
		for _, pt := range a.Platform.pluginTools() {
			if a.callable(pt.Name, who) {
				tools = append(tools, D{"name": pt.Name, "plugin": true})
			}
		}
		jsonResponse(w, 200, D{"ok": true, "tools": tools})
	})
	mux.HandleFunc("POST /v1/tools/{name}", func(w http.ResponseWriter, r *http.Request) {
		who, ok := a.bearerMember(w, r, origin, "/mcp")
		if !ok {
			return
		}
		name := r.PathValue("name")
		if !a.callable(name, who) {
			jsonResponse(w, 404, D{"ok": false, "error": D{"code": "not_found", "message": "Unknown tool"}})
			return
		}
		args := D{}
		body, err := io.ReadAll(r.Body)
		if err == nil && len(strings.TrimSpace(string(body))) > 0 {
			err = json.Unmarshal(body, &args)
		}
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			jsonResponse(w, 413, D{"ok": false, "error": D{"code": "invalid", "message": "The body is larger than 256 KiB"}})
			return
		}
		if err != nil {
			jsonResponse(w, 400, D{"ok": false, "error": D{"code": "invalid", "message": "The body must be a JSON object of the tool's arguments"}})
			return
		}
		writeToolResult(w, a.Call(r.Context(), name, args, who))
	})
	mux.HandleFunc("GET /v1/operations/{id}", func(w http.ResponseWriter, r *http.Request) {
		who, ok := a.bearerMember(w, r, origin, "/mcp")
		if !ok {
			return
		}
		args := D{"id": r.PathValue("id"), "wait_seconds": 0}
		if t := r.URL.Query().Get("tenant"); t != "" {
			args["tenant"] = t
		}
		writeToolResult(w, a.Call(r.Context(), "operation_get", args, who))
	})
}

func writeToolResult(w http.ResponseWriter, result D) {
	status := 200
	if !boolean(result["ok"]) {
		code := str(obj(result["error"])["code"])
		if status = toolStatus[code]; status == 0 {
			status = 500
		}
	}
	jsonResponse(w, status, result)
}

var (
	openAPIOnce sync.Once
	openAPIDoc  []byte
)

// servedOpenAPI is openapi.json with a path per core tool, made from the
// contract, so the document never lags the tools. Plugin tools come and go
// with the nodes, so GET /v1/tools lists them instead.
func servedOpenAPI() []byte {
	openAPIOnce.Do(func() {
		var doc D
		must(json.Unmarshal(openAPI, &doc))
		paths := obj(doc["paths"])
		for _, d := range dicts(Contract["tools"]) {
			name := str(d["name"])
			paths["/v1/tools/"+name] = D{"post": D{
				"operationId":        name,
				"summary":            d["description"],
				"x-carrel-audience":  "member",
				"x-carrel-admin":     named("admin_tools", name),
				"x-carrel-read-only": boolean(obj(d["annotations"])["readOnlyHint"]),
				"security":           []any{D{"oauth": []any{}}},
				"requestBody":        D{"required": false, "content": D{"application/json": D{"schema": d["inputSchema"]}}},
				"responses":          D{"200": D{"$ref": "#/components/responses/Json"}, "default": D{"$ref": "#/components/responses/Error"}},
			}}
		}
		openAPIDoc = encoded(doc)
	})
	return openAPIDoc
}
