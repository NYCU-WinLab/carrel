package carrel

// HTTP routes for plugin tools (#661): the same tools as MCP lists, for a
// client that speaks plain HTTP. A call goes through App.Call, so it is
// checked, gated and run exactly as on /mcp. Poll a call by sending it again
// with the same idempotency_key: the same arguments return the same
// operation.

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

var pluginHTTPStatus = map[string]int{"forbidden": 403, "not_found": 404, "invalid": 400, "conflict": 409,
	"unsupported": 409, "quota_exceeded": 409, "backend_unavailable": 503}

// member verifies the caller's bearer token as /mcp does, or answers 401 or
// 503 and returns nil.
func (a *App) member(w http.ResponseWriter, r *http.Request) D {
	authorization := r.Header.Get("Authorization")
	refuse := func() {
		// As /mcp does: the client finds where to sign in from here.
		w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+strings.TrimRight(a.Platform.Config.Origin, "/")+`/.well-known/oauth-protected-resource/mcp"`)
		jsonResponse(w, 401, D{"error": "invalid_token"})
	}
	if !strings.HasPrefix(authorization, "Bearer ") {
		refuse()
		return nil
	}
	who, err := a.verifier.Verify(r.Context(), authorization[7:])
	if err != nil {
		var unavailable IssuerUnavailable
		if errors.As(err, &unavailable) {
			jsonResponse(w, 503, D{"error": "temporarily_unavailable"})
		} else {
			refuse()
		}
		return nil
	}
	return who
}

func (a *App) pluginRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /plugins/v1/tools", func(w http.ResponseWriter, r *http.Request) {
		who := a.member(w, r)
		if who == nil {
			return
		}
		tools := []D{}
		for _, t := range pluginListing(a.Platform.pluginTools(), func(pt *pluginTool) bool { return boolean(who["admin"]) || pt.Member }) {
			tools = append(tools, D{"name": t.Name, "description": t.Description, "input_schema": t.InputSchema,
				"read_only": t.Annotations != nil && t.Annotations.ReadOnlyHint})
		}
		jsonResponse(w, 200, D{"ok": true, "tools": tools})
	})
	mux.HandleFunc("POST /plugins/v1/tools/{tool}", func(w http.ResponseWriter, r *http.Request) {
		who := a.member(w, r)
		if who == nil {
			return
		}
		name := r.PathValue("tool")
		if a.Platform.pluginTools()[name] == nil {
			jsonResponse(w, 404, D{"ok": false, "error": D{"code": "not_found", "message": "No plugin tool " + name + " is reported now"}})
			return
		}
		args := D{}
		body, err := io.ReadAll(r.Body)
		if err != nil || json.Unmarshal(body, &args) != nil || args == nil {
			jsonResponse(w, 400, D{"ok": false, "error": D{"code": "invalid", "message": "The body must be a JSON object of the tool's arguments"}})
			return
		}
		// The key is how a caller polls the operation here: without it, a
		// second request would start the work again.
		if str(args["idempotency_key"]) == "" {
			jsonResponse(w, 400, D{"ok": false, "error": D{"code": "invalid", "message": "idempotency_key is required: send the same arguments with the same key to poll the operation"}})
			return
		}
		result := a.Call(r.Context(), name, args, who)
		status := 200
		if !boolean(result["ok"]) {
			if status = pluginHTTPStatus[str(obj(result["error"])["code"])]; status == 0 {
				status = 500
			}
		}
		jsonResponse(w, status, result)
	})
}
