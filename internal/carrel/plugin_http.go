package carrel

// HTTP routes for plugin tools (#661): the same tools as MCP lists (GET /v1/tools shows them), for a
// client that speaks plain HTTP. A call goes through App.Call, so it is
// checked, gated and run exactly as on /mcp. Poll a call by sending it again
// with the same idempotency_key: the same arguments return the same
// operation.

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

var pluginHTTPStatus = map[string]int{"forbidden": 403, "not_found": 404, "invalid": 400, "conflict": 409,
	"unsupported": 409, "quota_exceeded": 409, "backend_unavailable": 503}

// member verifies the caller's bearer token as /mcp does (bearerMember), or
// answers 401 or 503 and returns nil.
func (a *App) member(w http.ResponseWriter, r *http.Request) D {
	who, _ := a.bearerMember(w, r, strings.TrimRight(a.Platform.Config.Origin, "/"), "/mcp")
	return who
}

func (a *App) pluginRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /plugins/v1/tools/{tool}", func(w http.ResponseWriter, r *http.Request) {
		who := a.member(w, r)
		if who == nil {
			return
		}
		name := r.PathValue("tool")
		pt := a.Platform.pluginTools()[name]
		if pt == nil {
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
		if !pt.ReadOnly && !boolean(args["dry_run"]) && str(args["idempotency_key"]) == "" {
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
