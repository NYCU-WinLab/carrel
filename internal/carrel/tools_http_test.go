package carrel

import (
	"encoding/json"
	"errors"
	"testing"
)

func toolCall(t *testing.T, app *App, name, body string) (int, D) {
	t.Helper()
	w := requestApp(app, "POST", "/v1/tools/"+name, body, map[string]string{"Authorization": "Bearer test", "Content-Type": "application/json"})
	out := D{}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("%s: %d %s", name, w.Code, w.Body.String())
	}
	return w.Code, out
}

// A client with curl and a token does what an MCP client does.
func TestEveryToolHasAnHTTPRoute(t *testing.T) {
	p, _ := fixture(t)
	runQueue(p)
	app := NewApp(p, testVerifier{who: person("alice", false)})
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHttpHttpHttpHttpHttpHttpHttpHttpHttpHttpH http"
	if code, out := toolCall(t, app, "ssh_key_add", `{"key":"`+key+`"}`); code != 200 || out["ok"] != true {
		t.Fatalf("ssh_key_add: %d %s", code, encoded(out))
	}
	// The fake backend never reports the guest ready: the operation ends,
	// and the machine stays for its owner.
	code, out := toolCall(t, app, "machine_create", `{"name":"web"}`)
	if code != 200 || obj(out["operation"])["done"] != true {
		t.Fatalf("create: %d %s", code, encoded(out))
	}
	id := str(obj(out["operation"])["id"])
	if code, out := toolCall(t, app, "machine_get", `{"machine":"web"}`); code != 200 || len(arr(out["machines"])) != 1 || obj(arr(out["machines"])[0])["name"] != "web" {
		t.Fatalf("get: %d %s", code, encoded(out))
	}
	w := requestApp(app, "GET", "/v1/operations/"+id, "", map[string]string{"Authorization": "Bearer test"})
	if w.Code != 200 {
		t.Fatalf("operation: %d %s", w.Code, w.Body.String())
	}
	if code, out := toolCall(t, app, "machine_delete", `{"machine":"web","confirm":"web"}`); code != 200 || out["ok"] != true {
		t.Fatalf("delete: %d %s", code, encoded(out))
	}
	// Errors keep their code and answer with its status.
	if code, out := toolCall(t, app, "machine_get", `{"machine":"web"}`); code != 404 || obj(out["error"])["code"] != "not_found" {
		t.Fatalf("gone: %d %s", code, encoded(out))
	}
	if code, _ := toolCall(t, app, "machine_get", `{"machine":`); code != 400 {
		t.Fatalf("bad JSON: %d", code)
	}
	if code, _ := toolCall(t, app, "machine_get", `{"nope":1}`); code != 400 {
		t.Fatalf("schema: %d", code)
	}
	// The audit log has the HTTP calls, as for MCP.
	if rows := p.Store.Rows("SELECT tool FROM audit WHERE tool='machine_create'"); len(rows) == 0 {
		t.Fatal("no audit record")
	}
}

func TestToolRoutesKeepTheirGates(t *testing.T) {
	p, _ := fixture(t)
	member := NewApp(p, testVerifier{who: person("alice", false)})
	// An admin tool is unknown to a member, as on /mcp.
	if code, _ := toolCall(t, member, "node_list", ``); code != 404 {
		t.Fatalf("node_list for a member: %d", code)
	}
	if code, _ := toolCall(t, member, "no_such_tool", `{}`); code != 404 {
		t.Fatalf("unknown tool: %d", code)
	}
	admin := NewApp(p, testVerifier{who: person("root", true)})
	if code, out := toolCall(t, admin, "tenant_list", ``); code != 200 || out["ok"] != true {
		t.Fatalf("tenant_list for an admin: %d %s", code, encoded(out))
	}
	// A bad token: 401 with the resource metadata, as on /mcp.
	unauth := NewApp(p, testVerifier{err: errors.New("bad token")})
	w := requestApp(unauth, "POST", "/v1/tools/machine_list", "{}", map[string]string{"Authorization": "Bearer bad"})
	if w.Code != 401 || w.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("bad token: %d", w.Code)
	}
	// The listing shows only what the caller may run.
	w = requestApp(member, "GET", "/v1/tools", "", map[string]string{"Authorization": "Bearer test"})
	var list struct{ Tools []D }
	_ = json.Unmarshal(w.Body.Bytes(), &list)
	names := map[string]bool{}
	for _, tool := range list.Tools {
		names[str(tool["name"])] = true
	}
	if !names["machine_create"] || names["node_list"] || len(names) < 50 {
		t.Fatalf("listing: %d tools", len(names))
	}
}

// The served document has a path for every core tool, made from the contract.
func TestOpenAPIHasEveryTool(t *testing.T) {
	var doc struct {
		Paths map[string]map[string]D `json:"paths"`
	}
	if err := json.Unmarshal(servedOpenAPI(), &doc); err != nil {
		t.Fatal(err)
	}
	for _, d := range dicts(Contract["tools"]) {
		op := doc.Paths["/v1/tools/"+str(d["name"])]["post"]
		if op == nil || !equal(obj(obj(obj(op["requestBody"])["content"])["application/json"])["schema"], d["inputSchema"]) {
			t.Fatalf("%s has no up-to-date path", d["name"])
		}
	}
}
