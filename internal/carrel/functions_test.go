package carrel

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const testHostToken = "cfh_test-host-token"

func functionFixture(t *testing.T) (*Platform, *App) {
	t.Helper()
	p, _ := fixture(t)
	p.Config.FunctionHosts = []FunctionHostConfig{{Name: "fn01", Router: "10.200.0.20:8090", TokenSHA256: digest(testHostToken)}}
	return p, NewApp(p, nil)
}

// hostCall sends a host agent's request from the infra network.
func hostCall(t *testing.T, a *App, method, path, token, body string) (int, D) {
	t.Helper()
	req := httptest.NewRequest(method, "http://10.200.0.3:8080"+path, strings.NewReader(body))
	req.RemoteAddr = "10.200.0.20:40000"
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)
	out := D{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func report(t *testing.T, a *App, inventory string) {
	t.Helper()
	if code, out := hostCall(t, a, "POST", "/functions/v1/agent/report", testHostToken, inventory); code != 200 {
		t.Fatalf("report: %d %v", code, out)
	}
}

func hostState(t *testing.T, a *App) D {
	t.Helper()
	code, out := hostCall(t, a, "GET", "/functions/v1/agent/state?since=-1", testHostToken, "")
	if code != 200 {
		t.Fatalf("state: %d %v", code, out)
	}
	return out
}

func TestFunctionDeployBuildRollbackRemove(t *testing.T) {
	p, a := functionFixture(t)
	alice := person("alice", false)
	call := func(tool string, args D) D { return a.Call(context.Background(), tool, args, alice) }

	r := call("function_deploy", D{"name": "hook", "image": "ghcr.io/alice/hook:1", "port": 9000})
	assertOK(t, r)
	if r["state"] != "building" || obj(r["function"])["pending"] != "v1" {
		t.Fatalf("deploy %v", r)
	}
	// A second deploy waits for the first build.
	assertCode(t, call("function_deploy", D{"name": "hook", "image": "ghcr.io/alice/hook:2"}), "conflict")

	state := hostState(t, a)
	fns := arr(state["functions"])
	if len(fns) != 1 {
		t.Fatalf("state %v", state)
	}
	f := obj(fns[0])
	if f["id"] != "t1-hook" || f["current"] != nil {
		t.Fatalf("desired %v", f)
	}
	v := obj(arr(f["versions"])[0])
	if v["version"] != "v1" || v["image"] != "ghcr.io/alice/hook:1" || integer(v["port"]) != 9000 || v["mode"] != "reuse" || integer(v["max_instances"]) != 1 {
		t.Fatalf("desired version %v", v)
	}

	// The host built v1: it becomes current.
	report(t, a, `{"revision":1,"functions":[{"id":"t1-hook","versions":[{"version":"v1","state":"ready","bytes":1073741824,"digest":"sha256:`+strings.Repeat("a", 64)+`"}]}]}`)
	got := obj(call("function_get", D{"function": "hook"})["function"])
	if got["state"] != "deployed" || got["current"] != "v1" || got["pending"] != nil || got["host"] != "connected" || got["image"] != "ghcr.io/alice/hook:1" {
		t.Fatalf("after build %v", got)
	}
	if obj(hostState(t, a)["functions"].([]any)[0])["current"] != "v1" {
		t.Fatal("state does not name v1 current")
	}
	quota := call("quota_get", D{})
	if used := obj(obj(quota["quota"])["used"]); integer(used["functions"]) != 1 || num(used["function_gb"]) != 1 {
		t.Fatalf("quota %v", quota)
	}

	// v2 fails: v1 stays current and the state stops naming v2.
	assertOK(t, call("function_deploy", D{"name": "hook", "image": "ghcr.io/alice/hook:2"}))
	report(t, a, `{"revision":2,"functions":[{"id":"t1-hook","current":"v1","versions":[{"version":"v1","state":"ready","bytes":1073741824},{"version":"v2","state":"failed","error":"pull failed"}]}]}`)
	got = obj(call("function_get", D{"function": "hook"})["function"])
	if got["current"] != "v1" || got["pending"] != nil || got["state"] != "deployed" {
		t.Fatalf("after a failed build %v", got)
	}
	if versions := arr(obj(arr(hostState(t, a)["functions"])[0])["versions"]); len(versions) != 1 {
		t.Fatalf("a failed version is still desired: %v", versions)
	}

	// v3 builds; rollback returns to v1 without a build.
	assertOK(t, call("function_deploy", D{"name": "hook", "image": "ghcr.io/alice/hook:3"}))
	report(t, a, `{"revision":3,"functions":[{"id":"t1-hook","current":"v1","versions":[{"version":"v1","state":"ready"},{"version":"v3","state":"ready"}]}]}`)
	got = obj(call("function_get", D{"function": "hook"})["function"])
	if got["current"] != "v3" || got["previous"] != "v1" {
		t.Fatalf("after v3 %v", got)
	}
	r = call("function_rollback", D{"function": "hook"})
	assertOK(t, r)
	if f := obj(r["function"]); f["current"] != "v1" || f["previous"] != "v3" {
		t.Fatalf("rollback %v", r)
	}

	assertCode(t, call("function_remove", D{"function": "hook", "confirm": "nope"}), "invalid")
	assertOK(t, call("function_remove", D{"function": "hook", "confirm": "hook"}))
	if fns := arr(hostState(t, a)["functions"]); len(fns) != 0 {
		t.Fatalf("removed function still desired: %v", fns)
	}
	if n := len(p.Store.Objects("function_versions")); n != 0 {
		t.Fatalf("%d versions left", n)
	}
	// A late report about a removed function changes nothing.
	report(t, a, `{"revision":9,"functions":[{"id":"t1-hook","versions":[{"version":"v3","state":"ready"}]}]}`)
	assertCode(t, call("function_get", D{"function": "hook"}), "not_found")
}

func TestFunctionHostAccess(t *testing.T) {
	_, a := functionFixture(t)
	for _, token := range []string{"", "cfh_wrong", "cdt_" + testHostToken[4:], testHostToken + "x"} {
		if code, _ := hostCall(t, a, "GET", "/functions/v1/agent/state?since=-1", token, ""); code != 403 {
			t.Fatalf("token %q: %d", token, code)
		}
	}
	// The token works only from its host's address: a tenant machine on
	// 10.200.0.0/16 passes the infra gate but not this.
	req0 := httptest.NewRequest("GET", "http://10.200.0.3:8080/functions/v1/agent/state?since=-1", nil)
	req0.RemoteAddr = "10.200.1.10:40000"
	req0.Header.Set("Authorization", "Bearer "+testHostToken)
	w0 := httptest.NewRecorder()
	a.ServeHTTP(w0, req0)
	if w0.Code != 403 {
		t.Fatalf("a tenant machine with the token: %d", w0.Code)
	}
	// Only the infra network reaches the agent paths, whatever the token.
	req := httptest.NewRequest("GET", "https://carrel.test/functions/v1/agent/state?since=-1", nil)
	req.Header.Set("Authorization", "Bearer "+testHostToken)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)
	if w.Code != 403 {
		t.Fatalf("public request: %d", w.Code)
	}
}

func TestFunctionReportTouchesOnlyItsHost(t *testing.T) {
	p, a := functionFixture(t)
	p.Config.FunctionHosts = append(p.Config.FunctionHosts, FunctionHostConfig{Name: "fn02", Router: "10.200.0.20:8091", TokenSHA256: digest("cfh_other")})
	alice := person("alice", false)
	assertOK(t, a.Call(context.Background(), "function_deploy", D{"name": "hook", "image": "x/y:1"}, alice))
	// Another host cannot mark fn01's version built.
	if code, _ := hostCall(t, a, "POST", "/functions/v1/agent/report", "cfh_other", `{"functions":[{"id":"t1-hook","versions":[{"version":"v1","state":"ready"}]}]}`); code != 200 {
		t.Fatal(code)
	}
	if f := obj(a.Call(context.Background(), "function_get", D{"function": "hook"}, alice)["function"]); f["pending"] != "v1" {
		t.Fatalf("another host's report changed the function: %v", f)
	}
	if code, out := hostCall(t, a, "GET", "/functions/v1/agent/state?since=-1", "cfh_other", ""); code != 200 || len(arr(out["functions"])) != 0 {
		t.Fatalf("fn02 sees %v", out)
	}
	// Bad values in a report are ignored.
	report(t, a, `{"functions":[{"id":"t1-hook","current":"../x","versions":[{"version":"../v1","state":"ready"},{"version":"v1","state":"ready","bytes":-5,"digest":"md5:1"}]}]}`)
	v := p.Store.Get("function_versions", "1-hook/v1")
	if v["state"] != "ready" || v["bytes"] != nil || v["digest"] != nil {
		t.Fatalf("version %v", v)
	}
}

func TestFunctionDeployLimits(t *testing.T) {
	p, a := functionFixture(t)
	alice := person("alice", false)
	call := func(args D) D { return a.Call(context.Background(), "function_deploy", args, alice) }
	assertCode(t, call(D{"name": "x", "image": "a/b", "memory_mb": 4096}), "invalid")
	assertCode(t, call(D{"name": "x", "image": "a/b", "instance": "fresh", "max_instances": 11}), "invalid")
	assertCode(t, call(D{"name": "x", "image": "a/b", "timeout_seconds": 3601}), "invalid")
	assertCode(t, call(D{"name": "x", "image": "a b"}), "invalid")
	r := call(D{"name": "x", "image": "a/b", "instance": "fresh", "dry_run": true})
	assertOK(t, r)
	if len(p.Store.Objects("functions")) != 0 {
		t.Fatal("dry run wrote a function")
	}
	p.Store.Exec(`UPDATE tenants SET quota=json_set(quota,'$.functions',0) WHERE n=1`)
	assertCode(t, call(D{"name": "x", "image": "a/b"}), "quota_exceeded")
	p.Config.FunctionHosts = nil
	p.Store.Exec(`UPDATE tenants SET quota=json_set(quota,'$.functions',5) WHERE n=1`)
	assertCode(t, call(D{"name": "x", "image": "a/b"}), "capacity_exhausted")
}

func TestFunctionStateWaitsForAChange(t *testing.T) {
	p, a := functionFixture(t)
	revision := p.Store.functionRevision()
	done := make(chan D)
	go func() {
		_, out := hostCall(t, a, "GET", "/functions/v1/agent/state?since="+json.Number(strings.TrimSpace(string(encoded(revision)))).String(), testHostToken, "")
		done <- out
	}()
	assertOK(t, a.Call(context.Background(), "function_deploy", D{"name": "hook", "image": "x/y:1"}, person("alice", false)))
	out := <-done
	if integer(out["revision"]) <= int(revision) || len(arr(out["functions"])) != 1 {
		t.Fatalf("long poll answered %v", out)
	}
}

func TestFunctionVersionsAreNeverReused(t *testing.T) {
	_, a := functionFixture(t)
	alice := person("alice", false)
	call := func(tool string, args D) D { return a.Call(context.Background(), tool, args, alice) }
	assertOK(t, call("function_deploy", D{"name": "hook", "image": "x/old:1"}))
	report(t, a, `{"functions":[{"id":"t1-hook","versions":[{"version":"v1","state":"ready"}]}]}`)
	assertOK(t, call("function_remove", D{"function": "hook", "confirm": "hook"}))
	r := call("function_deploy", D{"name": "hook", "image": "x/new:1"})
	assertOK(t, r)
	if pending := obj(r["function"])["pending"]; pending == "v1" {
		t.Fatal("a removed function's version name came back")
	}
	// A late report of the old v1 does not make anything current.
	report(t, a, `{"functions":[{"id":"t1-hook","current":"v1","versions":[{"version":"v1","state":"ready"}]}]}`)
	if f := obj(call("function_get", D{"function": "hook"})["function"]); f["current"] != nil || f["state"] != "building" {
		t.Fatalf("old report changed the new function: %v", f)
	}
}

func TestFunctionBuildsHoldQuota(t *testing.T) {
	p, a := functionFixture(t)
	alice := person("alice", false)
	p.Store.Exec(`UPDATE tenants SET quota=json_set(quota,'$.function_gb',6) WHERE n=1`)
	call := func(name string) D {
		return a.Call(context.Background(), "function_deploy", D{"name": name, "image": "x/y:1"}, alice)
	}
	// Each build holds 2.5 GiB at 512 MiB until its size is known.
	assertOK(t, call("a"))
	assertOK(t, call("b"))
	assertCode(t, call("c"), "quota_exceeded")
	// A reported size replaces the reserve.
	report(t, a, `{"functions":[{"id":"t1-a","versions":[{"version":"v1","state":"ready","bytes":536870912}]}]}`)
	assertOK(t, call("c"))
}

// A suspended tenant's function must stop answering on its domains: unlike
// a machine, a function wakes on any request.
func TestFunctionRoutesSkipSuspendedTenants(t *testing.T) {
	p, a := functionFixture(t)
	alice := person("alice", false)
	assertOK(t, a.Call(context.Background(), "function_deploy", D{"name": "hook", "image": "ghcr.io/alice/hook:1", "port": 9000}, alice))
	e := p.execution(context.Background())
	if routes := e.functionRoutes(); len(routes) != 1 || routes[0]["host_id"] != "t1-hook" {
		t.Fatalf("routes %v", routes)
	}
	p.Store.Exec("UPDATE tenants SET status='suspended' WHERE n=1")
	if routes := e.functionRoutes(); len(routes) != 0 {
		t.Fatalf("suspended tenant still routed: %v", routes)
	}
}

func TestFunctionLogsAskTheHost(t *testing.T) {
	p, a := functionFixture(t)
	alice := person("alice", false)
	assertOK(t, a.Call(context.Background(), "function_deploy", D{"name": "hook", "image": "ghcr.io/alice/hook:1"}, alice))
	done := make(chan D, 1)
	go func() {
		done <- a.Call(context.Background(), "function_logs", D{"function": "hook", "since_seconds": 60, "max_bytes": 100}, alice)
	}()
	code, asked := hostCall(t, a, "GET", "/functions/v1/agent/logs", testHostToken, "")
	reqs := arr(asked["requests"])
	if code != 200 || len(reqs) != 1 {
		t.Fatalf("requests: %d %v", code, asked)
	}
	req := obj(reqs[0])
	if req["function"] != "t1-hook" || integer(req["max_bytes"]) != 100 || req["build"] != false || int64(integer(req["since"])) < time.Now().Unix()-61 {
		t.Fatalf("request %v", req)
	}
	// Another host's token cannot answer it, and a tenant machine cannot ask.
	p.Config.FunctionHosts = append(p.Config.FunctionHosts, FunctionHostConfig{Name: "fn02", Router: "10.200.0.20:8091", TokenSHA256: digest("cfh_other")})
	if code, _ := hostCall(t, a, "POST", "/functions/v1/agent/logs", "cfh_other", `{"id":"`+str(req["id"])+`","text":"forged\n"}`); code != 200 {
		t.Fatalf("other host: %d", code)
	}
	if code, _ := hostCall(t, a, "POST", "/functions/v1/agent/logs", testHostToken, `{"id":"`+str(req["id"])+`","text":"2026-11-13T00:00:00.000Z hello\n"}`); code != 200 {
		t.Fatalf("answer: %d", code)
	}
	r := <-done
	assertOK(t, r)
	if r["log"] != "2026-11-13T00:00:00.000Z hello\n" {
		t.Fatalf("logs %v", r)
	}
}

func TestFunctionLogsWhenTheHostIsAway(t *testing.T) {
	p, a := functionFixture(t)
	old := functionLogWait
	functionLogWait = 50 * time.Millisecond
	defer func() { functionLogWait = old }()
	alice := person("alice", false)
	assertOK(t, a.Call(context.Background(), "function_deploy", D{"name": "hook", "image": "ghcr.io/alice/hook:1"}, alice))
	assertCode(t, a.Call(context.Background(), "function_logs", D{"function": "hook"}, alice), "unavailable")
	// The unanswered request is gone, not handed to the next poll.
	if len(p.fnLogs.waiting["fn01"]) != 0 || len(p.fnLogs.asked) != 0 {
		t.Fatalf("stale request %v", p.fnLogs.waiting)
	}
}

// Requests a host never collected leave nothing behind, in any order.
func TestFunctionLogRequestsAreReleased(t *testing.T) {
	var l functionLogs
	old := functionLogWait
	functionLogWait = 20 * time.Millisecond
	defer func() { functionLogWait = old }()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	for i := 0; i < 50; i++ {
		go func() {
			l.ask(ctx, "fn01", D{"id": randomID()})
			done <- struct{}{}
		}()
	}
	cancel()
	for i := 0; i < 50; i++ {
		<-done
	}
	if len(l.waiting) != 0 || len(l.asked) != 0 {
		t.Fatalf("left behind: %d hosts, %d asks", len(l.waiting), len(l.asked))
	}
}

// The largest log of the worst characters for JSON still gets through.
func TestFunctionLogsLargestAnswerFits(t *testing.T) {
	_, a := functionFixture(t)
	alice := person("alice", false)
	assertOK(t, a.Call(context.Background(), "function_deploy", D{"name": "hook", "image": "ghcr.io/alice/hook:1"}, alice))
	done := make(chan D, 1)
	go func() {
		done <- a.Call(context.Background(), "function_logs", D{"function": "hook", "max_bytes": functionLogMax}, alice)
	}()
	_, asked := hostCall(t, a, "GET", "/functions/v1/agent/logs", testHostToken, "")
	text := strings.Repeat("<\x1b", functionLogMax/2)
	body, _ := json.Marshal(D{"id": obj(arr(asked["requests"])[0])["id"], "text": text})
	if code, out := hostCall(t, a, "POST", "/functions/v1/agent/logs", testHostToken, string(body)); code != 200 {
		t.Fatalf("answer of %d bytes: %d %v", len(body), code, out)
	}
	r := <-done
	assertOK(t, r)
	if r["log"] != text {
		t.Fatalf("log of %d bytes", len(str(r["log"])))
	}
}

const testEnvKey = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=" // 32 bytes

// putEnv uploads an environment file to a function_env link, from outside.
func putEnv(t *testing.T, a *App, link, body string) (int, D) {
	t.Helper()
	req := httptest.NewRequest("PUT", link, strings.NewReader(body))
	req.RemoteAddr = "198.51.100.7:40000"
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)
	out := D{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func TestFunctionEnvUploadBuildsAVersion(t *testing.T) {
	p, a := functionFixture(t)
	p.Config.FunctionEnvKey = testEnvKey
	alice := person("alice", false)
	call := func(tool string, args D) D { return a.Call(context.Background(), tool, args, alice) }
	assertOK(t, call("function_deploy", D{"name": "hook", "image": "ghcr.io/alice/hook:1", "port": 9000}))
	report(t, a, `{"revision":1,"functions":[{"id":"t1-hook","versions":[{"version":"v1","state":"ready","bytes":1073741824}]}]}`)

	r := call("function_env", D{"function": "hook"})
	assertOK(t, r)
	link := str(r["url"])
	if !strings.HasPrefix(link, "https://carrel.test/functions/v1/env/cfe_") || !strings.Contains(str(r["upload"]), "--data-binary @.env") {
		t.Fatalf("link %v", r)
	}
	// A file with a mistake leaves the link usable.
	if code, out := putEnv(t, a, link, "PORT=1\n"); code != 400 || !strings.Contains(str(obj(out["error"])["message"]), "PORT") {
		t.Fatalf("reserved key: %d %v", code, out)
	}
	for _, bad := range []string{"not a pair\n", "A=x\x1by\n"} {
		if code, _ := putEnv(t, a, link, bad); code != 400 {
			t.Fatalf("bad file %q: %d", bad, code)
		}
	}
	secret := "s3cr3t-value-" + randomID()
	code, out := putEnv(t, a, link, "# comment\nexport API_KEY=\""+secret+"\"\nMODE=prod\nMODE=test\n")
	if code != 200 || out["state"] != "building" || strings.Join(strs(out["keys"]), ",") != "API_KEY,MODE" {
		t.Fatalf("upload: %d %v", code, out)
	}
	if strings.Contains(string(encoded(out)), secret) {
		t.Fatal("the answer holds a value")
	}
	// Single use.
	if code, _ := putEnv(t, a, link, "A=1\n"); code != 404 {
		t.Fatalf("second use: %d", code)
	}
	// The host gets the values for the new version, in file order, the last MODE winning.
	versions := arr(obj(arr(hostState(t, a)["functions"])[0])["versions"])
	var v2 D
	for _, v := range versions {
		if obj(v)["version"] == "v2" {
			v2 = obj(v)
		}
	}
	if v2 == nil || v2["has_env"] != true || v2["env"] != nil || integer(v2["port"]) != 9000 {
		t.Fatalf("desired v2 %v", v2)
	}
	if env := hostEnv(t, a, "v2"); strings.Join(env, "|") != "API_KEY="+secret+"|MODE=test" {
		t.Fatalf("env of v2 %q", env)
	}
	// Another host gets nothing.
	p.Config.FunctionHosts = append(p.Config.FunctionHosts, FunctionHostConfig{Name: "fn02", Router: "10.200.0.20:8091", TokenSHA256: digest("cfh_other")})
	if code, _ := hostCall(t, a, "GET", "/functions/v1/agent/env?function=t1-hook&version=v2", "cfh_other", ""); code != 404 {
		t.Fatalf("other host: %d", code)
	}
	// Nothing at rest or in the audit log holds the value.
	for _, table := range []string{"objects", "audit", "site"} {
		for _, row := range p.Store.Rows("SELECT * FROM " + table) {
			if strings.Contains(string(encoded(row)), secret) {
				t.Fatalf("%s holds the value: %v", table, row)
			}
		}
	}
	got := obj(call("function_get", D{"function": "hook"})["function"])
	// The function shows its live version's names; the building one has its own.
	if len(strs(got["env_keys"])) != 0 || strings.Join(strs(obj(arr(got["versions"])[0])["env_keys"]), ",") != "API_KEY,MODE" || strings.Contains(string(encoded(got)), secret) {
		t.Fatalf("function_get %v", got)
	}
	// A deploy keeps the live version's environment.
	report(t, a, `{"revision":3,"functions":[{"id":"t1-hook","current":"v1","versions":[{"version":"v1","state":"ready","bytes":1},{"version":"v2","state":"ready","bytes":1}]}]}`)
	assertOK(t, call("function_deploy", D{"name": "hook", "image": "ghcr.io/alice/hook:2", "port": 9000}))
	if env := hostEnv(t, a, "v3"); len(env) != 2 {
		t.Fatalf("deploy dropped the environment: %q", env)
	}
	// After a rollback to v2 (with the environment) from v3, and a clear in v4,
	// rolling back to v3 and deploying again brings v3's values, not v4's none.
	report(t, a, `{"revision":4,"functions":[{"id":"t1-hook","current":"v3","versions":[{"version":"v2","state":"ready","bytes":1},{"version":"v3","state":"ready","bytes":1}]}]}`)
	assertOK(t, call("function_env", D{"function": "hook", "clear": true}))
	report(t, a, `{"revision":5,"functions":[{"id":"t1-hook","current":"v4","versions":[{"version":"v3","state":"ready","bytes":1},{"version":"v4","state":"ready","bytes":1}]}]}`)
	if got := obj(call("function_get", D{"function": "hook"})["function"]); len(strs(got["env_keys"])) != 0 {
		t.Fatalf("after clear %v", got["env_keys"])
	}
	assertOK(t, call("function_rollback", D{"function": "hook"}))
	assertOK(t, call("function_deploy", D{"name": "hook", "image": "ghcr.io/alice/hook:3", "port": 9000}))
	if env := hostEnv(t, a, "v5"); len(env) != 2 {
		t.Fatalf("deploy after rollback took the wrong environment: %q", env)
	}
	// A link dies with its function, even if one of the same name follows.
	stale := str(call("function_env", D{"function": "hook"})["url"])
	assertOK(t, call("function_remove", D{"function": "hook", "confirm": "hook"}))
	assertOK(t, call("function_deploy", D{"name": "hook", "image": "ghcr.io/alice/hook:1"}))
	if code, _ := putEnv(t, a, stale, "A=1\n"); code != 404 {
		t.Fatalf("stale link: %d", code)
	}
	if code, _ := putEnv(t, a, str(call("function_env", D{"function": "hook"})["url"]), "A=\xff\n"); code != 400 {
		t.Fatalf("not UTF-8: %d", code)
	}
	// Another tenant cannot ask for a link to it.
	assertCode(t, a.Call(context.Background(), "function_env", D{"function": "hook"}, person("bob", false)), "not_found")
}

func hostEnv(t *testing.T, a *App, version string) []string {
	t.Helper()
	code, out := hostCall(t, a, "GET", "/functions/v1/agent/env?function=t1-hook&version="+version, testHostToken, "")
	if code != 200 {
		t.Fatalf("env of %s: %d %v", version, code, out)
	}
	return strs(out["env"])
}

func TestFunctionEnvNeedsAKeyAndStaysWithItsFunction(t *testing.T) {
	p, a := functionFixture(t)
	alice := person("alice", false)
	assertOK(t, a.Call(context.Background(), "function_deploy", D{"name": "hook", "image": "ghcr.io/alice/hook:1"}, alice))
	assertCode(t, a.Call(context.Background(), "function_env", D{"function": "hook"}, alice), "unavailable")
	p.Config.FunctionEnvKey = testEnvKey
	sealed := p.sealFunctionEnv("1-hook", []string{"A=1"})
	if got := p.openFunctionEnv("1-hook", sealed); len(got) != 1 || got[0] != "A=1" {
		t.Fatalf("open %v", got)
	}
	if err := attempt(func() { p.openFunctionEnv("2-hook", sealed) }); err == nil {
		t.Fatal("an environment opened for another function")
	}
}

func strs(v any) []string {
	out := []string{}
	for _, x := range arr(v) {
		out = append(out, str(x))
	}
	return out
}

func TestFunctionRegistryCredentialsGoToTheirRegistryOnly(t *testing.T) {
	p, a := functionFixture(t)
	p.Config.FunctionEnvKey = testEnvKey
	alice := person("alice", false)
	call := func(tool string, args D) D { return a.Call(context.Background(), tool, args, alice) }
	assertOK(t, call("function_deploy", D{"name": "hook", "image": "ghcr.io/alice/hook:1"}))
	r := call("function_registry", D{"function": "hook"})
	assertOK(t, r)
	link := str(r["url"])
	if r["registry"] != "ghcr.io" || !strings.Contains(link, "/functions/v1/registry/cfr_") || !strings.Contains(str(r["upload"]), "$REGISTRY_TOKEN") {
		t.Fatalf("link %v", r)
	}
	// An environment link does not open the registry path, nor the reverse.
	envLink := str(call("function_env", D{"function": "hook"})["url"])
	if code, _ := putEnv(t, a, strings.Replace(envLink, "/env/", "/registry/", 1), `{"username":"u","password":"p"}`); code != 404 {
		t.Fatalf("env link on the registry path: %d", code)
	}
	if code, _ := putEnv(t, a, strings.Replace(link, "/registry/", "/env/", 1), "A=1\n"); code != 404 {
		t.Fatalf("registry link on the env path: %d", code)
	}
	if code, _ := putEnv(t, a, link, `{"username":"alice"}`); code != 400 {
		t.Fatalf("no password: %d", code)
	}
	secret := "ghp_" + randomID()
	if code, out := putEnv(t, a, link, `{"username":"alice","password":"`+secret+`"}`); code != 200 || out["registry"] != "ghcr.io" {
		t.Fatalf("upload: %d %v", code, out)
	}
	if code, _ := putEnv(t, a, link, `{"username":"alice","password":"x"}`); code != 404 {
		t.Fatalf("second use: %d", code)
	}
	// The host is told v1 wants credentials, and gets them.
	v1 := obj(arr(obj(arr(hostState(t, a)["functions"])[0])["versions"])[0])
	if v1["has_auth"] != true || strings.Contains(string(encoded(v1)), secret) {
		t.Fatalf("desired v1 %v", v1)
	}
	code, out := hostCall(t, a, "GET", "/functions/v1/agent/auth?function=t1-hook&version=v1", testHostToken, "")
	if auth := obj(out["auth"]); code != 200 || auth["registry"] != "ghcr.io" || auth["username"] != "alice" || auth["password"] != secret {
		t.Fatalf("auth: %d %v", code, out)
	}
	// Nothing at rest, in the audit log or in function_get holds the token.
	for _, table := range []string{"objects", "audit", "site"} {
		for _, row := range p.Store.Rows("SELECT * FROM " + table) {
			if strings.Contains(string(encoded(row)), secret) {
				t.Fatalf("%s holds the token", table)
			}
		}
	}
	got := obj(call("function_get", D{"function": "hook"})["function"])
	if got["registry"] != "ghcr.io" || strings.Contains(string(encoded(got)), secret) {
		t.Fatalf("function_get %v", got)
	}
	// An image on another registry never gets them.
	report(t, a, `{"revision":3,"functions":[{"id":"t1-hook","versions":[{"version":"v1","state":"ready","bytes":1}]}]}`)
	assertOK(t, call("function_deploy", D{"name": "hook", "image": "docker.io/library/nginx:1"}))
	for _, v := range arr(obj(arr(hostState(t, a)["functions"])[0])["versions"]) {
		if obj(v)["version"] == "v2" && obj(v)["has_auth"] != false {
			t.Fatalf("credentials for another registry: %v", v)
		}
	}
	if code, _ := hostCall(t, a, "GET", "/functions/v1/agent/auth?function=t1-hook&version=v2", testHostToken, ""); code != 404 {
		t.Fatalf("auth for another registry: %d", code)
	}
	// clear removes them.
	assertOK(t, call("function_registry", D{"function": "hook", "clear": true}))
	if code, _ := hostCall(t, a, "GET", "/functions/v1/agent/auth?function=t1-hook&version=v1", testHostToken, ""); code != 404 {
		t.Fatalf("auth after clear: %d", code)
	}
}
