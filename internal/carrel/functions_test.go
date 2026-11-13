package carrel

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
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
