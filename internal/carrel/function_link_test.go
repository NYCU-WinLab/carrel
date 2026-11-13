package carrel

import (
	"context"
	"strings"
	"testing"
)

func TestFunctionLinkDeploysFromGitHub(t *testing.T) {
	p, a := functionFixture(t)
	a.github = fakeGitHub{
		"good":   push("alice/hook", "42", "main"),
		"other":  push("mallory/hook", "7", "main"),
		"branch": push("alice/hook", "42", "dev"),
		"pr":     {Repository: "alice/hook", RepositoryID: "42", Ref: "refs/heads/main", Event: "pull_request"},
		"reborn": push("alice/hook", "99", "main"),
	}
	alice := person("alice", false)
	call := func(tool string, args D) D { return a.Call(context.Background(), tool, args, alice) }
	digestA := "ghcr.io/alice/hook@sha256:" + strings.Repeat("a", 64)
	deploy := func(token, image string) (int, D) {
		return do(t, a, "POST", "/functions/v1/deploy/alice/hook", token, strings.NewReader(`{"image":"`+image+`"}`))
	}

	// Not linked yet: the same answer as an unknown function.
	assertOK(t, call("function_deploy", D{"name": "hook", "image": "ghcr.io/alice/hook:1", "port": 9000, "memory_mb": 256}))
	if code, _ := deploy("good", digestA); code != 404 {
		t.Fatalf("unlinked: %d", code)
	}
	r := call("function_link", D{"function": "hook", "repo": "Alice/Hook"})
	assertOK(t, r)
	wf := str(r["workflow"])
	for _, want := range []string{"branches: [main]", "id-token: write", "tenant: alice", "function: hook", "ghcr.io/alice/hook@${{ steps.image.outputs.digest }}", "concurrency: carrel-hook"} {
		if !strings.Contains(wf, want) {
			t.Fatalf("workflow lacks %q:\n%s", want, wf)
		}
	}
	// A build in progress refuses another.
	if code, _ := deploy("good", digestA); code != 409 {
		t.Fatalf("while building: %d", code)
	}
	report(t, a, `{"revision":1,"functions":[{"id":"t1-hook","current":"v1","versions":[{"version":"v1","state":"ready","bytes":1073741824}]}]}`)

	for token, want := range map[string]int{"": 403, "forged": 403, "other": 403, "branch": 403, "pr": 403} {
		if code, _ := deploy(token, digestA); code != want {
			t.Fatalf("token %q: %d", token, code)
		}
	}
	for _, image := range []string{"ghcr.io/alice/hook:latest", "ghcr.io/alice/hook@sha256:abc", "Ghcr.io/alice/hook@sha256:" + strings.Repeat("a", 64)} {
		if code, _ := deploy("good", image); code != 400 {
			t.Fatalf("image %q: %d", image, code)
		}
	}
	code, out := deploy("good", digestA)
	v := obj(out["version"])
	if code != 200 || v["version"] != "v2" || v["state"] != "building" {
		t.Fatalf("deploy: %d %v", code, out)
	}
	// The version keeps the function's settings, with the pushed image and its commit.
	got := p.Store.Get("function_versions", functionVersionID("1-hook", "v2"))
	if got["image"] != digestA || integer(got["port"]) != 9000 || integer(got["memory_mb"]) != 256 || got["sha"] != "abc123" {
		t.Fatalf("version %v", got)
	}
	status := func(token, version string) (int, D) {
		code, out := do(t, a, "GET", "/functions/v1/deploy/alice/hook/"+version, token, nil)
		return code, obj(out["version"])
	}
	if code, s := status("good", "v2"); code != 200 || s["state"] != "building" {
		t.Fatalf("status: %d %v", code, s)
	}
	if code, _ := status("other", "v2"); code != 403 {
		t.Fatalf("status by another repository: %d", code)
	}
	// Ready but not yet served stays building; live once the host serves it.
	report(t, a, `{"revision":2,"functions":[{"id":"t1-hook","current":"v1","versions":[{"version":"v1","state":"ready"},{"version":"v2","state":"ready"}]}]}`)
	report(t, a, `{"revision":3,"functions":[{"id":"t1-hook","current":"v2","versions":[{"version":"v1","state":"ready"},{"version":"v2","state":"ready"}]}]}`)
	if _, s := status("good", "v2"); s["state"] != "live" {
		t.Fatalf("after serving: %v", s)
	}
	// A failed build fails the workflow with the error.
	_, out = deploy("good", "ghcr.io/alice/hook@sha256:"+strings.Repeat("b", 64))
	v3 := str(obj(out["version"])["version"])
	report(t, a, `{"revision":4,"functions":[{"id":"t1-hook","current":"v2","versions":[{"version":"v2","state":"ready"},{"version":"`+v3+`","state":"failed","error":"pull failed"}]}]}`)
	if _, s := status("good", v3); s["state"] != "failed" || s["error"] != "pull failed" {
		t.Fatalf("failed build: %v", s)
	}
	// The first deploy pinned the repository id: a recreated repository cannot deploy.
	if code, _ := deploy("reborn", digestA); code != 403 {
		t.Fatalf("recreated repository: %d", code)
	}
	if fn := obj(call("function_get", D{"function": "hook"})["function"]); fn["repo"] != "alice/hook" || fn["branch"] != "main" {
		t.Fatalf("function_get %v", fn)
	}
	// Unlinking stops deploys; linking again starts unpinned.
	assertOK(t, call("function_link", D{"function": "hook", "clear": true}))
	if code, _ := deploy("good", digestA); code != 404 {
		t.Fatalf("after unlink: %d", code)
	}
	assertOK(t, call("function_link", D{"function": "hook", "repo": "alice/hook"}))
	if code, _ := deploy("reborn", digestA); code != 200 {
		t.Fatalf("relinked: %d", code)
	}
	// Another tenant's member cannot link it.
	if r := a.Call(context.Background(), "function_link", D{"function": "hook", "repo": "bob/x"}, person("bob", false)); r["ok"] == true {
		t.Fatalf("bob linked alice's function: %v", r)
	}
}

// The links members and GitHub jobs use reach carrel through the gateway; the
// host agents' paths do not.
func TestFunctionPublicPathsGoThroughTheGateway(t *testing.T) {
	routed := func(path string) bool {
		for _, c := range controlPaths {
			if c == path || (strings.HasSuffix(c, "/*") && strings.HasPrefix(path, strings.TrimSuffix(c, "*"))) {
				return true
			}
		}
		return false
	}
	for _, path := range []string{"/functions/v1/env/cfe_x", "/functions/v1/registry/cfr_x", "/functions/v1/deploy/alice/hook", "/functions/v1/deploy/alice/hook/v2"} {
		if !routed(path) {
			t.Errorf("%s is not routed to carrel", path)
		}
	}
	for _, path := range []string{"/functions/v1/agent/state", "/functions/v1/agent/env", "/functions/v1/agent/auth", "/functions/v1/agent/logs", "/functions/v1/agent/report"} {
		if routed(path) {
			t.Errorf("%s is public", path)
		}
	}
}
