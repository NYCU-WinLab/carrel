package carrel

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

const commit = "0123456789abcdef0123456789abcdef01234567"

func TestPullAppBuildsOnTheMachine(t *testing.T) {
	p, a, _ := appFixture(t)
	seedMachine(p, "pull", 10102)
	ctx, alice := context.Background(), person("alice", false)
	link := func(args D) D {
		return a.Call(ctx, "app_link", merge(D{"machine": "pull", "name": "gitea", "mode": "pull", "start": "./run", "port": 8000}, args), alice)
	}
	for _, bad := range []string{"/srv/repo", "file:///srv/repo", "ext::sh -c id", "https://u:p@git.example.org/a/b.git", "https://git.example.org/", "-oProxyCommand=id@host:x"} {
		assertCode(t, link(D{"repo": bad}), "invalid")
	}
	assertCode(t, a.Call(ctx, "app_link", D{"machine": "pull", "name": "x", "repo": "alice/site", "build": "make", "start": "./run", "port": 8000}, alice), "invalid")

	r := link(D{"repo": "git@git.example.org:alice/site.git", "build": "make"})
	assertOK(t, r)
	app, hook, token := obj(r["app"]), str(r["webhook_url"]), str(r["agent_token"])
	if app["mode"] != "pull" || app["repo_url"] != "git@git.example.org:alice/site.git" || app["build"] != "make" || r["workflow"] != nil || !strings.Contains(str(r["install"]), " --pull;") || !strings.HasPrefix(hook, "https://carrel.test/apps/v1/hooks/cdh_") {
		t.Fatalf("unexpected link: %s", encoded(r))
	}
	path := strings.TrimPrefix(hook, "https://carrel.test")

	// The agent learns what to build.
	if code, out := do(t, a, "GET", "/apps/v1/agent/source", token, nil); code != 200 || out["url"] != "git@git.example.org:alice/site.git" || out["branch"] != "main" || out["build"] != "make" {
		t.Fatalf("source: %d %s", code, encoded(out))
	}
	// A webhook call makes the next poll answer at once.
	if code, _ := do(t, a, "POST", "/apps/v1/hooks/cdh_nope", "", strings.NewReader("{}")); code != 404 {
		t.Fatalf("unknown hook: %d", code)
	}
	if code, _ := do(t, a, "POST", path, "", strings.NewReader(`{"ref":"refs/heads/main"}`)); code != 200 {
		t.Fatalf("hook: %d", code)
	}
	if code, out := do(t, a, "POST", "/apps/v1/agent/next", token, nil); code != 200 || out["pull"] != true {
		t.Fatalf("next after hook: %d %s", code, encoded(out))
	}

	// The deploy key's public half shows in app_get.
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl carrel-gitea"
	if code, _ := do(t, a, "POST", "/apps/v1/agent/report", token, strings.NewReader(`{"deploy_key":"ssh-rsa AAAA"}`)); code != 400 {
		t.Fatalf("bad key: %d", code)
	}
	if code, _ := do(t, a, "POST", "/apps/v1/agent/report", token, strings.NewReader(`{"deploy_key":"`+key+`"}`)); code != 200 {
		t.Fatalf("key: %d", code)
	}

	// A failed build is a release with its log and no artifact.
	if code, _ := do(t, a, "POST", "/apps/v1/agent/report", token, strings.NewReader(`{"sha":"`+commit+`","state":"failed","error":"build failed: exit status 2","log":"make: *** [all] Error 2"}`)); code != 200 {
		t.Fatalf("failed build: %d", code)
	}
	got := obj(a.Call(ctx, "app_get", D{"app": "gitea"}, alice)["app"])
	failed := obj(arr(got["releases"])[0])
	if got["deploy_key"] != key || failed["state"] != "failed" || failed["sha"] != commit || !strings.Contains(str(failed["log"]), "Error 2") {
		t.Fatalf("app_get: %s", encoded(got))
	}
	assertCode(t, a.Call(ctx, "app_deploy", D{"app": "gitea", "release": failed["id"]}, alice), "conflict")

	// A good build becomes the pending release, as an upload from CI does.
	upload := func(token, sha string) (int, D) {
		// Larger than the 256 KiB limit on other requests.
		req := httptest.NewRequest("POST", "https://carrel.test/apps/v1/agent/upload", strings.NewReader(strings.Repeat("a", 300<<10)))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("X-Carrel-Sha", sha)
		w := httptest.NewRecorder()
		a.ServeHTTP(w, req)
		out := D{}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	if code, _ := upload(token, "main"); code != 400 {
		t.Fatalf("bad sha: %d", code)
	}
	code, out := upload(token, commit)
	if code != 200 || obj(out["release"])["sha"] != commit || obj(out["release"])["state"] != "pending" {
		t.Fatalf("upload: %d %s", code, encoded(out))
	}
	if code, out := do(t, a, "POST", "/apps/v1/agent/next", token, nil); code != 200 || obj(out["release"])["sha"] != commit {
		t.Fatalf("next release: %d %s", code, encoded(out))
	}
}

func TestPushAppTakesNoAgentUpload(t *testing.T) {
	_, a, token := appFixture(t)
	req := httptest.NewRequest("POST", "https://carrel.test/apps/v1/agent/upload", strings.NewReader("artifact"))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Carrel-Sha", commit)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)
	if w.Code != 403 {
		t.Fatalf("push app took an agent upload: %d", w.Code)
	}
	if code, out := do(t, a, "GET", "/apps/v1/agent/source", token, nil); code != 200 || out["mode"] != "push" {
		t.Fatalf("source: %d %s", code, encoded(out))
	}
	if code, _ := do(t, a, "POST", "/apps/v1/agent/report", token, strings.NewReader(`{"sha":"`+commit+`","state":"failed"}`)); code != 403 {
		t.Fatalf("push app took a build report: %d", code)
	}
}
