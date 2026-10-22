package carrel

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type fakeGitHub map[string]GitHubClaims

func (f fakeGitHub) VerifyGitHub(_ context.Context, token string) (GitHubClaims, error) {
	c, ok := f[token]
	if !ok {
		return GitHubClaims{}, errors.New("bad token")
	}
	return c, nil
}

func push(repo, id, branch string) GitHubClaims {
	return GitHubClaims{Repository: repo, RepositoryID: id, Ref: "refs/heads/" + branch, SHA: "abc123", Event: "push"}
}

func appFixture(t *testing.T) (*Platform, *App, string) {
	t.Helper()
	p, _ := fixture(t)
	p.Config["apps_dir"] = t.TempDir()
	p.Config["apps_disk_headroom_bytes"] = 0
	seedMachine(p, "web", 10100)
	a := NewApp(p, nil)
	a.github = fakeGitHub{
		"good":   push("alice/site", "42", "main"),
		"other":  push("mallory/site", "7", "main"),
		"branch": push("alice/site", "42", "dev"),
		"pr":     {Repository: "alice/site", RepositoryID: "42", Ref: "refs/heads/main", Event: "pull_request"},
		"reborn": push("alice/site", "99", "main"),
	}
	r := a.Call(context.Background(), "app_link", D{"machine": "web", "name": "site", "repo": "Alice/Site", "start": "python3 -m http.server $PORT", "port": 8000}, person("alice", false))
	assertOK(t, r)
	token := regexp.MustCompile(`printf '%s\\n' (cdt_[A-Za-z0-9_-]+) \| sudo sh "\$f"`).FindStringSubmatch(str(r["install"]))
	if token == nil {
		t.Fatalf("install line has no token: %s", r["install"])
	}
	return p, a, token[1]
}

func do(t *testing.T, a *App, method, path, token string, body io.Reader) (int, D) {
	t.Helper()
	req := httptest.NewRequest(method, "https://carrel.test"+path, body)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)
	out := D{}
	if w.Code != 204 && strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
		_ = json.Unmarshal(w.Body.Bytes(), &out)
	}
	if w.Code == 200 && out["ok"] == nil {
		out["body"] = w.Body.String()
	}
	return w.Code, out
}

func upload(t *testing.T, a *App, token, data string) (int, D) {
	return do(t, a, "POST", "/apps/v1/alice/site/releases", token, strings.NewReader(data))
}

func TestAppLinkValidatesAndIsUniquePerMachine(t *testing.T) {
	_, a, _ := appFixture(t)
	ctx, alice := context.Background(), person("alice", false)
	assertCode(t, a.Call(ctx, "app_link", D{"machine": "web", "name": "site", "repo": "alice/x", "start": "x", "port": 8000}, alice), "conflict")
	assertCode(t, a.Call(ctx, "app_link", D{"machine": "web", "name": "second", "repo": "alice/x", "start": "x", "port": 8000}, alice), "conflict")
	assertCode(t, a.Call(ctx, "app_link", D{"machine": "missing", "name": "third", "repo": "alice/x", "start": "x", "port": 8000}, alice), "not_found")
	assertCode(t, a.Call(ctx, "app_link", D{"machine": "web", "name": "bad", "repo": "not a repo", "start": "x", "port": 8000}, alice), "invalid")
	assertCode(t, a.Call(ctx, "app_get", D{"app": "site"}, person("bob", false)), "not_found")
	r := a.Call(ctx, "app_get", D{"app": "site"}, alice)
	assertOK(t, r)
	app := obj(r["app"])
	if app["agent"] != "not_installed" || app["repo"] != "alice/site" || app["branch"] != "main" || app["agent_token"] != nil {
		t.Fatalf("unexpected app: %s", encoded(app))
	}
}

func TestReleaseUploadChecksRepositoryBranchAndEvent(t *testing.T) {
	_, a, _ := appFixture(t)
	for _, token := range []string{"", "nope", "other", "branch", "pr"} {
		if code, _ := upload(t, a, token, "x"); code != 403 {
			t.Fatalf("token %q got %d", token, code)
		}
	}
	if code, _ := do(t, a, "POST", "/apps/v1/alice/missing/releases", "good", strings.NewReader("x")); code != 404 {
		t.Fatalf("missing app got %d", code)
	}
	code, out := upload(t, a, "good", "artifact")
	if code != 200 || obj(out["release"])["state"] != "pending" {
		t.Fatalf("upload failed: %d %s", code, encoded(out))
	}
	if code, _ := upload(t, a, "reborn", "artifact"); code != 403 {
		t.Fatalf("recreated repository deployed: %d", code)
	}
	id := str(obj(out["release"])["id"])
	if code, out := do(t, a, "GET", "/apps/v1/alice/site/releases/"+id, "good", nil); code != 200 || obj(out["release"])["agent"] != "not_installed" {
		t.Fatalf("status failed: %d %s", code, encoded(out))
	}
	if code, _ := do(t, a, "GET", "/apps/v1/alice/site/releases/"+id, "other", nil); code != 403 {
		t.Fatal("another repository read release status")
	}
}

func TestReleaseUploadRespectsImagesQuota(t *testing.T) {
	p, a, _ := appFixture(t)
	p.Store.Exec("UPDATE tenants SET quota=? WHERE n=1", string(encoded(merge(DefaultQuota, D{"images_gb": 0}))))
	if code, out := upload(t, a, "good", "artifact"); code != 409 || obj(out["error"])["code"] != "quota_exceeded" {
		t.Fatalf("quota not enforced: %d %s", code, encoded(out))
	}
	entries, _ := os.ReadDir(p.appsDir() + "/1-site")
	if len(entries) != 0 {
		t.Fatalf("rejected upload left %d files", len(entries))
	}
}

func TestAgentDeploysReportsAndRollsBack(t *testing.T) {
	p, a, agent := appFixture(t)
	ctx, alice := context.Background(), person("alice", false)
	if code, _ := do(t, a, "POST", "/apps/v1/agent/next", "cdt_wrong", nil); code != 403 {
		t.Fatal("wrong agent token accepted")
	}
	deploy := func(data string) string {
		_, out := upload(t, a, "good", data)
		id := str(obj(out["release"])["id"])
		code, next := do(t, a, "POST", "/apps/v1/agent/next", agent, nil)
		if code != 200 || obj(next["release"])["id"] != id {
			t.Fatalf("agent did not receive %s: %d %s", id, code, encoded(next))
		}
		code, file := do(t, a, "GET", "/apps/v1/agent/releases/"+id, agent, nil)
		if code != 200 || file["body"] != data {
			t.Fatalf("download failed: %d %s", code, encoded(file))
		}
		for _, state := range []string{"deploying", "live"} {
			if code, _ := do(t, a, "POST", "/apps/v1/agent/report", agent, strings.NewReader(`{"release":"`+id+`","state":"`+state+`"}`)); code != 200 {
				t.Fatalf("report %s failed: %d", state, code)
			}
		}
		return id
	}
	first, second := deploy("one"), deploy("two")
	app := obj(a.Call(ctx, "app_get", D{"app": "site"}, alice)["app"])
	if app["current"] != second || app["previous"] != first || app["agent"] != "connected" || app["pending"] != nil {
		t.Fatalf("unexpected state: %s", encoded(app))
	}
	assertOK(t, a.Call(ctx, "app_rollback", D{"app": "site"}, alice))
	_, next := do(t, a, "POST", "/apps/v1/agent/next", agent, nil)
	if obj(next["release"])["id"] != first {
		t.Fatalf("rollback not offered: %s", encoded(next))
	}
	body := `{"release":"` + first + `","state":"failed","error":"health check failed","log":"boom"}`
	do(t, a, "POST", "/apps/v1/agent/report", agent, strings.NewReader(body))
	rs := dicts(obj(a.Call(ctx, "app_get", D{"app": "site"}, alice)["app"])["releases"])
	failed := find(rs, func(r D) bool { return r["id"] == first })
	if failed["state"] != "failed" || failed["log"] != "boom" {
		t.Fatalf("failure not recorded: %s", encoded(failed))
	}
	_ = p
}

func TestAgentPollWaitsThenReturnsNothing(t *testing.T) {
	p, _, agent := appFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	if r := p.AgentNext(ctx, agent); r != nil {
		t.Fatalf("unexpected release: %s", encoded(r))
	}
}

func TestReleasesArePruned(t *testing.T) {
	p, a, agent := appFixture(t)
	ids := []string{}
	for i := 0; i < 5; i++ {
		_, out := upload(t, a, "good", "artifact")
		ids = append(ids, str(obj(out["release"])["id"]))
		time.Sleep(2 * time.Millisecond)
	}
	if n := len(p.Store.Objects("releases", 1)); n != keptReleases {
		t.Fatalf("kept %d releases", n)
	}
	if code, _ := do(t, a, "GET", "/apps/v1/agent/releases/"+ids[0], agent, nil); code != 404 {
		t.Fatal("pruned release still served")
	}
}

func TestUnlinkRevokesAgentAndDeletesReleases(t *testing.T) {
	p, a, agent := appFixture(t)
	ctx, alice := context.Background(), person("alice", false)
	upload(t, a, "good", "artifact")
	assertCode(t, a.Call(ctx, "app_unlink", D{"app": "site", "confirm": "wrong"}, alice), "invalid")
	assertOK(t, a.Call(ctx, "app_unlink", D{"app": "site", "confirm": "site"}, alice))
	if code, _ := do(t, a, "POST", "/apps/v1/agent/next", agent, nil); code != 403 {
		t.Fatal("agent token survived unlink")
	}
	if _, err := os.Stat(p.appsDir() + "/1-site"); !os.IsNotExist(err) {
		t.Fatal("release files survived unlink")
	}
	if len(p.Store.Objects("releases", 1)) != 0 {
		t.Fatal("release records survived unlink")
	}
}

func TestSuspendedTenantCannotDeploy(t *testing.T) {
	p, a, agent := appFixture(t)
	p.Store.Exec("UPDATE tenants SET status='suspended' WHERE n=1")
	if code, _ := upload(t, a, "good", "artifact"); code != 404 {
		t.Fatalf("suspended tenant upload got %d", code)
	}
	if code, _ := do(t, a, "POST", "/apps/v1/agent/next", agent, nil); code != 403 {
		t.Fatal("suspended tenant agent accepted")
	}
}

func TestGitHubVerifierChecksSignatureAudienceAndClaims(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e := big.NewInt(int64(key.E)).Bytes()
		jsonResponse(w, 200, D{"keys": []D{{"kid": "k1", "kty": "RSA", "alg": "RS256", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(e)}}})
	}))
	defer jwks.Close()
	v := NewGitHubVerifier("carrel.test")
	v.JWKS = jwks.URL
	sign := func(claims jwt.MapClaims, k *rsa.PrivateKey) string {
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = "k1"
		s, err := token.SignedString(k)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	claims := func(aud string) jwt.MapClaims {
		return jwt.MapClaims{"iss": githubIssuer, "aud": aud, "exp": time.Now().Add(time.Minute).Unix(), "iat": time.Now().Unix(), "repository": "Alice/Site", "repository_id": "42", "ref": "refs/heads/main", "sha": "abc", "event_name": "push", "run_id": "9"}
	}
	c, err := v.VerifyGitHub(context.Background(), sign(claims("carrel.test"), key))
	if err != nil || c.Repository != "alice/site" || c.RepositoryID != "42" || c.RunURL != "https://github.com/Alice/Site/actions/runs/9" {
		t.Fatalf("valid token rejected: %v %+v", err, c)
	}
	if _, err := v.VerifyGitHub(context.Background(), sign(claims("other.test"), key)); err == nil {
		t.Fatal("wrong audience accepted")
	}
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, err := v.VerifyGitHub(context.Background(), sign(claims("carrel.test"), other)); err == nil {
		t.Fatal("wrong signature accepted")
	}
	missing := claims("carrel.test")
	delete(missing, "repository_id")
	if _, err := v.VerifyGitHub(context.Background(), sign(missing, key)); err == nil {
		t.Fatal("token without repository_id accepted")
	}
}

func TestOneUploadPerAppAtATime(t *testing.T) {
	_, a, _ := appFixture(t)
	reader, writer := io.Pipe()
	done := make(chan int)
	go func() {
		req := httptest.NewRequest("POST", "https://carrel.test/apps/v1/alice/site/releases", reader)
		req.Header.Set("Authorization", "Bearer good")
		w := httptest.NewRecorder()
		a.ServeHTTP(w, req)
		done <- w.Code
	}()
	writer.Write([]byte("partial"))
	deadline := time.Now().Add(2 * time.Second)
	for {
		code, out := upload(t, a, "good", "second")
		if code == 409 && obj(out["error"])["code"] == "conflict" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("second upload was not refused: %d %s", code, encoded(out))
		}
		time.Sleep(20 * time.Millisecond)
	}
	writer.Close()
	if code := <-done; code != 200 {
		t.Fatalf("first upload failed: %d", code)
	}
	if code, _ := upload(t, a, "good", "third"); code != 200 {
		t.Fatalf("upload after the first finished got %d", code)
	}
}

func TestLiveReportClearsPendingWithoutDeploying(t *testing.T) {
	p, a, agent := appFixture(t)
	_, out := upload(t, a, "good", "one")
	id := str(obj(out["release"])["id"])
	do(t, a, "POST", "/apps/v1/agent/report", agent, strings.NewReader(`{"release":"`+id+`","state":"live"}`))
	if app := p.Store.Get("apps", "1-site"); app["pending"] != nil || app["current"] != id {
		t.Fatalf("pending not cleared: %s", encoded(app))
	}
}

func TestInstallKeepsStartCommandReadableByTheAppUser(t *testing.T) {
	if !strings.Contains(appsInstallScript, "ExecStart=/bin/sh /etc/carrel-app/$app.start") || !strings.Contains(appsInstallScript, `chmod 0644 "/etc/carrel-app/$app.start"`) {
		t.Fatal("app unit must read its start command from the world-readable /etc/carrel-app")
	}
	if strings.Contains(appsInstallScript, `>"/etc/carrel-deployd/$app.start"`) {
		t.Fatal("start command written into the 0700 token directory")
	}
}

func TestWorkflowSnippetDoesNotPackItself(t *testing.T) {
	p, _, _ := appFixture(t)
	w := p.execution(context.Background()).appWorkflow(D{"slug": "alice"}, D{"name": "site", "branch": "main"})
	if !strings.Contains(w, `tar czf "$RUNNER_TEMP/app.tar.gz" --exclude=.git .`) || !strings.Contains(w, "artifact: ${{ runner.temp }}/app.tar.gz") {
		t.Fatalf("workflow packs into its own source tree:\n%s", w)
	}
}
