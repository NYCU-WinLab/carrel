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

type fakeForge map[string]CIClaims

func (f fakeForge) Verify(_ context.Context, token string) (CIClaims, error) {
	c, ok := f[token]
	if !ok {
		return CIClaims{}, errors.New("bad token")
	}
	return c, nil
}

func push(repo, id, branch string) CIClaims {
	return CIClaims{Issuer: githubIssuer, Repository: repo, RepositoryID: id, Ref: "refs/heads/" + branch, SHA: "abc123", Event: "push"}
}

func gitlabPush(issuer, project, id, branch, source string) CIClaims {
	return CIClaims{Issuer: issuer, Repository: project, RepositoryID: id, Ref: "refs/heads/" + branch, SHA: "def456", Event: source}
}

func appFixture(t *testing.T) (*Platform, *App, string) {
	t.Helper()
	p, _ := fixture(t)
	p.Config.AppsDir = t.TempDir()
	noHeadroom := int64(0)
	p.Config.AppsDiskHeadroomBytes = &noHeadroom
	seedMachine(p, "web", 10100)
	a := NewApp(p, nil)
	a.forges = fakeForge{
		"good":   push("alice/site", "42", "main"),
		"other":  push("mallory/site", "7", "main"),
		"branch": push("alice/site", "42", "dev"),
		"pr":     {Issuer: githubIssuer, Repository: "alice/site", RepositoryID: "42", Ref: "refs/heads/main", Event: "pull_request"},
		"reborn": push("alice/site", "99", "main"),
	}
	r := a.Call(context.Background(), "app_link", D{"machine": "web", "name": "site", "repo": "Alice/Site", "start": "python3 -m http.server $PORT", "port": 8000}, person("alice", false))
	assertOK(t, r)
	// The token comes apart from the install line, which must not carry it (issue #33).
	token := str(r["agent_token"])
	if !regexp.MustCompile(`^cdt_[A-Za-z0-9_-]{43}$`).MatchString(token) || strings.Contains(str(r["install"]), token) {
		t.Fatalf("token %q, install line %s", token, r["install"])
	}
	return p, a, token
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
	// Another repository, branch or event reads nothing (#263).
	for _, token := range []string{"other", "branch", "pr"} {
		if code, _ := do(t, a, "GET", "/apps/v1/alice/site/releases/"+id, token, nil); code != 403 {
			t.Fatalf("status by %q: %d", token, code)
		}
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
	c, err := v.Verify(context.Background(), sign(claims("carrel.test"), key))
	if err != nil || c.Repository != "alice/site" || c.RepositoryID != "42" || c.RunURL != "https://github.com/Alice/Site/actions/runs/9" {
		t.Fatalf("valid token rejected: %v %+v", err, c)
	}
	if _, err := v.Verify(context.Background(), sign(claims("other.test"), key)); err == nil {
		t.Fatal("wrong audience accepted")
	}
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, err := v.Verify(context.Background(), sign(claims("carrel.test"), other)); err == nil {
		t.Fatal("wrong signature accepted")
	}
	missing := claims("carrel.test")
	delete(missing, "repository_id")
	if _, err := v.Verify(context.Background(), sign(missing, key)); err == nil {
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

// carrel-deploy defaults to the B09 origin, so a workflow from any other
// site must name its own, or its pushes deploy to B09 (#569 M11).
func TestWorkflowsNameTheirOwnOrigin(t *testing.T) {
	p, _, _ := appFixture(t)
	p.Config.Origin = "https://carrel.staging.test"
	e := p.execution(context.Background())
	for name, w := range map[string]string{
		"app":     e.appWorkflow(D{"slug": "alice"}, D{"name": "site", "branch": "main"}),
		"service": e.serviceWorkflow(D{"slug": "alice"}, D{"name": "fn"}, "alice/fn", "main", false),
		"preview": e.previewWorkflow(D{"slug": "alice"}, D{"name": "fn"}, "alice/fn", "main"),
	} {
		uses := strings.Count(w, "NYCU-WinLab/carrel-deploy@v1")
		if uses == 0 || strings.Count(w, "url: https://carrel.staging.test\n") != uses {
			t.Fatalf("%s workflow does not pass its origin to every deploy step:\n%s", name, w)
		}
	}
}

const labGitLab = "https://gitlab.winlab.test"

func TestGitLabAppIsBoundToItsIssuerAndProject(t *testing.T) {
	p, a, _ := appFixture(t)
	p.Config.GitLabIssuers = []string{gitlabCom, labGitLab}
	seedMachine(p, "lab", 10101)
	ctx, alice := context.Background(), person("alice", false)
	link := func(name, machine, repo string) D {
		return a.Call(ctx, "app_link", D{"machine": machine, "name": name, "repo": repo, "start": "./run", "port": 8000}, alice)
	}
	assertCode(t, link("evil", "lab", "https://gitlab.evil.test/alice/site"), "invalid")
	assertCode(t, link("short", "lab", labGitLab+"/alice"), "invalid")
	r := link("docs", "lab", labGitLab+"/Group/Sub/Docs.git")
	assertOK(t, r)
	app := obj(r["app"])
	if app["forge"] != "gitlab" || app["repo"] != "group/sub/docs" || app["repo_url"] != labGitLab+"/group/sub/docs" || r["workflow_path"] != ".gitlab-ci.yml" {
		t.Fatalf("unexpected app: %s", encoded(r))
	}
	workflow := str(r["workflow"])
	for _, want := range []string{"CARREL_ID_TOKEN:", "aud: carrel.test", `$CI_COMMIT_BRANCH == "main"`, "/apps/v1/deploy.sh | sh -s -- --tenant alice --app docs"} {
		if !strings.Contains(workflow, want) {
			t.Fatalf("workflow lacks %q:\n%s", want, workflow)
		}
	}
	a.forges = fakeForge{
		"push":     gitlabPush(labGitLab, "group/sub/docs", "5", "main", "push"),
		"web":      gitlabPush(labGitLab, "group/sub/docs", "5", "main", "web"),
		"schedule": gitlabPush(labGitLab, "group/sub/docs", "5", "main", "schedule"),
		"tag":      {Issuer: labGitLab, Repository: "group/sub/docs", RepositoryID: "5", Ref: "refs/tags/main", Event: "push"},
		"dispatch": gitlabPush(labGitLab, "group/sub/docs", "5", "main", "workflow_dispatch"),
		// The same path on another instance is another project.
		"elsewhere": gitlabPush(gitlabCom, "group/sub/docs", "5", "main", "push"),
		// A GitLab project named like a linked GitHub repository.
		"lookalike": gitlabPush(gitlabCom, "alice/site", "42", "main", "push"),
		"moved":     gitlabPush(labGitLab, "group/sub/docs", "6", "main", "push"),
	}
	send := func(app, token string) int {
		code, _ := do(t, a, "POST", "/apps/v1/alice/"+app+"/releases", token, strings.NewReader("artifact"))
		return code
	}
	for _, token := range []string{"schedule", "tag", "dispatch", "elsewhere"} {
		if code := send("docs", token); code != 403 {
			t.Fatalf("token %q got %d", token, code)
		}
	}
	if code := send("site", "lookalike"); code != 403 {
		t.Fatalf("GitLab token deployed the GitHub app: %d", code)
	}
	code, out := do(t, a, "POST", "/apps/v1/alice/docs/releases", "push", strings.NewReader("artifact"))
	if code != 200 {
		t.Fatalf("push: %d %s", code, encoded(out))
	}
	id := str(obj(out["release"])["id"])
	if code, _ := do(t, a, "GET", "/apps/v1/alice/docs/releases/"+id, "elsewhere", nil); code != 403 {
		t.Fatalf("status from another instance: %d", code)
	}
	if code, _ := do(t, a, "GET", "/apps/v1/alice/docs/releases/"+id, "web", nil); code != 200 {
		t.Fatalf("status: %d", code)
	}
	if code := send("docs", "moved"); code != 403 {
		t.Fatalf("pinned project id ignored: %d", code)
	}
	// The served script carries the origin.
	if code, out := do(t, a, "GET", "/apps/v1/deploy.sh", "", nil); code != 200 || !strings.Contains(str(out["body"]), "url=https://carrel.test") {
		t.Fatalf("deploy.sh: %d", code)
	}
}

func TestGitLabVerifierAndIssuerRouting(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var issuer string
	gitlab := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/discovery/keys" {
			http.NotFound(w, r)
			return
		}
		e := big.NewInt(int64(key.E)).Bytes()
		jsonResponse(w, 200, D{"keys": []D{{"kid": "k1", "kty": "RSA", "alg": "RS256", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(e)}}})
	}))
	defer gitlab.Close()
	issuer = gitlab.URL
	v := NewForgeVerifier("carrel.test", []string{issuer})
	sign := func(claims jwt.MapClaims) string {
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = "k1"
		s, err := token.SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	claims := func() jwt.MapClaims {
		return jwt.MapClaims{"iss": issuer, "aud": "carrel.test", "exp": time.Now().Add(time.Minute).Unix(), "iat": time.Now().Unix(), "project_path": "Group/Sub/Docs", "project_id": "5", "ref": "main", "ref_type": "branch", "ref_path": "refs/heads/main", "sha": "abc", "pipeline_source": "push", "job_id": "77"}
	}
	c, err := v.Verify(context.Background(), sign(claims()))
	if err != nil || c.Issuer != issuer || c.Repository != "group/sub/docs" || c.RepositoryID != "5" || c.Ref != "refs/heads/main" || c.Event != "push" || c.RunURL != issuer+"/Group/Sub/Docs/-/jobs/77" || c.Forge() != forgeGitLab {
		t.Fatalf("valid token rejected: %v %+v", err, c)
	}
	old := claims()
	delete(old, "ref_path")
	if c, err := v.Verify(context.Background(), sign(old)); err != nil || c.Ref != "refs/heads/main" {
		t.Fatalf("token without ref_path: %v %+v", err, c)
	}
	untrusted := claims()
	untrusted["iss"] = "https://gitlab.evil.test"
	if _, err := v.Verify(context.Background(), sign(untrusted)); err == nil {
		t.Fatal("untrusted issuer accepted")
	}
	audience := claims()
	audience["aud"] = "other.test"
	if _, err := v.Verify(context.Background(), sign(audience)); err == nil {
		t.Fatal("wrong audience accepted")
	}
	protected := claims()
	protected["ref_protected"] = "true"
	if c, err := v.Verify(context.Background(), sign(protected)); err != nil || !c.RefProtected {
		t.Fatalf("ref_protected not read: %v %+v", err, c)
	}
	if c, _ := v.Verify(context.Background(), sign(claims())); c.RefProtected {
		t.Fatal("a token without ref_protected counted as protected")
	}
	missing := claims()
	delete(missing, "project_id")
	if _, err := v.Verify(context.Background(), sign(missing)); err == nil {
		t.Fatal("token without project_id accepted")
	}
}

func TestGitLabIssuersConfig(t *testing.T) {
	if c := (Config{}).WithDefaults(); len(c.GitLabIssuers) != 1 || c.GitLabIssuers[0] != gitlabCom {
		t.Fatalf("default issuers: %v", c.GitLabIssuers)
	}
	base := Config{PublicAddress: "192.0.2.1", Origin: "https://carrel.winlab.tw", Database: "x", Nodes: []NodeConfig{{Name: "pve1", Target: "pve1"}}}
	for _, bad := range []string{"http://gitlab.test", "https://gitlab.test/", "gitlab.test", "https://u:p@gitlab.test", githubIssuer, "https://GitLab.test", "https://gitlab.test?", "https://gitlab.test/#", "https://gitlab.test/a/../b"} {
		c := base
		c.GitLabIssuers = []string{bad}
		if c.WithDefaults().Validate() == nil {
			t.Fatalf("issuer %q accepted", bad)
		}
	}
	c := base
	c.GitLabIssuers = []string{"https://gitlab.winlab.tw", "https://git.example.org/gitlab"}
	if err := c.WithDefaults().Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestParseRepoPrefersTheLongestIssuer(t *testing.T) {
	issuers := []string{"https://x.test", "https://x.test/gitlab"}
	if issuer, path := parseRepo("https://x.test/gitlab/a/b", issuers); issuer != "https://x.test/gitlab" || path != "a/b" {
		t.Fatalf("got %s %s", issuer, path)
	}
	if issuer, path := parseRepo("https://x.test/a/b", issuers); issuer != "https://x.test" || path != "a/b" {
		t.Fatalf("got %s %s", issuer, path)
	}
	for _, bad := range []string{"owner/.", "owner/..", "https://github.com/owner/.."} {
		if err := attempt(func() { parseRepo(bad, issuers) }); err == nil {
			t.Fatalf("%s accepted", bad)
		}
	}
}

func TestProtectedOnlyNeedsAProtectedRef(t *testing.T) {
	p, a, _ := appFixture(t)
	p.Config.GitLabIssuers = []string{labGitLab}
	seedMachine(p, "lab", 10101)
	ctx, alice := context.Background(), person("alice", false)
	assertCode(t, a.Call(ctx, "app_link", D{"machine": "lab", "name": "gh", "repo": "alice/other", "start": "./run", "port": 8000, "protected_only": true}, alice), "invalid")
	assertCode(t, a.Call(ctx, "app_link", D{"machine": "lab", "name": "pl", "repo": "https://git.example.org/a/b.git", "mode": "pull", "start": "./run", "port": 8000, "protected_only": true}, alice), "invalid")
	r := a.Call(ctx, "app_link", D{"machine": "lab", "name": "docs", "repo": labGitLab + "/group/docs", "start": "./run", "port": 8000, "protected_only": true}, alice)
	assertOK(t, r)
	if obj(r["app"])["protected_only"] != true {
		t.Fatalf("app: %s", encoded(r))
	}
	open, closed := gitlabPush(labGitLab, "group/docs", "5", "main", "push"), gitlabPush(labGitLab, "group/docs", "5", "main", "push")
	closed.RefProtected = true
	a.forges = fakeForge{"open": open, "closed": closed}
	if code, _ := do(t, a, "POST", "/apps/v1/alice/docs/releases", "open", strings.NewReader("artifact")); code != 403 {
		t.Fatalf("unprotected ref deployed: %d", code)
	}
	if code, out := do(t, a, "POST", "/apps/v1/alice/docs/releases", "closed", strings.NewReader("artifact")); code != 200 {
		t.Fatalf("protected ref refused: %d %s", code, encoded(out))
	}
}
