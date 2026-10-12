package carrel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Apps deploy on push (PLAN 7.9). GitHub Actions uploads a release with an
// OIDC token, and carrel-deployd inside the tenant machine pulls it. carrel
// never connects to the machine; the agent only makes outbound requests.

const (
	githubIssuer    = "https://token.actions.githubusercontent.com"
	maxReleaseBytes = 500 << 20
	keptReleases    = 3
	diskHeadroom    = 2 * GiB
	appAgentWait    = 25 * time.Second
)

func appID(n int, name string) string { return fmt.Sprintf("%d-%s", n, name) }

func (p *Platform) appsDir() string { return textAt(p.Config, "apps_dir", "/var/lib/carrel/apps") }
func (p *Platform) appOrigin() string {
	return strings.TrimRight(textAt(p.Config, "origin", "https://carrel.winlab.tw"), "/")
}
func (p *Platform) releasePath(app, release string) string {
	return filepath.Join(p.appsDir(), app, release+".tar.gz")
}

func (e *Execution) App(t D, name any) D {
	a := e.S.Get("apps", appID(integer(t["n"]), str(name)))
	if a == nil {
		fail("not_found", "App not found in this tenant")
	}
	return a
}

func (e *Execution) Releases(app D) []D {
	rs := filter(e.S.Objects("releases", integer(app["tenant_n"])), func(r D) bool { return r["app"] == app["id"] })
	sort.Slice(rs, func(i, j int) bool { return num(rs[i]["created_at"]) > num(rs[j]["created_at"]) })
	return rs
}

func publicRelease(r D) D {
	return pick(r, "id", "sha", "ref", "run_url", "size", "sha256", "state", "created_at", "deployed_at", "error", "log")
}

func (e *Execution) PublicApp(app D) D {
	out := pick(app, "name", "machine", "repo", "branch", "start", "port", "created_at", "current", "previous", "pending")
	seen := num(app["agent_seen_at"])
	switch {
	case seen == 0:
		out["agent"] = "not_installed"
	case now()-seen > 90:
		out["agent"] = "agent_offline"
	default:
		out["agent"] = "connected"
	}
	out["repository_pinned"] = app["repo_id"] != nil
	rs := []D{}
	for _, r := range e.Releases(app) {
		rs = append(rs, publicRelease(r))
	}
	out["releases"] = rs
	return out
}

func (e *Execution) AppTool(tool string, a, t D) D {
	dry, n := boolean(a["dry_run"]), integer(t["n"])
	switch tool {
	case "app_list":
		out := []D{}
		for _, app := range e.S.Objects("apps", n) {
			out = append(out, e.PublicApp(app))
		}
		return D{"apps": out}
	case "app_get":
		return D{"app": e.PublicApp(e.App(t, a["app"]))}
	case "app_link":
		m := e.Machine(t, a["machine"])
		name := str(a["name"])
		if e.S.Get("apps", appID(n, name)) != nil {
			fail("conflict", "An app with this name already exists; unlink it first")
		}
		if find(e.S.Objects("apps", n), func(o D) bool { return integer(o["vmid"]) == integer(m["vmid"]) }) != nil {
			fail("conflict", "This machine already runs an app; use another machine or unlink the existing app")
		}
		app := D{"id": appID(n, name), "name": name, "tenant_n": n, "vmid": m["vmid"], "machine": m["name"], "repo": strings.ToLower(str(a["repo"])), "branch": textAt(a, "branch", "main"), "start": a["start"], "port": integer(a["port"]), "created_at": now()}
		r := D{"dry_run": dry, "quota_after": e.Quota(t)}
		if dry {
			r["app"] = without(app, "tenant_n", "vmid")
			return r
		}
		token := "cdt_" + random(32)
		app["agent_token"] = digest(token)
		e.Put("apps", app["id"], n, app)
		r["app"] = e.PublicApp(app)
		r["install"] = e.appInstall(t, app, token)
		r["workflow"] = e.appWorkflow(t, app)
		r["next_steps"] = []string{
			"Run install on the machine over SSH; it needs sudo.",
			"Commit workflow to .github/workflows/carrel.yml on the linked branch and adjust the build step.",
			"Write runtime secrets to /srv/apps/" + name + "/env on the machine; they never pass through carrel.",
			"Publish the port with domain_add when the app should answer on HTTPS.",
		}
		return r
	case "app_deploy", "app_rollback":
		app := e.App(t, a["app"])
		target := str(a["release"])
		if tool == "app_rollback" {
			target = str(app["previous"])
			if target == "" {
				fail("conflict", "No previous release to roll back to")
			}
		}
		r := find(e.Releases(app), func(r D) bool { return r["id"] == target })
		if r == nil {
			fail("not_found", "Release not found for this app")
		}
		if _, err := os.Stat(e.P.releasePath(str(app["id"]), target)); err != nil {
			fail("conflict", "Release artifact is no longer stored")
		}
		if !dry {
			app["pending"] = target
			e.Put("apps", app["id"], n, app)
			r["state"], r["error"], r["log"] = "pending", nil, nil
			e.Put("releases", r["id"], n, r)
		}
		return D{"dry_run": dry, "quota_after": e.Quota(t), "release": publicRelease(r), "state": "pending"}
	case "app_unlink":
		app := e.App(t, a["app"])
		if a["confirm"] != app["name"] {
			fail("invalid", "confirm must equal the app name")
		}
		if !dry {
			e.removeApps([]D{app})
		}
		return D{"dry_run": dry, "quota_after": e.Quota(t), "unlinked": D{"name": app["name"], "machine_unchanged": true}}
	}
	fail("invalid", "Unknown tool")
	return nil
}

// removeApps deletes app records, their releases and stored artifacts. The
// machine keeps whatever was deployed; the revoked token stops its agent.
func (e *Execution) removeApps(apps []D) {
	e.Transaction(func(tx *Execution) {
		for _, app := range apps {
			for _, r := range tx.Releases(app) {
				tx.S.Remove("releases", r["id"])
			}
			tx.S.Remove("apps", app["id"])
		}
	})
	for _, app := range apps {
		_ = os.RemoveAll(filepath.Join(e.P.appsDir(), str(app["id"])))
	}
}

func (e *Execution) appInstall(t D, app D, token string) string {
	return fmt.Sprintf("curl -fsSL %s/apps/v1/install.sh | sudo CARREL_APP_TOKEN=%s sh -s -- --app %s --port %d --user \"$USER\" --start %s",
		e.P.appOrigin(), token, app["name"], integer(app["port"]), shellQuote(str(app["start"])))
}

func (e *Execution) appWorkflow(t D, app D) string {
	return fmt.Sprintf(`name: carrel
on:
  push:
    branches: [%s]
  workflow_dispatch:
permissions:
  contents: read
  id-token: write
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      # Replace with the real build; pack exactly what the start command runs.
      - run: tar czf "$RUNNER_TEMP/app.tar.gz" --exclude=.git .
      - uses: NYCU-WinLab/carrel-deploy@v1
        with:
          tenant: %s
          app: %s
          artifact: ${{ runner.temp }}/app.tar.gz
`, app["branch"], t["slug"], app["name"])
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'" }

// GitHub OIDC

type GitHubClaims struct {
	Repository   string
	RepositoryID string
	Ref          string
	SHA          string
	Event        string
	RunURL       string
}

type OIDCVerifier interface {
	VerifyGitHub(context.Context, string) (GitHubClaims, error)
}

type GitHubVerifier struct{ *Verifier }

func NewGitHubVerifier(audience string) *GitHubVerifier {
	return &GitHubVerifier{&Verifier{Issuer: githubIssuer, Audience: audience, JWKS: githubIssuer + "/.well-known/jwks", HTTP: &http.Client{Timeout: 8 * time.Second}}}
}

func (v *GitHubVerifier) VerifyGitHub(ctx context.Context, token string) (GitHubClaims, error) {
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (any, error) { return v.key(ctx, str(t.Header["kid"])) }, jwt.WithValidMethods([]string{"RS256"}), jwt.WithAudience(v.Audience), jwt.WithIssuer(v.Issuer), jwt.WithExpirationRequired(), jwt.WithLeeway(10*time.Second))
	if err != nil {
		return GitHubClaims{}, err
	}
	c := GitHubClaims{Repository: strings.ToLower(str(claims["repository"])), RepositoryID: str(claims["repository_id"]), Ref: str(claims["ref"]), SHA: str(claims["sha"]), Event: str(claims["event_name"])}
	if c.Repository == "" || c.RepositoryID == "" || c.Ref == "" {
		return GitHubClaims{}, errors.New("missing repository claims")
	}
	if id := str(claims["run_id"]); id != "" {
		c.RunURL = "https://github.com/" + str(claims["repository"]) + "/actions/runs/" + id
	}
	return c, nil
}

// authorizeRelease checks a GitHub token against the app it targets. The
// first accepted deploy pins repository_id, so a deleted and recreated
// repository with the same name cannot deploy afterwards.
func (e *Execution) authorizeRelease(app D, c GitHubClaims) {
	if c.Repository != app["repo"] {
		fail("forbidden", "Token repository does not match the linked repository")
	}
	if pinned := str(app["repo_id"]); pinned != "" && pinned != c.RepositoryID {
		fail("forbidden", "Token repository id does not match the linked repository")
	}
	if c.Ref != "refs/heads/"+str(app["branch"]) {
		fail("forbidden", "Only the linked branch can deploy")
	}
	if c.Event != "push" && c.Event != "workflow_dispatch" {
		fail("forbidden", "Only push and workflow_dispatch events can deploy")
	}
}

func (e *Execution) appBySlug(slug, name string) D {
	t := find(e.S.Tenants(), func(t D) bool { return t["slug"] == slug })
	if t == nil || t["status"] != "active" {
		fail("not_found", "App not found")
	}
	app := e.S.Get("apps", appID(integer(t["n"]), name))
	if app == nil {
		fail("not_found", "App not found")
	}
	return app
}

// storedBytes is the size of all stored artifacts of a tenant. They count
// against images_gb (PLAN 7.9).
func (e *Execution) storedBytes(n int) float64 {
	total := 0.0
	for _, r := range e.S.Objects("releases", n) {
		total += num(r["size"])
	}
	return total
}

// reserveUpload holds space for one upload before any byte is written: one
// upload per app, the tenant's images_gb including uploads in flight, and
// free disk under apps_dir after every reservation.
func (p *Platform) reserveUpload(e *Execution, app D, size int64) func() {
	n, id := integer(app["tenant_n"]), str(app["id"])
	p.uploadMu.Lock()
	defer p.uploadMu.Unlock()
	if p.uploads == nil {
		p.uploads = map[string]int64{}
	}
	if _, busy := p.uploads[id]; busy {
		fail("conflict", "Another upload for this app is in progress")
	}
	var tenant, all int64
	for key, v := range p.uploads {
		all += v
		if strings.HasPrefix(key, fmt.Sprintf("%d-", n)) {
			tenant += v
		}
	}
	t := e.S.TenantN(n)
	if limit := num(obj(t["quota"])["images_gb"]) * GiB; e.storedBytes(n)+float64(tenant+size) > limit {
		fail("quota_exceeded", "Stored releases would exceed images_gb", D{"dimension": "images_gb"})
	}
	must(os.MkdirAll(p.appsDir(), 0700))
	var fs syscall.Statfs_t
	must(syscall.Statfs(p.appsDir(), &fs))
	headroom := int64(num(fallback(p.Config, "apps_disk_headroom_bytes", float64(diskHeadroom))))
	if free := int64(fs.Bavail) * int64(fs.Bsize); free-all-size < headroom {
		fail("capacity_exhausted", "carrel has no room for this release now")
	}
	p.uploads[id] = size
	return func() {
		p.uploadMu.Lock()
		delete(p.uploads, id)
		p.uploadMu.Unlock()
	}
}

func (p *Platform) ReceiveRelease(ctx context.Context, slug, name string, c GitHubClaims, length int64, body io.Reader) D {
	e := p.execution(ctx)
	var app D
	func() {
		p.writer.Lock()
		defer p.writer.Unlock()
		app = e.appBySlug(slug, name)
		e.authorizeRelease(app, c)
	}()
	n := integer(app["tenant_n"])
	size := int64(maxReleaseBytes)
	if length > maxReleaseBytes {
		fail("invalid", "Release exceeds 500 MB")
	}
	if length > 0 {
		size = length
	}
	defer p.reserveUpload(e, app, size)()
	id := randomID()[:16]
	dir := filepath.Join(p.appsDir(), str(app["id"]))
	must(os.MkdirAll(dir, 0700))
	tmp, err := os.CreateTemp(dir, ".upload-*")
	must(err)
	defer os.Remove(tmp.Name())
	h := sha256.New()
	written, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(body, size+1))
	closeErr := tmp.Close()
	if err != nil || closeErr != nil {
		fail("invalid", "Upload did not complete")
	}
	if written > size {
		fail("invalid", "Release is larger than declared or exceeds 500 MB")
	}
	if written == 0 {
		fail("invalid", "Release is empty")
	}
	p.writer.Lock()
	defer p.writer.Unlock()
	app = e.appBySlug(slug, name)
	e.authorizeRelease(app, c)
	t := e.S.TenantN(n)
	if limit := num(obj(t["quota"])["images_gb"]) * GiB; e.storedBytes(n)+float64(written) > limit {
		fail("quota_exceeded", "Stored releases would exceed images_gb", D{"dimension": "images_gb"})
	}
	must(os.Rename(tmp.Name(), p.releasePath(str(app["id"]), id)))
	r := D{"id": id, "app": app["id"], "vmid": app["vmid"], "sha": c.SHA, "ref": c.Ref, "run_url": c.RunURL, "size": written, "sha256": hex.EncodeToString(h.Sum(nil)), "state": "pending", "created_at": now()}
	e.Transaction(func(tx *Execution) {
		tx.S.Put("releases", id, n, r)
		if app["repo_id"] == nil {
			app["repo_id"] = c.RepositoryID
		}
		app["pending"] = id
		tx.S.Put("apps", app["id"], n, app)
	})
	e.pruneReleases(app)
	e.S.Log("github:"+c.Repository, n, "app_release", D{"app": app["name"], "release": id, "sha": c.SHA, "size": written}, "ok")
	return publicRelease(r)
}

// pruneReleases keeps the newest releases plus the current and previous ones.
func (e *Execution) pruneReleases(app D) {
	keep := map[string]bool{str(app["current"]): true, str(app["previous"]): true, str(app["pending"]): true}
	for i, r := range e.Releases(app) {
		if i < keptReleases || keep[str(r["id"])] || r["state"] == "deploying" {
			continue
		}
		e.S.Remove("releases", r["id"])
		_ = os.Remove(e.P.releasePath(str(app["id"]), str(r["id"])))
	}
}

func (p *Platform) ReleaseStatus(ctx context.Context, slug, name, id string, c GitHubClaims) D {
	e := p.execution(ctx)
	app := e.appBySlug(slug, name)
	if c.Repository != app["repo"] || (app["repo_id"] != nil && str(app["repo_id"]) != c.RepositoryID) {
		fail("forbidden", "Token repository does not match the linked repository")
	}
	r := e.S.Get("releases", id)
	if r == nil || r["app"] != app["id"] {
		fail("not_found", "Release not found")
	}
	return merge(publicRelease(r), D{"agent": e.PublicApp(app)["agent"]})
}

// Agent side

func (p *Platform) agentApp(token string) D {
	if !strings.HasPrefix(token, "cdt_") {
		fail("forbidden", "Invalid agent token")
	}
	h := digest(token)
	app := find(p.Store.Objects("apps"), func(a D) bool { return secureEqual(str(a["agent_token"]), h) })
	if app == nil {
		fail("forbidden", "Invalid agent token")
	}
	if t := p.Store.TenantN(integer(app["tenant_n"])); t == nil || t["status"] != "active" {
		fail("forbidden", "Tenant is suspended")
	}
	return app
}

func (p *Platform) touchAgent(app D) {
	p.writer.Lock()
	defer p.writer.Unlock()
	current := p.Store.Get("apps", str(app["id"]))
	if current == nil {
		return
	}
	current["agent_seen_at"] = now()
	p.Store.Put("apps", current["id"], integer(current["tenant_n"]), current)
}

// AgentNext long-polls for a pending release. It returns nil when none
// arrives within the wait.
func (p *Platform) AgentNext(ctx context.Context, token string) D {
	app := p.agentApp(token)
	p.touchAgent(app)
	deadline := time.Now().Add(appAgentWait)
	for {
		app = p.Store.Get("apps", str(app["id"]))
		if app == nil {
			fail("forbidden", "App was unlinked")
		}
		if id := str(app["pending"]); id != "" {
			r := p.Store.Get("releases", id)
			if r != nil {
				return D{"release": D{"id": r["id"], "sha": r["sha"], "sha256": r["sha256"], "size": r["size"], "url": p.appOrigin() + "/apps/v1/agent/releases/" + id}}
			}
		}
		if time.Now().After(deadline) || !sleep(ctx, time.Second) {
			return nil
		}
	}
}

func (p *Platform) AgentRelease(token, id string) string {
	app := p.agentApp(token)
	r := p.Store.Get("releases", id)
	if r == nil || r["app"] != app["id"] {
		fail("not_found", "Release not found")
	}
	return p.releasePath(str(app["id"]), id)
}

func (p *Platform) AgentReport(ctx context.Context, token string, body D) D {
	app := p.agentApp(token)
	id, state := str(body["release"]), str(body["state"])
	if !contains([]string{"deploying", "live", "failed"}, state) {
		fail("invalid", "state must be deploying, live or failed")
	}
	p.writer.Lock()
	defer p.writer.Unlock()
	e := p.execution(ctx)
	app = p.Store.Get("apps", str(app["id"]))
	n := integer(app["tenant_n"])
	r := p.Store.Get("releases", id)
	if r == nil || r["app"] != app["id"] {
		fail("not_found", "Release not found")
	}
	r["state"] = state
	app["agent_seen_at"] = now()
	switch state {
	case "deploying":
		if app["pending"] == id {
			app["pending"] = nil
		}
	case "live":
		if app["pending"] == id {
			app["pending"] = nil
		}
		r["deployed_at"], r["error"], r["log"] = now(), nil, nil
		if app["current"] != id {
			if old := p.Store.Get("releases", str(app["current"])); old != nil && old["state"] == "live" {
				old["state"] = "superseded"
				p.Store.Put("releases", old["id"], n, old)
			}
			app["previous"], app["current"] = app["current"], id
		}
	case "failed":
		if app["pending"] == id {
			app["pending"] = nil
		}
		r["error"] = truncate(str(body["error"]), 256)
		r["log"] = truncate(str(body["log"]), 8192)
	}
	e.Transaction(func(tx *Execution) {
		tx.S.Put("releases", id, n, r)
		tx.S.Put("apps", app["id"], n, app)
	})
	e.S.Log("agent:"+str(app["id"]), n, "app_report", D{"app": app["name"], "release": id, "state": state}, "ok")
	return D{"ok": true}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}
