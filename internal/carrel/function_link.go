package carrel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// function_link binds a GitHub repository branch to a function (PLAN 7.11),
// the way app_link does for a machine (PLAN 7.9). The workflow builds and
// pushes the image in GitHub Actions, then NYCU-WinLab/carrel-deploy sends its
// digest with the job's OIDC token. carrel checks the token as for an app and
// builds a version from the function's current settings with that image. The
// repository holds no carrel secret.

// pinnedImageRE is an image named by its digest: a push deploys exactly the
// image its job built, never whatever a tag points at later.
var pinnedImageRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._/:-]{0,254}@sha256:[a-f0-9]{64}$`)

const maxFunctionDeployBody = 4 << 10

func (e *Execution) functionLink(a, t D) D {
	n, dry := integer(t["n"]), boolean(a["dry_run"])
	f := e.Function(t, a["function"])
	if boolean(a["clear"]) {
		was := f["repo"]
		if !dry {
			delete(f, "repo")
			delete(f, "branch")
			delete(f, "repo_id")
			e.Put("functions", f["id"], n, f)
		}
		return D{"dry_run": dry, "function": f["name"], "unlinked": was}
	}
	repo, branch := strings.ToLower(str(a["repo"])), textAt(a, "branch", "main")
	if repo == "" {
		fail("invalid", "Give repo, the GitHub owner/name, or clear")
	}
	if !dry {
		// Another repository starts unpinned; the same one keeps its id.
		if f["repo"] != repo {
			delete(f, "repo_id")
		}
		f["repo"], f["branch"] = repo, branch
		e.Put("functions", f["id"], n, f)
	}
	return D{
		"dry_run": dry, "function": f["name"], "repo": repo, "branch": branch,
		"workflow":    e.functionWorkflow(t, f, repo, branch),
		"next_action": "Commit workflow to .github/workflows/carrel.yml on " + branch + ". Each push builds the image, pushes it to ghcr.io and deploys it as a new version with this function's settings. A ghcr.io package is private by default: make it public in its package settings, or give the function credentials with function_registry (registry ghcr.io) before the first push.",
	}
}

func (e *Execution) functionWorkflow(t, f D, repo, branch string) string {
	return fmt.Sprintf(`name: carrel
on:
  push:
    branches: [%s]
  workflow_dispatch:
permissions:
  contents: read
  packages: write
  id-token: write
# One deploy at a time: a push waits for the build before it.
concurrency: carrel-%s
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      # Buildx reports the digest of the pushed manifest, which the deploy names.
      - uses: docker/setup-buildx-action@v3
      - id: image
        uses: docker/build-push-action@v6
        with:
          push: true
          platforms: linux/amd64
          tags: ghcr.io/%s:${{ github.sha }}
      - uses: NYCU-WinLab/carrel-deploy@v1
        with:
          tenant: %s
          function: %s
          image: ghcr.io/%s@${{ steps.image.outputs.digest }}
`, branch, f["name"], repo, t["slug"], f["name"], repo)
}

// functionBySlug finds a function by its tenant's slug for a deploy from
// GitHub. An unknown, suspended or unlinked one looks the same.
func (e *Execution) functionBySlug(slug, name string) (D, D) {
	t := find(e.S.Tenants(), func(t D) bool { return t["slug"] == slug })
	// One answer for an unknown tenant, function or link: a GitHub token
	// learns nothing about who exists.
	if t == nil || t["status"] != "active" {
		fail("not_found", "Function not found or not linked to a repository; call function_link")
	}
	f := e.S.Get("functions", functionID(integer(t["n"]), name))
	if f == nil || str(f["repo"]) == "" {
		fail("not_found", "Function not found or not linked to a repository; call function_link")
	}
	return t, f
}

// ReceiveFunctionImage builds a version of a linked function from the image a
// GitHub job pushed.
func (p *Platform) ReceiveFunctionImage(ctx context.Context, slug, name string, c GitHubClaims, body io.Reader) D {
	var in struct {
		Image string `json:"image"`
	}
	if json.NewDecoder(io.LimitReader(body, maxFunctionDeployBody)).Decode(&in) != nil {
		fail("invalid", "The body must be JSON with image")
	}
	if !pinnedImageRE.MatchString(in.Image) {
		fail("invalid", "image must be named by its digest, such as ghcr.io/owner/app@sha256:<64 hex>")
	}
	e := p.execution(ctx)
	p.writer.Lock()
	defer p.writer.Unlock()
	t, f := e.functionBySlug(slug, name)
	// Same checks as an app release: repository, its pinned id, branch, event.
	e.authorizeRelease(f, c)
	if str(f["pending"]) != "" {
		fail("conflict", "A build of this function is in progress", D{"pending": f["pending"]})
	}
	var base D
	for _, v := range e.FunctionVersions(f) {
		if v["version"] == f["current"] || (base == nil && str(f["current"]) == "") {
			base = v
		}
	}
	if base == nil {
		fail("conflict", "The function has no version to take its settings from; deploy it once with function_deploy")
	}
	spec := pick(base, functionSpecKeys...)
	spec["image"] = in.Image
	extra := D{"env": str(base["env"]), "env_keys": base["env_keys"], "sha": c.SHA, "ref": c.Ref, "run_url": c.RunURL}
	n := integer(f["tenant_n"])
	// The first accepted deploy pins the repository id; the version's
	// transaction stores it with the function.
	if f["repo_id"] == nil {
		f["repo_id"] = c.RepositoryID
	}
	r := e.startFunctionVersion(t, f, spec, D{}, extra, false)
	e.S.Log("github:"+c.Repository, n, "function_release", D{"function": f["name"], "version": f["pending"], "sha": c.SHA, "image": in.Image}, "ok")
	return D{"version": functionRelease(f, e.S.Get("function_versions", functionVersionID(str(f["id"]), str(f["pending"]))), str(f["pending"])), "next_action": r["next_action"]}
}

// functionRelease is what the deploy action reads of one version: building,
// live once the host serves it, failed with the build's error, or superseded
// when it was removed or another version went live first.
func functionRelease(f, v D, version string) D {
	out := D{"version": version}
	switch {
	case v == nil:
		out["state"] = "superseded"
	case v["state"] == "failed":
		out["state"], out["error"] = "failed", v["error"]
	case v["state"] == "ready" && f["live"] == version:
		out["state"] = "live"
	case v["state"] == "ready" && f["current"] != version:
		out["state"] = "superseded"
	default:
		out["state"] = "building"
	}
	return out
}

// FunctionImageStatus answers the deploy action's poll for one version.
func (p *Platform) FunctionImageStatus(ctx context.Context, slug, name, version string, c GitHubClaims) D {
	e := p.execution(ctx)
	_, f := e.functionBySlug(slug, name)
	if c.Repository != f["repo"] || (f["repo_id"] != nil && str(f["repo_id"]) != c.RepositoryID) {
		fail("forbidden", "Token repository does not match the linked repository")
	}
	if !functionVersionRE.MatchString(version) {
		fail("not_found", "Version not found")
	}
	v := e.S.Get("function_versions", functionVersionID(str(f["id"]), version))
	out := functionRelease(f, v, version)
	out["host"] = e.functionHostState(str(f["host"]))
	return out
}
