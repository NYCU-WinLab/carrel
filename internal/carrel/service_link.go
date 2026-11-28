package carrel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// service_link binds a GitHub repository branch to a service (PLAN 7.11),
// the way app_link does for a machine (PLAN 7.9). The workflow builds and
// pushes the image in GitHub Actions, then NYCU-WinLab/carrel-deploy sends its
// digest with the job's OIDC token. carrel checks the token as for an app and
// builds a version from the service's current settings with that image. The
// repository holds no carrel secret.

// pinnedImageRE is an image named by its digest: a push deploys exactly the
// image its job built, never whatever a tag points at later.
var pinnedImageRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._/:-]{0,254}@sha256:[a-f0-9]{64}$`)

const maxServiceDeployBody = 4 << 10

func (e *Execution) serviceLink(a, t D) D {
	n, dry := integer(t["n"]), boolean(a["dry_run"])
	f := e.Service(t, a["service"])
	if boolean(a["clear"]) {
		was := f["repo"]
		if !dry {
			delete(f, "repo")
			delete(f, "branch")
			delete(f, "repo_id")
			delete(f, "previews")
			e.Put("services", f["id"], n, f)
			e.removePreviews(e.previewsOf(f))
		}
		return D{"dry_run": dry, "service": f["name"], "unlinked": was}
	}
	repo, branch := strings.ToLower(str(a["repo"])), textAt(a, "branch", "main")
	if repo == "" {
		fail("invalid", "Give repo, the GitHub owner/name, or clear")
	}
	if f["preview_of"] != nil {
		fail("invalid", "A preview is not linked; link the service it previews")
	}
	previews := boolean(a["previews"])
	if !dry {
		// Another repository starts unpinned; the same one keeps its id.
		moved := f["repo"] != repo
		if moved {
			delete(f, "repo_id")
		}
		f["repo"], f["branch"] = repo, branch
		if previews {
			f["previews"] = true
		} else {
			delete(f, "previews")
		}
		e.Put("services", f["id"], n, f)
		// Previews of another repository's pull requests, or of a link
		// without previews, go.
		if !previews || moved {
			e.removePreviews(e.previewsOf(f))
		}
	}
	return D{
		"dry_run": dry, "service": f["name"], "repo": repo, "branch": branch, "previews": previews,
		"workflow":    e.serviceWorkflow(t, f, repo, branch, previews),
		"next_action": "Commit workflow to .github/workflows/carrel.yml on " + branch + ". Each push builds the image, pushes it to ghcr.io and deploys it as a new version with this service's settings. A ghcr.io package is private by default: make it public in its package settings, or give the service credentials with service_registry (registry ghcr.io) before the first push.",
	}
}

func (e *Execution) serviceWorkflow(t, f D, repo, branch string, previews bool) string {
	if previews {
		return e.previewWorkflow(t, f, repo, branch)
	}
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
      - uses: NYCU-WinLab/carrel-deploy@v2
        with:
          url: %s
          tenant: %s
          service: %s
          image: ghcr.io/%s@${{ steps.image.outputs.digest }}
`, branch, f["name"], repo, e.P.appOrigin(), t["slug"], f["name"], repo)
}

// serviceBySlug finds a service by its tenant's slug for a deploy from
// GitHub. An unknown, suspended or unlinked one looks the same.
func (e *Execution) serviceBySlug(slug, name string) (D, D) {
	t := find(e.S.Tenants(), func(t D) bool { return t["slug"] == slug })
	// One answer for an unknown tenant, service or link: a GitHub token
	// learns nothing about who exists.
	if t == nil || t["status"] != "active" {
		fail("not_found", "Service not found or not linked to a repository; call service_link")
	}
	f := e.S.Get("services", serviceID(integer(t["n"]), name))
	if f == nil || str(f["repo"]) == "" {
		fail("not_found", "Service not found or not linked to a repository; call service_link")
	}
	return t, f
}

// ReceiveServiceImage builds a version of a linked service from the image a
// GitHub job pushed.
func (p *Platform) ReceiveServiceImage(ctx context.Context, slug, name string, c CIClaims, body io.Reader) D {
	var in struct {
		Image string `json:"image"`
	}
	if json.NewDecoder(io.LimitReader(body, maxServiceDeployBody)).Decode(&in) != nil {
		fail("invalid", "The body must be JSON with image")
	}
	if !pinnedImageRE.MatchString(in.Image) {
		fail("invalid", "image must be named by its digest, such as ghcr.io/owner/app@sha256:<64 hex>")
	}
	e := p.execution(ctx)
	p.writer.Lock()
	defer p.writer.Unlock()
	t, f := e.serviceBySlug(slug, name)
	if isPreviewToken(c) {
		return e.receivePreview(t, f, c, in.Image)
	}
	// Same checks as an app release: repository, its pinned id, branch, event.
	e.authorizeRelease(f, c)
	if str(f["pending"]) != "" {
		fail("conflict", "A build of this service is in progress", D{"pending": f["pending"]})
	}
	var base D
	for _, v := range e.ServiceVersions(f) {
		if v["version"] == f["current"] || (base == nil && str(f["current"]) == "") {
			base = v
		}
	}
	if base == nil {
		fail("conflict", "The service has no version to take its settings from; deploy it once with service_deploy")
	}
	spec := pick(base, serviceSpecKeys...)
	spec["image"] = in.Image
	extra := D{"env": str(base["env"]), "env_keys": base["env_keys"], "sha": c.SHA, "ref": c.Ref, "run_url": c.RunURL}
	n := integer(f["tenant_n"])
	// The first accepted deploy pins the repository id; the version's
	// transaction stores it with the service.
	if f["repo_id"] == nil {
		f["repo_id"] = c.RepositoryID
	}
	r := e.startServiceVersion(t, f, spec, D{}, extra, false)
	e.S.Log(c.Forge()+":"+c.Repository, n, "service_release", D{"service": f["name"], "version": f["pending"], "sha": c.SHA, "image": in.Image}, "ok")
	return D{"version": serviceRelease(f, e.S.Get("service_versions", serviceVersionID(str(f["id"]), str(f["pending"]))), str(f["pending"])), "next_action": r["next_action"]}
}

// serviceRelease is what the deploy action reads of one version: building,
// live once the host serves it, failed with the build's error, or superseded
// when it was removed or another version went live first.
func serviceRelease(f, v D, version string) D {
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

// ServiceImageStatus answers the deploy action's poll for one version.
func (p *Platform) ServiceImageStatus(ctx context.Context, slug, name, version string, c CIClaims) D {
	e := p.execution(ctx)
	t, f := e.serviceBySlug(slug, name)
	if isPreviewToken(c) {
		return e.previewStatus(t, f, c, version)
	}
	// The same checks as the deploy: another branch or event of the linked
	// repository reads nothing.
	e.authorizeRelease(f, c)
	if !serviceVersionRE.MatchString(version) {
		fail("not_found", "Version not found")
	}
	v := e.S.Get("service_versions", serviceVersionID(str(f["id"]), version))
	out := serviceRelease(f, v, version)
	out["host"] = e.serviceHostState(str(f["host"]))
	return out
}
