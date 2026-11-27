package carrel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"time"
)

// Pull request previews (#645): a function linked with previews on gets one
// more function per open pull request of its repository, named
// pr-<number>-<function> and served at pr-<number>-<function>.<tenant>.winlab.tw
// under the tenant's wildcard certificate. A preview is an ordinary function
// with preview_of set, so versions, logs, events and removal are the ones
// functions have. It never starts from the parent's environment, schedules
// or registry credentials: a pull request runs code nobody has merged.

const (
	maxPreviews = 5
	// previewIdle removes a preview with no deploy for this long, for a
	// pull request whose close never reached carrel.
	previewIdle = 7 * 24 * time.Hour
)

var pullRefRE = regexp.MustCompile(`^refs/pull/([1-9][0-9]{0,8})/merge$`)

// pullNumber is the pull request a token's ref names, or 0. GitHub names it
// on opened, synchronize and an unmerged close; a merged close carries the
// base branch instead.
func pullNumber(c CIClaims) int {
	m := pullRefRE.FindStringSubmatch(c.Ref)
	if m == nil {
		return 0
	}
	n, _ := strconv.Atoi(m[1])
	return n
}

func isPreviewToken(c CIClaims) bool { return c.Issuer == githubIssuer && c.Event == "pull_request" }

// authorizePreview checks a pull_request token against a linked function:
// the same repository, by name and by the id the first push pinned. The
// branch is not checked: every pull request of the repository may preview.
// pull_request_target, which runs with the base repository's rights for a
// fork's code, is refused by the exact event check.
func (e *Execution) authorizePreview(f D, c CIClaims) {
	if !isPreviewToken(c) || c.Repository != f["repo"] || linkIssuer(f) != githubIssuer {
		fail("forbidden", "Token repository does not match the linked repository")
	}
	if !boolean(f["previews"]) {
		fail("forbidden", "Previews are off for this function; call function_link with previews true")
	}
	if pinned := str(f["repo_id"]); pinned == "" || pinned != c.RepositoryID {
		fail("forbidden", "Deploy the linked branch once before previews, so the repository id is pinned")
	}
}

func previewName(pr int, name string) string { return fmt.Sprintf("pr-%d-%s", pr, name) }

// previewsOf are the previews of a function.
func (e *Execution) previewsOf(f D) []D {
	return filter(e.S.Objects("functions", integer(f["tenant_n"])), func(p D) bool { return p["preview_of"] == f["id"] })
}

// previewFor finds or plans the preview of pull request pr. A name taken by
// something other than this function's preview of pr is refused.
func (e *Execution) previewFor(t, f D, pr int, headRef string) (D, bool) {
	n := integer(t["n"])
	name := previewName(pr, str(f["name"]))
	if !functionHostName.MatchString(name) {
		fail("invalid", "The preview name "+name+" is longer than 32 characters; give the function a shorter name")
	}
	if pf := e.S.Get("functions", functionID(n, name)); pf != nil {
		if pf["preview_of"] != f["id"] || integer(pf["pr"]) != pr {
			fail("conflict", "A function named "+name+" exists and is not this pull request's preview")
		}
		return pf, false
	}
	if len(e.previewsOf(f)) >= maxPreviews {
		fail("conflict", fmt.Sprintf("This function has %d previews, the most it may have; close a pull request first", maxPreviews))
	}
	if d, found := domainNamed(e.domains(n), previewHost(t, name)); found && d.Function != functionID(n, name) {
		fail("conflict", "The name "+previewHost(t, name)+" already points elsewhere")
	}
	return D{"id": functionID(n, name), "name": name, "tenant_n": n, "host": f["host"], "seq": 0, "created_at": now(),
		"preview_of": f["id"], "pr": pr, "head_ref": headRef}, true
}

func previewHost(t D, name string) string { return name + "." + str(t["slug"]) + ".winlab.tw" }

// receivePreview builds a version of pull request pr's preview from the
// image its job pushed. The first version takes only the parent's settings.
func (e *Execution) receivePreview(t, f D, c CIClaims, image string) D {
	e.authorizePreview(f, c)
	pr := pullNumber(c)
	if pr == 0 {
		fail("forbidden", "A preview deploys from an opened or updated pull request")
	}
	pf, created := e.previewFor(t, f, pr, c.HeadRef)
	if str(pf["pending"]) != "" {
		fail("conflict", "A build of this preview is in progress", D{"pending": pf["pending"]})
	}
	base := e.S.Get("function_versions", functionVersionID(str(pf["id"]), str(pf["current"])))
	env := D{}
	if base != nil {
		// The preview's own environment, set with function_env, carries on.
		env = D{"env": str(base["env"]), "env_keys": base["env_keys"]}
	} else {
		base = e.S.Get("function_versions", functionVersionID(str(f["id"]), str(f["current"])))
	}
	if base == nil {
		fail("conflict", "The function has no version to take its settings from; deploy it once with function_deploy")
	}
	spec := pick(base, functionSpecKeys...)
	spec["image"] = image
	env["sha"], env["ref"], env["run_url"] = c.SHA, c.Ref, c.RunURL
	n := integer(t["n"])
	delta := D{}
	var domain domainRecord
	if created {
		delta = D{"functions": 1, "domains": 1}
		name := str(pf["name"])
		domain = domainRecord{ID: randomID()[:16], TenantN: n, Function: str(pf["id"]), Sub: name, Slug: str(t["slug"]), Name: previewHost(t, name), State: "queued", ReadyAt: now()}
	}
	pf["head_ref"] = c.HeadRef
	r := e.startFunctionVersion(t, pf, spec, delta, env, false, func(tx *Execution) {
		if created {
			tx.Put("domains", domain.ID, n, domain)
		}
	})
	if created {
		e.P.kickMaintenance()
	}
	e.S.Log(c.Forge()+":"+c.Repository, n, "function_preview", D{"function": pf["name"], "version": pf["pending"], "sha": c.SHA, "image": image}, "ok")
	return D{"version": functionRelease(pf, e.S.Get("function_versions", functionVersionID(str(pf["id"]), str(pf["pending"]))), str(pf["pending"])),
		"preview": D{"function": pf["name"], "url": "https://" + previewHost(t, str(pf["name"]))}, "next_action": r["next_action"]}
}

// previewStatus is FunctionImageStatus for a preview's version.
func (e *Execution) previewStatus(t, f D, c CIClaims, version string) D {
	e.authorizePreview(f, c)
	pf := e.S.Get("functions", functionID(integer(t["n"]), previewName(pullNumber(c), str(f["name"]))))
	if pf == nil || pf["preview_of"] != f["id"] || !functionVersionRE.MatchString(version) {
		fail("not_found", "Version not found")
	}
	out := functionRelease(pf, e.S.Get("function_versions", functionVersionID(str(pf["id"]), version)), version)
	out["host"] = e.functionHostState(str(pf["host"]))
	return out
}

// removePreviews deletes previews and the domains that serve them, then
// wakes the maintenance loop so the gateway drops their routes.
func (e *Execution) removePreviews(previews []D) {
	if len(previews) == 0 {
		return
	}
	ids := map[string]bool{}
	for _, pf := range previews {
		ids[str(pf["id"])] = true
	}
	e.Transaction(func(tx *Execution) {
		for _, d := range tx.domains(integer(previews[0]["tenant_n"])) {
			if ids[d.Function] {
				tx.S.Remove("domains", d.ID)
			}
		}
		tx.dropFunctions(previews)
	})
	e.P.kickMaintenance()
}

// ClosePreview removes the preview of the pull request a closing job names.
// The job sends the number it closes (the action's github.event.pull_request
// .number). An unmerged close's token names the same number; a merged one's
// names only the base branch, so the preview must also have been deployed
// from the token's head branch. A late close of an older pull request on a
// reused branch name names its own number, and so never removes a newer
// pull request's preview.
func (p *Platform) ClosePreview(ctx context.Context, slug, name string, c CIClaims, body io.Reader) D {
	var in struct {
		PR int `json:"pr"`
	}
	if json.NewDecoder(io.LimitReader(body, 1<<10)).Decode(&in) != nil || in.PR <= 0 {
		fail("invalid", "The body must be JSON with pr, the closed pull request's number")
	}
	e := p.execution(ctx)
	p.writer.Lock()
	defer p.writer.Unlock()
	t, f := e.functionBySlug(slug, name)
	e.authorizePreview(f, c)
	if pr := pullNumber(c); pr != 0 && pr != in.PR {
		fail("forbidden", "The token names another pull request")
	}
	gone := filter(e.previewsOf(f), func(pf D) bool {
		return integer(pf["pr"]) == in.PR && (pullNumber(c) != 0 || (c.HeadRef != "" && pf["head_ref"] == c.HeadRef))
	})
	e.removePreviews(gone)
	removed := []any{}
	for _, pf := range gone {
		removed = append(removed, pf["name"])
	}
	e.S.Log(c.Forge()+":"+c.Repository, integer(t["n"]), "function_preview_close", D{"function": f["name"], "removed": removed}, "ok")
	return D{"removed": removed}
}

// ReapPreviews removes previews with no deploy for previewIdle. The caller
// holds the writer.
func (e *Execution) ReapPreviews() {
	for _, t := range e.S.Tenants() {
		stale := filter(e.S.Objects("functions", integer(t["n"])), func(f D) bool {
			last := num(f["deployed_at"])
			if last == 0 {
				last = num(f["created_at"])
			}
			return f["preview_of"] != nil && str(f["pending"]) == "" && now()-last > previewIdle.Seconds()
		})
		e.removePreviews(stale)
	}
}

// previewWorkflow is functionWorkflow with pull request previews: a pull
// request from the repository itself builds into its preview, and its close
// removes it. A fork's pull request gets no OIDC token, so it is skipped.
func (e *Execution) previewWorkflow(t, f D, repo, branch string) string {
	return fmt.Sprintf(`name: carrel
on:
  push:
    branches: [%s]
  pull_request:
    types: [opened, synchronize, reopened, closed]
  workflow_dispatch:
permissions:
  contents: read
  packages: write
  id-token: write
  pull-requests: write
# One deploy at a time per branch or pull request.
concurrency: carrel-%s-${{ github.event.pull_request.number || 'main' }}
jobs:
  deploy:
    if: github.event.action != 'closed' && (github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - uses: docker/setup-buildx-action@v3
      - id: image
        uses: docker/build-push-action@v6
        with:
          push: true
          platforms: linux/amd64
          tags: ghcr.io/%s:${{ github.sha }}
      # On a pull request this deploys the preview and comments its URL.
      - uses: NYCU-WinLab/carrel-deploy@v1
        with:
          tenant: %s
          function: %s
          image: ghcr.io/%s@${{ steps.image.outputs.digest }}
  close:
    if: github.event.action == 'closed' && github.event.pull_request.head.repo.full_name == github.repository
    runs-on: ubuntu-latest
    steps:
      - uses: NYCU-WinLab/carrel-deploy@v1
        with:
          tenant: %s
          function: %s
          close-preview: true
`, branch, f["name"], repo, t["slug"], f["name"], repo, t["slug"], f["name"])
}
