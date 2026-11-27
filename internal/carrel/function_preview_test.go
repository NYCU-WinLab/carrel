package carrel

import (
	"context"
	"strings"
	"testing"
	"time"
)

func pullToken(repo, id string, pr int, head string) CIClaims {
	ref := "refs/heads/main" // a merged pull request's close names the base branch
	if pr > 0 {
		ref = "refs/pull/" + itoa(int64(pr)) + "/merge"
	}
	return CIClaims{Issuer: githubIssuer, Repository: repo, RepositoryID: id, Ref: ref, SHA: "pr" + head, Event: "pull_request", HeadRef: head, BaseRef: "main"}
}

func TestPullRequestPreviews(t *testing.T) {
	p, a := functionFixture(t)
	a.forges = fakeForge{
		"good":     push("alice/hook", "42", "main"),
		"pr7":      pullToken("alice/hook", "42", 7, "feature"),
		"pr8":      pullToken("alice/hook", "42", 8, "other"),
		"merged7":  pullToken("alice/hook", "42", 0, "feature"),
		"target":   {Issuer: githubIssuer, Repository: "alice/hook", RepositoryID: "42", Ref: "refs/pull/7/merge", Event: "pull_request_target", HeadRef: "feature"},
		"reborn7":  pullToken("alice/hook", "99", 7, "feature"),
		"mallory7": pullToken("mallory/hook", "7", 7, "feature"),
	}
	alice := person("alice", false)
	ctx := context.Background()
	call := func(tool string, args D) D { return a.Call(ctx, tool, args, alice) }
	image := func(c string) string { return "ghcr.io/alice/hook@sha256:" + strings.Repeat(c, 64) }
	deploy := func(token, img string) (int, D) {
		return do(t, a, "POST", "/functions/v1/deploy/alice/hook", token, strings.NewReader(`{"image":"`+img+`"}`))
	}

	assertOK(t, call("function_deploy", D{"name": "hook", "image": "ghcr.io/alice/hook:1", "port": 9000, "memory_mb": 256}))
	report(t, a, `{"revision":1,"functions":[{"id":"t1-hook","current":"v1","versions":[{"version":"v1","state":"ready"}]}]}`)
	// The parent has an environment and a schedule a preview must not get.
	p.Store.Exec("UPDATE objects SET data=json_set(data,'$.env','sealed-production') WHERE kind='function_versions' AND id=?", functionVersionID("1-hook", "v1"))
	assertOK(t, call("function_schedule", D{"function": "hook", "name": "nightly", "cron": "0 3 * * *"}))

	// Previews off: a pull request is refused.
	assertOK(t, call("function_link", D{"function": "hook", "repo": "alice/hook"}))
	if code, _ := deploy("pr7", image("a")); code != 403 {
		t.Fatalf("previews off: %d", code)
	}
	r := call("function_link", D{"function": "hook", "repo": "alice/hook", "previews": true})
	assertOK(t, r)
	for _, want := range []string{"pull_request:", "close-preview: true", "head.repo.full_name == github.repository", "pull-requests: write"} {
		if !strings.Contains(str(r["workflow"]), want) {
			t.Fatalf("workflow lacks %q:\n%s", want, r["workflow"])
		}
	}
	// No push has pinned the repository id yet.
	if code, _ := deploy("pr7", image("a")); code != 403 {
		t.Fatalf("unpinned: %d", code)
	}
	if code, _ := deploy("good", image("b")); code != 200 {
		t.Fatalf("push: %d", code)
	}
	report(t, a, `{"revision":2,"functions":[{"id":"t1-hook","current":"v2","versions":[{"version":"v2","state":"ready"}]}]}`)

	for _, token := range []string{"target", "reborn7", "mallory7", "merged7"} {
		if code, _ := deploy(token, image("a")); code != 403 && code != 404 {
			t.Fatalf("token %s deployed: %d", token, code)
		}
	}
	code, out := deploy("pr7", image("a"))
	if code != 200 || obj(out["preview"])["url"] != "https://pr-7-hook.alice.winlab.tw" || obj(out["version"])["state"] != "building" {
		t.Fatalf("preview: %d %s", code, encoded(out))
	}
	pf := p.Store.Get("functions", functionID(1, "pr-7-hook"))
	v := p.Store.Get("function_versions", functionVersionID(str(pf["id"]), str(pf["pending"])))
	if pf["preview_of"] != "1-hook" || v["image"] != image("a") || integer(v["port"]) != 9000 || v["env"] != nil || pf["schedules"] != nil {
		t.Fatalf("preview record %s, version %s", encoded(pf), encoded(v))
	}
	d, found := domainNamed(p.execution(ctx).domains(1), "pr-7-hook.alice.winlab.tw")
	if !found || d.Function != str(pf["id"]) || d.State != "queued" {
		t.Fatalf("domain %+v %v", d, found)
	}
	select {
	case <-p.domainKick:
	case <-time.After(time.Second):
		t.Fatal("the domain loop was not woken")
	}
	// The status poll reads the preview's version with the same token.
	if code, s := do(t, a, "GET", "/functions/v1/deploy/alice/hook/"+str(pf["pending"]), "pr7", nil); code != 200 || obj(s["version"])["state"] != "building" {
		t.Fatalf("status: %d %s", code, encoded(s))
	}
	// The parent lists it; a second pull request gets its own.
	if got := obj(call("function_get", D{"function": "hook"})["function"]); len(arr(got["open_previews"])) != 1 {
		t.Fatalf("parent %s", encoded(got))
	}
	report(t, a, `{"revision":3,"functions":[{"id":"t1-hook","current":"v2","versions":[{"version":"v2","state":"ready"}]},{"id":"t1-pr-7-hook","current":"`+str(pf["pending"])+`","versions":[{"version":"`+str(pf["pending"])+`","state":"ready"}]}]}`)
	if code, _ := deploy("pr8", image("c")); code != 200 {
		t.Fatalf("second preview: %d", code)
	}
	// A function of that name that is no preview is never taken over.
	assertOK(t, call("function_deploy", D{"name": "pr-9-hook", "image": "ghcr.io/alice/x:1"}))
	a.forges.(fakeForge)["pr9"] = pullToken("alice/hook", "42", 9, "nine")
	if code, _ := deploy("pr9", image("d")); code != 409 {
		t.Fatalf("taken name: %d", code)
	}

	// A merged close names only the head branch: that preview goes, with its domain.
	closePR := func(token string, pr int) (int, D) {
		return do(t, a, "DELETE", "/functions/v1/deploy/alice/hook/preview", token, strings.NewReader(`{"pr":`+itoa(int64(pr))+`}`))
	}
	// A late close of an older pull request from a branch named like pr-8's
	// names its own number: pr-8's preview stays.
	a.forges.(fakeForge)["late"] = pullToken("alice/hook", "42", 0, "other")
	if code, out := closePR("late", 3); code != 200 || len(arr(out["removed"])) != 0 {
		t.Fatalf("late close: %d %s", code, encoded(out))
	}
	// The token's number must match the body's.
	if code, _ := closePR("pr8", 7); code != 403 {
		t.Fatalf("mismatched close: %d", code)
	}
	if code, out := closePR("merged7", 7); code != 200 || len(arr(out["removed"])) != 1 {
		t.Fatalf("close: %d %s", code, encoded(out))
	}
	if p.Store.Get("functions", functionID(1, "pr-7-hook")) != nil {
		t.Fatal("preview kept")
	}
	if _, found := domainNamed(p.execution(ctx).domains(1), "pr-7-hook.alice.winlab.tw"); found {
		t.Fatal("preview domain kept")
	}
	// Two previews from one head branch to different bases: a merged close
	// naming one base removes only that one (#779).
	a.forges.(fakeForge)["dev11"] = CIClaims{Issuer: githubIssuer, Repository: "alice/hook", RepositoryID: "42", Ref: "refs/pull/11/merge", Event: "pull_request", HeadRef: "shared", BaseRef: "dev"}
	a.forges.(fakeForge)["main12"] = CIClaims{Issuer: githubIssuer, Repository: "alice/hook", RepositoryID: "42", Ref: "refs/pull/12/merge", Event: "pull_request", HeadRef: "shared", BaseRef: "main"}
	a.forges.(fakeForge)["mergedMain"] = CIClaims{Issuer: githubIssuer, Repository: "alice/hook", RepositoryID: "42", Ref: "refs/heads/main", Event: "pull_request", HeadRef: "shared", BaseRef: "main"}
	for _, token := range []string{"dev11", "main12"} {
		if code, _ := deploy(token, image("e")); code != 200 {
			t.Fatalf("deploy %s: %d", token, code)
		}
	}
	if code, out := closePR("mergedMain", 11); code != 200 || len(arr(out["removed"])) != 0 {
		t.Fatalf("wrong base closed: %d %s", code, encoded(out))
	}
	if code, out := closePR("mergedMain", 12); code != 200 || len(arr(out["removed"])) != 1 {
		t.Fatalf("right base: %d %s", code, encoded(out))
	}
	if p.Store.Get("functions", functionID(1, "pr-11-hook")) == nil {
		t.Fatal("the other base's preview was removed")
	}
	// Another repository's token removes nothing.
	if code, _ := closePR("mallory7", 8); code != 403 && code != 404 {
		t.Fatalf("foreign close: %d", code)
	}
	// Removing the parent removes its previews.
	assertOK(t, call("function_remove", D{"function": "hook", "confirm": "hook"}))
	if p.Store.Get("functions", functionID(1, "pr-8-hook")) != nil {
		t.Fatal("pr-8 outlived its parent")
	}
}

func TestIdlePreviewsAreReaped(t *testing.T) {
	p, a := functionFixture(t)
	a.forges = fakeForge{"good": push("alice/hook", "42", "main"), "pr7": pullToken("alice/hook", "42", 7, "feature")}
	alice, ctx := person("alice", false), context.Background()
	assertOK(t, a.Call(ctx, "function_deploy", D{"name": "hook", "image": "ghcr.io/alice/hook:1"}, alice))
	report(t, a, `{"revision":1,"functions":[{"id":"t1-hook","current":"v1","versions":[{"version":"v1","state":"ready"}]}]}`)
	assertOK(t, a.Call(ctx, "function_link", D{"function": "hook", "repo": "alice/hook", "previews": true}, alice))
	img := "ghcr.io/alice/hook@sha256:" + strings.Repeat("a", 64)
	do(t, a, "POST", "/functions/v1/deploy/alice/hook", "good", strings.NewReader(`{"image":"`+img+`"}`))
	report(t, a, `{"revision":2,"functions":[{"id":"t1-hook","current":"v2","versions":[{"version":"v2","state":"ready"}]}]}`)
	if code, _ := do(t, a, "POST", "/functions/v1/deploy/alice/hook", "pr7", strings.NewReader(`{"image":"`+img+`"}`)); code != 200 {
		t.Fatalf("preview: %d", code)
	}
	pf := p.Store.Get("functions", functionID(1, "pr-7-hook"))
	pf["pending"], pf["created_at"] = nil, now()-previewIdle.Seconds()-60
	p.Store.Put("functions", pf["id"], 1, pf)
	p.execution(ctx).ReapPreviews()
	if p.Store.Get("functions", functionID(1, "pr-7-hook")) != nil {
		t.Fatal("idle preview kept")
	}
	if p.Store.Get("functions", functionID(1, "hook")) == nil {
		t.Fatal("the parent was reaped")
	}
}

// A special-domain grant domain added to a preview (domain_add with name:)
// goes with the preview, and the grant is left to MaintainGrants to release.
func TestClosingPreviewRemovesItsGrantDomain(t *testing.T) {
	p, a := functionFixture(t)
	a.forges = fakeForge{"good": push("alice/hook", "42", "main"), "pr7": pullToken("alice/hook", "42", 7, "feature")}
	alice, ctx := person("alice", false), context.Background()
	assertOK(t, a.Call(ctx, "function_deploy", D{"name": "hook", "image": "ghcr.io/alice/hook:1"}, alice))
	report(t, a, `{"revision":1,"functions":[{"id":"t1-hook","current":"v1","versions":[{"version":"v1","state":"ready"}]}]}`)
	assertOK(t, a.Call(ctx, "function_link", D{"function": "hook", "repo": "alice/hook", "previews": true}, alice))
	img := "ghcr.io/alice/hook@sha256:" + strings.Repeat("a", 64)
	do(t, a, "POST", "/functions/v1/deploy/alice/hook", "good", strings.NewReader(`{"image":"`+img+`"}`))
	report(t, a, `{"revision":2,"functions":[{"id":"t1-hook","current":"v2","versions":[{"version":"v2","state":"ready"}]}]}`)
	if code, _ := do(t, a, "POST", "/functions/v1/deploy/alice/hook", "pr7", strings.NewReader(`{"image":"`+img+`"}`)); code != 200 {
		t.Fatalf("preview: %d", code)
	}
	// What domain_add name: leaves behind: a grant and a domain under it that
	// points at the preview.
	grant := domainGrant{ID: "g1", Kind: "exact", Name: "demo.winlab.tw", RequestID: "r1", TenantN: 1, GrantedAt: time.Now().Unix()}
	p.Store.Put("domain_grants", grant.ID, 1, grant.D())
	extra := domainRecord{ID: "d1", TenantN: 1, Function: functionID(1, "pr-7-hook"), Grant: grant.ID, Slug: "alice", Name: grant.Name, State: "ready"}
	p.Store.Put("domains", extra.ID, 1, extra.D())

	if code, out := do(t, a, "DELETE", "/functions/v1/deploy/alice/hook/preview", "pr7", strings.NewReader(`{"pr":7}`)); code != 200 || len(arr(out["removed"])) != 1 {
		t.Fatalf("close: %d %s", code, encoded(out))
	}
	e := p.execution(ctx)
	if _, found := domainNamed(e.domains(1), grant.Name); found {
		t.Fatal("the grant domain outlived the preview")
	}
	for _, d := range e.domains(1) {
		if d.Function != "" && p.Store.Get("functions", d.Function) == nil {
			t.Fatalf("domain %s points at the deleted function %s", d.Name, d.Function)
		}
	}
	// The grant has no live domain now, so maintenance marks it unused.
	e.MaintainGrants()
	g, ok := rowOf[domainGrant](p.Store, "domain_grants", grant.ID)
	if !ok || g.UnusedSince == 0 {
		t.Fatalf("grant not marked unused: %+v %v", g, ok)
	}
}
