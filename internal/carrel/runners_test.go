package carrel

import (
	"context"
	"strings"
	"testing"
)

func runnerFixture(t *testing.T, visibility map[string]bool) (*Platform, *App) {
	t.Helper()
	p, a, _ := appFixture(t)
	old := githubVisibility
	githubVisibility = func(_ context.Context, repo string) (bool, bool) {
		public, known := visibility[repo]
		return public, known
	}
	t.Cleanup(func() { githubVisibility = old })
	return p, a
}

func TestRunnerAddKeepsTheTokenOffCarrel(t *testing.T) {
	_, a := runnerFixture(t, map[string]bool{"alice/site": false, "alice/open": true})
	ctx, alice := context.Background(), person("alice", false)
	call := func(tool string, args D) D { return a.Call(ctx, tool, args, alice) }

	r := call("runner_add", D{"machine": "web", "provider": "github", "url": "https://github.com/Alice/Site", "labels": []any{"big"}})
	assertOK(t, r)
	runner := obj(r["runner"])
	if runner["name"] != "web" || runner["url"] != "https://github.com/alice/site" || runner["scope"] != "repository" || r["warning"] != nil {
		t.Fatalf("unexpected runner: %s", encoded(r))
	}
	install, command := str(r["install"]), str(r["token_command"])
	for _, want := range []string{"/apps/v1/runner.sh", "--provider github", "--url 'https://github.com/alice/site'", "--name 'web'", "--labels 'big'"} {
		if !strings.Contains(install, want) {
			t.Fatalf("install lacks %q: %s", want, install)
		}
	}
	if !strings.HasPrefix(command, "gh api -X POST repos/alice/site/actions/runners/registration-token --jq .token | ssh web ") {
		t.Fatalf("token command: %s", command)
	}
	assertCode(t, call("runner_add", D{"machine": "web", "provider": "github", "url": "https://github.com/alice/site"}), "conflict")

	// A public repository needs allow_public; an unknown one gets a warning.
	assertCode(t, call("runner_add", D{"machine": "web", "name": "open", "provider": "github", "url": "https://github.com/alice/open"}), "forbidden")
	assertOK(t, call("runner_add", D{"machine": "web", "name": "open", "provider": "github", "url": "https://github.com/alice/open", "allow_public": true}))
	if r := call("runner_add", D{"machine": "web", "name": "unknown", "provider": "github", "url": "https://github.com/alice/unknown"}); r["warning"] == nil {
		t.Fatalf("no warning: %s", encoded(r))
	}
	org := call("runner_add", D{"machine": "web", "name": "org", "provider": "github", "url": "https://github.com/winlab"})
	if obj(org["runner"])["scope"] != "organization" || !strings.HasPrefix(str(org["token_command"]), "gh api -X POST orgs/winlab/actions/runners/registration-token") {
		t.Fatalf("organization runner: %s", encoded(org))
	}

	gl := call("runner_add", D{"machine": "web", "name": "gl", "provider": "gitlab", "url": "https://gitlab.winlab.tw/Group/Sub/Docs"})
	assertOK(t, gl)
	if c := str(gl["token_command"]); !strings.Contains(c, "GITLAB_HOST=gitlab.winlab.tw glab api projects/group%2Fsub%2Fdocs") || !strings.Contains(c, "user/runners") {
		t.Fatalf("gitlab token command: %s", c)
	}
	for _, bad := range []D{
		{"provider": "github", "url": "https://gitlab.com/a/b"},
		{"provider": "github", "url": "https://github.com/a/.."},
		{"provider": "gitlab", "url": "https://gitlab.com"},
		{"provider": "gitlab", "url": "https://u@gitlab.com/a/b"},
	} {
		bad["machine"], bad["name"] = "web", "bad"
		assertCode(t, call("runner_add", bad), "invalid")
	}

	list := obj(call("runner_list", D{}))["runners"]
	if len(arr(list)) != 5 {
		t.Fatalf("runners: %s", encoded(list))
	}
	assertCode(t, call("runner_remove", D{"runner": "web", "confirm": "nope"}), "invalid")
	removed := call("runner_remove", D{"runner": "web", "confirm": "web"})
	if !strings.Contains(str(removed["uninstall"]), "--remove") || !strings.HasPrefix(str(removed["token_command"]), "gh api -X POST repos/alice/site/actions/runners/remove-token") {
		t.Fatalf("remove: %s", encoded(removed))
	}
	if r := call("runner_remove", D{"runner": "gl", "confirm": "gl"}); !strings.Contains(str(r["token_command"]), "glab api -X DELETE runners/$id") || !strings.Contains(str(r["uninstall"]), "--provider gitlab") {
		t.Fatalf("gitlab remove: %s", encoded(r))
	}
	assertCode(t, call("runner_remove", D{"runner": "web", "confirm": "web"}), "not_found")
	assertCode(t, a.Call(ctx, "runner_remove", D{"runner": "org", "confirm": "org"}, person("bob", false)), "not_found")

	if code, out := do(t, a, "GET", "/apps/v1/runner.sh", "", nil); code != 200 || !strings.Contains(str(out["body"]), "ACTIONS_RUNNER_INPUT_TOKEN") {
		t.Fatalf("runner.sh: %d", code)
	}
}
