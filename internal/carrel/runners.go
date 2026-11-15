package carrel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Runners (issue #267) are GitHub Actions or GitLab self-hosted runners on a
// member's machine. Jobs build on the machine with its own tools and quota,
// and still deploy through the push flow: a self-hosted job gets an OIDC
// token as a hosted one does. carrel never holds a runner token. The member's
// agent pipes one from gh or glab straight into the install line over SSH, so
// it appears in no tool argument, no tool result and no command line. carrel
// keeps a record per runner so runner_list can say what runs where.

const runnerUser = "carrel-runner"

var (
	runnerLabelRE    = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	githubRunnerURL  = regexp.MustCompile(`^https://github\.com/([a-z0-9][a-z0-9-]{0,38})(?:/([a-z0-9._-]{1,100}))?$`)
	gitlabRunnerHost = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+(:[0-9]{1,5})?$`)
)

func runnerID(n int, name string) string { return fmt.Sprintf("%d-%s", n, name) }

func publicRunner(r D) D {
	return pick(r, "name", "machine", "provider", "url", "scope", "labels", "created_at")
}

// runnerTarget reads runner_add's url. GitHub: a repository or an
// organization. GitLab: any page of the instance; the runner registers with
// the instance, and the token decides the project or group.
func runnerTarget(provider, raw string) (target, scope string) {
	u := strings.TrimSuffix(strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), "/"), ".git")
	switch provider {
	case forgeGitHub:
		m := githubRunnerURL.FindStringSubmatch(u)
		if m == nil || m[2] == "." || m[2] == ".." {
			fail("invalid", "url must be https://github.com/<owner>/<repo> or https://github.com/<organization>")
		}
		if m[2] == "" {
			return "https://github.com/" + m[1], "organization"
		}
		return "https://github.com/" + m[1] + "/" + m[2], "repository"
	case forgeGitLab:
		parsed, err := url.Parse(u)
		if err != nil || parsed.Scheme != "https" || parsed.User != nil || !gitlabRunnerHost.MatchString(parsed.Host) {
			fail("invalid", "url must be an https URL on the GitLab instance, such as https://gitlab.com/group/project")
		}
		path := strings.Trim(parsed.Path, "/")
		if path == "" {
			fail("invalid", "url must name the GitLab project or group the runner serves, such as https://gitlab.com/group/project")
		}
		return "https://" + parsed.Host + "/" + path, "project_or_group"
	}
	fail("invalid", "provider must be github or gitlab")
	return "", ""
}

// githubVisibility asks GitHub, without credentials, whether a repository is
// public. A private repository answers 404 like a missing one, which is the
// safe answer here.
var githubVisibility = func(ctx context.Context, repo string) (public bool, known bool) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/repos/"+repo, nil)
	if err != nil {
		return false, false
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, false
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return false, true
	}
	if resp.StatusCode != 200 {
		return false, false
	}
	var body struct {
		Private bool `json:"private"`
	}
	if json.NewDecoder(resp.Body).Decode(&body) != nil {
		return false, false
	}
	return !body.Private, true
}

func (e *Execution) RunnerTool(tool string, a, t D) D {
	dry, n := boolean(a["dry_run"]), integer(t["n"])
	switch tool {
	case "runner_list":
		out := []D{}
		for _, r := range e.S.Objects("runners", n) {
			out = append(out, publicRunner(r))
		}
		return D{"runners": out}
	case "runner_add":
		m := e.Machine(t, a["machine"])
		provider := str(a["provider"])
		target, scope := runnerTarget(provider, str(a["url"]))
		name := textAt(a, "name", str(m["name"]))
		if e.S.Get("runners", runnerID(n, name)) != nil {
			fail("conflict", "A runner with this name already exists; remove it first or choose another name")
		}
		labels := []string{}
		for _, l := range arr(a["labels"]) {
			if !runnerLabelRE.MatchString(str(l)) {
				fail("invalid", "Labels are letters, digits, '.', '_' and '-'")
			}
			labels = append(labels, str(l))
		}
		r := D{"dry_run": dry}
		// Anyone who forks a public GitHub repository can open a pull request
		// whose workflow runs on its self-hosted runners.
		if scope == "repository" {
			public, known := githubVisibility(e.Ctx, strings.TrimPrefix(target, "https://github.com/"))
			switch {
			case public && !boolean(a["allow_public"]):
				fail("forbidden", "The repository is public: a pull request from any fork could run code on this machine. Use a private repository, or pass allow_public after restricting fork pull request workflows in the repository settings.")
			case !known:
				r["warning"] = "carrel could not check whether the repository is public. Do not use a self-hosted runner for a public repository."
			}
		}
		runner := D{"id": runnerID(n, name), "name": name, "tenant_n": n, "vmid": m["vmid"], "machine": m["name"], "provider": provider, "url": target, "scope": scope, "labels": labels, "created_at": now()}
		r["runner"] = publicRunner(runner)
		if dry {
			return r
		}
		e.Put("runners", runner["id"], n, runner)
		install := e.runnerScript(runner, "")
		r["install"] = install
		r["token_command"] = runnerTokenCommand(runner, "registration-token", str(m["name"]), install)
		r["next_steps"] = []string{
			"Run token_command from the client. It asks " + map[string]string{forgeGitHub: "GitHub", forgeGitLab: "GitLab"}[provider] + " for a runner token and pipes it into install on the machine over SSH, so the token appears in no tool call, no output and no command line. install needs sudo.",
			"Jobs pick the runner with runs-on: [self-hosted" + labelSuffix(labels) + "] on GitHub, or tags on GitLab when the runner was created with tags.",
			"Deploy from a job on this runner as from a hosted one: the app_link workflow works unchanged.",
		}
		return r
	case "runner_remove":
		runner := e.S.Get("runners", runnerID(n, str(a["runner"])))
		if runner == nil {
			fail("not_found", "Runner not found in this tenant")
		}
		if a["confirm"] != runner["name"] {
			fail("invalid", "confirm must equal the runner name")
		}
		if !dry {
			e.Transaction(func(tx *Execution) { tx.S.Remove("runners", runner["id"]) })
		}
		uninstall := e.runnerScript(runner, "--remove")
		out := D{"dry_run": dry, "removed": publicRunner(runner), "uninstall": uninstall}
		out["token_command"] = runnerTokenCommand(runner, "remove-token", str(runner["machine"]), uninstall)
		out["next_action"] = "Run token_command from the client: it stops the runner on the machine and deletes it from " + map[string]string{forgeGitHub: "GitHub", forgeGitLab: "GitLab"}[str(runner["provider"])] + "."
		return out
	}
	fail("invalid", "Unknown tool")
	return nil
}

func runnerLabels(runner D) []string {
	out := []string{}
	for _, l := range arr(runner["labels"]) {
		out = append(out, str(l))
	}
	return out
}

// labelSuffix names the labels a job selects the runner by: the given
// ones, or carrel, which the install script sets when none are given.
func labelSuffix(labels []string) string {
	if len(labels) == 0 {
		labels = []string{"carrel"}
	}
	s := ""
	for _, l := range labels {
		s += ", " + l
	}
	return s
}

func (e *Execution) runnerScript(runner D, extra string) string {
	args := fmt.Sprintf("--provider %s --url %s --name %s", runner["provider"], shellQuote(str(runner["url"])), shellQuote(str(runner["name"])))
	if labels := strings.Join(runnerLabels(runner), ","); labels != "" && extra == "" {
		args += " --labels " + shellQuote(labels)
	}
	if extra != "" {
		args += " " + extra
	}
	return fmt.Sprintf("f=$(mktemp) && curl -fsSL %s/apps/v1/runner.sh -o \"$f\" && sudo sh \"$f\" %s; rm -f \"$f\"", e.P.appOrigin(), args)
}

// runnerTokenCommand asks the forge for a token with the member's own gh or
// glab login and pipes it into the script on the machine.
func runnerTokenCommand(runner D, kind, machine, script string) string {
	target := str(runner["url"])
	ssh := " | ssh " + machine + " " + shellQuote(script)
	if runner["provider"] == forgeGitHub {
		path := strings.TrimPrefix(target, "https://github.com/")
		api := "repos/" + path
		if runner["scope"] == "organization" {
			api = "orgs/" + path
		}
		return "gh api -X POST " + api + "/actions/runners/" + kind + " --jq .token" + ssh
	}
	u, _ := url.Parse(target)
	path := strings.TrimPrefix(u.Path, "/")
	host := "GITLAB_HOST=" + u.Host + " "
	if kind == "remove-token" {
		// A runner made with a runner authentication token stays on GitLab
		// after gitlab-runner unregister, so the client deletes it by name.
		return fmt.Sprintf(`ssh %[1]s %[2]s && { r=$(%[3]sglab api projects/%[4]s/runners 2>/dev/null) || r=$(%[3]sglab api groups/%[4]s/runners); } && for id in $(printf '%%s\n' "$r" | jq -r --arg name %[5]s '.[] | select(.description == $name) | .id'); do %[3]sglab api -X DELETE runners/$id; done`,
			machine, shellQuote(script), host, url.PathEscape(path), shellQuote(str(runner["name"])))
	}
	// A project runner when the path is a project, else a group runner.
	// glab api has no --jq, and it prints an error body on stdout, so its
	// exit status is checked before jq reads the answer.
	return fmt.Sprintf(`{ if p=$(%[1]sglab api projects/%[2]s 2>/dev/null); then type=project_type; key=project_id; else p=$(%[1]sglab api groups/%[2]s) && type=group_type && key=group_id; fi && r=$(%[1]sglab api -X POST user/runners -f runner_type=$type -F $key=$(printf '%%s' "$p" | jq -r .id) -f description=%[3]s -F run_untagged=true) && printf '%%s\n' "$r" | jq -r .token; }`,
		host, url.PathEscape(path), shellQuote(str(runner["name"]))) + ssh
}

// removeRunners forgets the runners of a deleted machine. The machine and
// what ran on it are gone; the forge shows the runner offline until removed.
func (e *Execution) removeRunners(n int, vmid any) {
	for _, r := range e.S.Objects("runners", n) {
		if integer(r["vmid"]) == integer(vmid) {
			e.S.Remove("runners", r["id"])
		}
	}
}
