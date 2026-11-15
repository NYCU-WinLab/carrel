package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Pull mode (issue #266): the agent watches the linked branch, builds a new
// commit and uploads the result as a release, which then deploys like any
// other. Everything that touches the repository runs as the app user, in
// directories the app user owns: git and the build command run code the
// repository controls, and root must not. The build has the app user's
// rights, as the app itself does: when that user may sudo, so may the build.

type source struct {
	Mode   string `json:"mode"`
	URL    string `json:"url"`
	Branch string `json:"branch"`
	Build  string `json:"build"`
}

const (
	buildTimeout = 30 * time.Minute
	gitTimeout   = 2 * time.Minute
	logTail      = 8192
)

var commitRE = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)

func (a *agent) source(ctx context.Context) (*source, error) {
	c, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	resp, err := a.request(c, "GET", "/apps/v1/agent/source", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		// An older carrel has no source: the app is in push mode.
		return &source{Mode: "push"}, nil
	}
	var s source
	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		return nil, err
	}
	return &s, nil
}

// home is the app user's directory for pull mode: the deploy key, the
// known hosts and the build checkout.
func (a *agent) home() string { return filepath.Join(a.root, ".carrel") }
func (a *agent) key() string  { return filepath.Join(a.home(), "deploy_key") }

// asUser runs a shell script as the app user with the given environment.
func (a *agent) asUser(ctx context.Context, script string, env map[string]string, stdout io.Writer) (string, error) {
	cmd := exec.CommandContext(ctx, "runuser", "-u", a.cfg.User, "--", "/bin/sh", "-c", script)
	cmd.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "GIT_TERMINAL_PROMPT=0", "HOME=" + a.home()}
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	// ssh takes the deploy key and records the host on first use.
	cmd.Env = append(cmd.Env, "GIT_SSH_COMMAND=ssh -i "+a.key()+" -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="+filepath.Join(a.home(), "known_hosts")+" -o BatchMode=yes")
	var log tail
	cmd.Stderr = &log
	if stdout != nil {
		cmd.Stdout = stdout
	} else {
		cmd.Stdout = &log
	}
	cmd.WaitDelay = 10 * time.Second
	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		err = errors.New("timed out")
	}
	return log.String(), err
}

// ensureKey makes the deploy key once and reports its public half. carrel
// shows it in app_get for the member to add to the repository.
func (a *agent) ensureKey(ctx context.Context) {
	if a.keyShown {
		return
	}
	script := `set -eu; umask 077; mkdir -p "$CARREL_HOME"; [ -f "$CARREL_KEY" ] || ssh-keygen -q -t ed25519 -N "" -C "carrel-$CARREL_APP" -f "$CARREL_KEY"; ssh-keygen -y -f "$CARREL_KEY"`
	var out bytes.Buffer
	if log, err := a.asUser(ctx, script, map[string]string{"CARREL_HOME": a.home(), "CARREL_KEY": a.key(), "CARREL_APP": a.cfg.App}, &out); err != nil {
		slog.Warn("deploy_key_failed", "error", err, "log", log)
		return
	}
	// ssh-keygen -y may print the key's comment; carrel gets type, key and a
	// comment of its own.
	fields := strings.Fields(out.String())
	if len(fields) < 2 {
		return
	}
	resp, err := a.request(ctx, "POST", "/apps/v1/agent/report", map[string]string{"deploy_key": fields[0] + " " + fields[1] + " carrel-" + a.cfg.App})
	if err != nil {
		return
	}
	resp.Body.Close()
	a.keyShown = resp.StatusCode == 200
}

func (a *agent) pulledFile() string { return filepath.Join(a.state, "pulled") }

// check builds the branch head when it is a commit this agent has not
// built yet.
func (a *agent) check(ctx context.Context) {
	src, err := a.source(ctx)
	if err != nil || src.Mode != "pull" {
		return
	}
	a.ensureKey(ctx)
	env := map[string]string{"CARREL_URL": src.URL, "CARREL_BRANCH": src.Branch}
	var out bytes.Buffer
	c, cancel := context.WithTimeout(ctx, gitTimeout)
	log, err := a.asUser(c, `git ls-remote -- "$CARREL_URL" "refs/heads/$CARREL_BRANCH"`, env, &out)
	cancel()
	if err != nil {
		slog.Warn("ls_remote_failed", "error", err, "log", log)
		return
	}
	head := strings.Fields(out.String())
	if len(head) == 0 || !commitRE.MatchString(head[0]) {
		slog.Warn("branch_not_found", "branch", src.Branch)
		return
	}
	sha := head[0]
	if last, _ := os.ReadFile(a.pulledFile()); strings.TrimSpace(string(last)) == sha {
		return
	}
	slog.Info("build_started", "sha", sha)
	err = a.build(ctx, src, sha)
	if errors.Is(err, errRetry) {
		slog.Warn("upload_failed", "sha", sha, "error", err)
		return
	}
	if err != nil {
		slog.Warn("build_failed", "sha", sha, "error", err)
	}
	// A failed build is reported and not retried until the branch moves.
	_ = os.MkdirAll(a.state, 0700)
	_ = os.WriteFile(a.pulledFile(), []byte(sha+"\n"), 0600)
}

// errRetry is a build that did not reach carrel; the next check retries it.
var errRetry = errors.New("carrel did not take the release")

func (a *agent) build(ctx context.Context, src *source, sha string) error {
	work := filepath.Join(a.home(), "build")
	env := map[string]string{"CARREL_URL": src.URL, "CARREL_BRANCH": src.Branch, "CARREL_BUILD": src.Build, "CARREL_WORK": work, "CARREL_SHA": sha, "PORT": fmt.Sprint(a.cfg.Port)}
	fetch := `set -eu
rm -rf "$CARREL_WORK"; mkdir -p "$CARREL_WORK"; cd "$CARREL_WORK"
git init -q .
git fetch -q --depth 1 -- "$CARREL_URL" "refs/heads/$CARREL_BRANCH"
git -c advice.detachedHead=false checkout -q FETCH_HEAD
got=$(git rev-parse HEAD)
[ "$got" = "$CARREL_SHA" ] || { echo "the branch moved to $got while fetching; the next check builds it" >&2; exit 1; }
if [ -n "$CARREL_BUILD" ]; then sh -c "$CARREL_BUILD" >&2; fi`
	c, cancel := context.WithTimeout(ctx, buildTimeout)
	log, err := a.asUser(c, fetch, env, nil)
	cancel()
	if err != nil {
		a.reportBuild(ctx, sha, "build failed: "+err.Error(), log)
		return err
	}
	// The app user packs the checkout; root only streams the bytes.
	reader, writer := io.Pipe()
	packed := make(chan error, 1)
	var packLog string
	go func() {
		var err error
		packLog, err = a.asUser(ctx, `cd "$CARREL_WORK" && tar czf - --exclude=./.git .`, env, writer)
		writer.CloseWithError(err)
		packed <- err
	}()
	req, err := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(a.cfg.Origin, "/")+"/apps/v1/agent/upload", reader)
	if err != nil {
		reader.Close()
		return err
	}
	req.Header.Set("Authorization", "Bearer "+a.cfg.Token)
	req.Header.Set("Content-Type", "application/gzip")
	req.Header.Set("X-Carrel-Sha", sha)
	resp, err := a.http.Do(req)
	reader.Close()
	perr := <-packed
	if err != nil {
		// Not reported: carrel did not answer, so a report would not land
		// either. The next check builds the commit again.
		return fmt.Errorf("%w: %v", errRetry, err)
	}
	defer resp.Body.Close()
	if perr != nil {
		a.reportBuild(ctx, sha, "pack failed: "+perr.Error(), packLog)
		return perr
	}
	// carrel busy or out of space for now: the next check builds the commit
	// again. A refusal (a 4xx, such as a full quota) is reported instead.
	if resp.StatusCode == 429 || resp.StatusCode >= 500 {
		return fmt.Errorf("%w: upload returned %d", errRetry, resp.StatusCode)
	}
	if resp.StatusCode != 200 {
		var out struct {
			Error struct{ Message string }
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&out)
		a.reportBuild(ctx, sha, fmt.Sprintf("upload returned %d: %s", resp.StatusCode, out.Error.Message), log)
		return fmt.Errorf("upload returned %d", resp.StatusCode)
	}
	slog.Info("build_uploaded", "sha", sha)
	return nil
}

func (a *agent) reportBuild(ctx context.Context, sha, message, log string) {
	resp, err := a.request(ctx, "POST", "/apps/v1/agent/report", map[string]string{"sha": sha, "state": "failed", "error": message, "log": log})
	if err != nil {
		slog.Warn("report_failed", "error", err)
		return
	}
	resp.Body.Close()
}

// tail keeps the last logTail bytes written to it.
type tail struct{ b []byte }

func (t *tail) Write(p []byte) (int, error) {
	t.b = append(t.b, p...)
	if len(t.b) > logTail {
		t.b = t.b[len(t.b)-logTail:]
	}
	return len(p), nil
}

func (t *tail) String() string { return string(t.b) }
