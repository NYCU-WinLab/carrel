// carrel-deployd receives app releases from carrel and switches them in
// place (PLAN 7.9). The machine owner installs it; it only makes outbound
// requests to carrel and never accepts connections.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type config struct {
	Origin string `json:"origin"`
	Token  string `json:"token"`
	App    string `json:"app"`
	Port   int    `json:"port"`
	User   string `json:"user"`
}

type release struct {
	ID     string `json:"id"`
	SHA    string `json:"sha"`
	SHA256 string `json:"sha256"`
	URL    string `json:"url"`
}

type agent struct {
	cfg    config
	root   string
	http   *http.Client
	uid    int
	gid    int
	health time.Duration
}

const (
	kept        = 3
	maxUnpacked = 4 << 30
)

func main() {
	path := flag.String("config", "", "agent configuration")
	flag.Parse()
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	content, err := os.ReadFile(*path)
	if err != nil {
		slog.Error("read configuration", "error", err)
		os.Exit(1)
	}
	var cfg config
	if err := json.Unmarshal(content, &cfg); err != nil || cfg.App == "" || cfg.Token == "" {
		slog.Error("invalid configuration")
		os.Exit(1)
	}
	u, err := user.Lookup(cfg.User)
	if err != nil {
		slog.Error("unknown user", "user", cfg.User)
		os.Exit(1)
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	a := &agent{cfg: cfg, root: filepath.Join("/srv/apps", cfg.App), http: &http.Client{Timeout: 10 * time.Minute}, uid: uid, gid: gid, health: 60 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	slog.Info("carrel_deployd_started", "app", cfg.App)
	a.loop(ctx)
}

func (a *agent) loop(ctx context.Context) {
	for ctx.Err() == nil {
		r, status, err := a.next(ctx)
		switch {
		case err != nil:
			slog.Warn("poll_failed", "error", err)
			pause(ctx, 5*time.Second)
		case status == 403:
			slog.Error("token_rejected; the app may be unlinked")
			pause(ctx, 60*time.Second)
		case r != nil:
			a.deploy(ctx, *r)
		}
	}
}

func pause(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}

func (a *agent) request(ctx context.Context, method, path string, body any) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(a.cfg.Origin, "/")+path, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+a.cfg.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return a.http.Do(req)
}

func (a *agent) next(ctx context.Context) (*release, int, error) {
	poll, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	resp, err := a.request(poll, "POST", "/apps/v1/agent/next", nil)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case 204:
		return nil, 204, nil
	case 200:
		var out struct{ Release *release }
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || out.Release == nil {
			return nil, 200, errors.New("invalid release response")
		}
		return out.Release, 200, nil
	}
	return nil, resp.StatusCode, nil
}

func (a *agent) report(ctx context.Context, id, state, message, log string) {
	resp, err := a.request(ctx, "POST", "/apps/v1/agent/report", map[string]string{"release": id, "state": state, "error": message, "log": log})
	if err != nil {
		slog.Warn("report_failed", "error", err)
		return
	}
	resp.Body.Close()
}

func (a *agent) deploy(ctx context.Context, r release) {
	slog.Info("deploy_started", "release", r.ID, "sha", r.SHA)
	a.report(ctx, r.ID, "deploying", "", "")
	dir := filepath.Join(a.root, "releases", r.ID)
	if err := a.fetch(ctx, r, dir); err != nil {
		a.report(ctx, r.ID, "failed", err.Error(), "")
		return
	}
	current := filepath.Join(a.root, "current")
	previous, _ := os.Readlink(current)
	if err := swap(current, dir); err != nil {
		a.report(ctx, r.ID, "failed", "switch release: "+err.Error(), "")
		return
	}
	if err := a.restartAndCheck(ctx); err != nil {
		log := a.journal()
		message := err.Error()
		if previous != "" && swap(current, previous) == nil {
			if a.restartAndCheck(ctx) == nil {
				message += "; previous release restored"
			} else {
				message += "; previous release did not recover"
			}
		}
		a.report(ctx, r.ID, "failed", message, log)
		slog.Warn("deploy_failed", "release", r.ID, "error", message)
		return
	}
	a.report(ctx, r.ID, "live", "", "")
	a.prune(dir, previous)
	slog.Info("deploy_live", "release", r.ID)
}

// fetch downloads and unpacks a release. A directory that already exists
// came from an earlier complete unpack of the same release, so it is reused;
// this keeps the running release in place when it is deployed again.
func (a *agent) fetch(ctx context.Context, r release, dir string) error {
	if _, err := os.Lstat(dir); err == nil {
		return nil
	}
	resp, err := a.request(ctx, "GET", "/apps/v1/agent/releases/"+r.ID, nil)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("download returned %d", resp.StatusCode)
	}
	tmp, err := os.CreateTemp(filepath.Join(a.root, "releases"), ".download-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmp, h), resp.Body); err != nil {
		tmp.Close()
		return fmt.Errorf("download: %w", err)
	}
	if hex.EncodeToString(h.Sum(nil)) != r.SHA256 {
		tmp.Close()
		return errors.New("checksum mismatch")
	}
	if _, err := tmp.Seek(0, 0); err != nil {
		return err
	}
	defer tmp.Close()
	staging := dir + ".unpack"
	os.RemoveAll(staging)
	if err := extract(tmp, staging, a.uid, a.gid); err != nil {
		os.RemoveAll(staging)
		return fmt.Errorf("unpack: %w", err)
	}
	return os.Rename(staging, dir)
}

// extract unpacks a tar.gz into dir, which must not exist. Every write goes
// through os.Root, so no entry or link can reach outside dir, and existing
// links are never followed. Unpacked content is capped at maxUnpacked.
func extract(r io.Reader, dir string, uid, gid int) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	if err := os.Mkdir(dir, 0755); err != nil {
		return err
	}
	if err := os.Lchown(dir, uid, gid); err != nil {
		return err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	var total int64
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		name := filepath.Clean(h.Name)
		if name == "." {
			continue
		}
		if !filepath.IsLocal(name) {
			return fmt.Errorf("entry %q leaves the release", h.Name)
		}
		mode := os.FileMode(h.Mode).Perm() &^ 0o022
		switch h.Typeflag {
		case tar.TypeDir:
			if err := root.MkdirAll(name, mode|0o700); err != nil {
				return err
			}
		case tar.TypeReg:
			total += h.Size
			if total > maxUnpacked {
				return errors.New("unpacked release exceeds 4 GiB")
			}
			if err := root.MkdirAll(filepath.Dir(name), 0755); err != nil {
				return err
			}
			f, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
			if err != nil {
				return err
			}
			_, err = io.Copy(f, io.LimitReader(tr, h.Size))
			f.Close()
			if err != nil {
				return err
			}
		case tar.TypeSymlink:
			if filepath.IsAbs(h.Linkname) || !filepath.IsLocal(filepath.Join(filepath.Dir(name), h.Linkname)) {
				return fmt.Errorf("link %q points outside the release", h.Name)
			}
			if err := root.MkdirAll(filepath.Dir(name), 0755); err != nil {
				return err
			}
			if err := root.Symlink(h.Linkname, name); err != nil {
				return err
			}
		default:
			continue
		}
		if err := root.Lchown(name, uid, gid); err != nil {
			return err
		}
	}
}

// swap points link at target atomically.
func swap(link, target string) error {
	tmp := link + ".new"
	os.Remove(tmp)
	if err := os.Symlink(target, tmp); err != nil {
		return err
	}
	return os.Rename(tmp, link)
}

func (a *agent) unit() string { return "carrel-app-" + a.cfg.App + ".service" }

func (a *agent) restartAndCheck(ctx context.Context) error {
	if out, err := exec.CommandContext(ctx, "systemctl", "restart", a.unit()).CombinedOutput(); err != nil {
		return fmt.Errorf("restart failed: %s", strings.TrimSpace(string(out)))
	}
	client := &http.Client{Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	deadline := time.Now().Add(a.health)
	last := "no answer"
	for time.Now().Before(deadline) {
		if exec.CommandContext(ctx, "systemctl", "is-failed", "--quiet", a.unit()).Run() == nil {
			return errors.New("app process failed")
		}
		resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/", a.cfg.Port))
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode < 500 {
				return nil
			}
			last = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		pause(ctx, time.Second)
	}
	return fmt.Errorf("health check on port %d failed: %s", a.cfg.Port, last)
}

func (a *agent) journal() string {
	out, _ := exec.Command("journalctl", "-u", a.unit(), "-n", "50", "--no-pager", "-o", "cat").Output()
	return string(out)
}

// prune keeps the newest releases plus the current and previous ones.
func (a *agent) prune(current, previous string) {
	base := filepath.Join(a.root, "releases")
	entries, err := os.ReadDir(base)
	if err != nil {
		return
	}
	type dir struct {
		path string
		mod  time.Time
	}
	dirs := []dir{}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if info, err := e.Info(); err == nil {
			dirs = append(dirs, dir{filepath.Join(base, e.Name()), info.ModTime()})
		}
	}
	sort.Slice(dirs, func(i, j int) bool { return dirs[i].mod.After(dirs[j].mod) })
	for i, d := range dirs {
		if i < kept || d.path == current || d.path == previous {
			continue
		}
		os.RemoveAll(d.path)
	}
}
