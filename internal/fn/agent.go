//go:build linux

package fn

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// The host agent keeps a function host at the control plane's desired state
// (PLAN 7.11). It asks for the state with the host's one token, builds the
// versions it lacks, puts each function's current version live, removes what
// the state no longer names, and reports what the host holds. Both sides are
// level-triggered: the agent sends the whole inventory after every pass, so a
// lost report or a restart on either side heals on the next pass.

// DesiredVersion is one version of a function, as the control plane asks for it.
type DesiredVersion struct {
	Version        string `json:"version"`
	Image          string `json:"image"`
	Port           int    `json:"port"`
	MemoryMB       int    `json:"memory_mb"`
	Mode           string `json:"mode"`
	IdleSeconds    int    `json:"idle_seconds"`
	TimeoutSeconds int    `json:"timeout_seconds"`
	MaxInstances   int    `json:"max_instances"`
	WakePath       string `json:"wake_path,omitempty"`
}

// DesiredFunction names a function on the host, t<tenant>-<name>, its
// versions to keep and the one to put live. Current is empty until a version
// built.
type DesiredFunction struct {
	ID       string           `json:"id"`
	Current  string           `json:"current,omitempty"`
	Versions []DesiredVersion `json:"versions"`
}

// Desired is the whole state of one host.
type Desired struct {
	Revision  int64             `json:"revision"`
	Functions []DesiredFunction `json:"functions"`
}

// HeldVersion is a version the host holds, or failed to build.
type HeldVersion struct {
	Version string `json:"version"`
	// State is "ready" or "failed".
	State  string `json:"state"`
	Bytes  int64  `json:"bytes,omitempty"`
	Digest string `json:"digest,omitempty"`
	Error  string `json:"error,omitempty"`
}

// HeldFunction is what the host holds of one function.
type HeldFunction struct {
	ID       string        `json:"id"`
	Current  string        `json:"current,omitempty"`
	Versions []HeldVersion `json:"versions"`
}

// Inventory is the agent's report after a pass.
type Inventory struct {
	Revision  int64          `json:"revision"`
	Functions []HeldFunction `json:"functions"`
}

// Agent runs on a function host next to the router.
type Agent struct {
	// Control is the control plane's base URL, Token the host's token.
	Control string
	Token   string
	Root    string
	Client  *http.Client
	// Build makes one version. It must not activate it. The agent holds
	// the function's lock while it runs.
	Build func(ctx context.Context, f Function, image string) error
	// Lock takes a function's lock, the one a build from the command line
	// takes too. It fails at once when the lock is held.
	Lock func(name string) (unlock func(), err error)
	// Forget tells the router a function changed or went away.
	Forget func(name string)
	// failed holds the error of a version that did not build, so the agent
	// does not build it again while the control plane still names it.
	failed map[string]string
}

const (
	// agentPoll is how long one request for the state may wait for a change.
	agentPoll = 30 * time.Second
	// agentRetry is the pause after a failed request.
	agentRetry = 5 * time.Second
	// maxState bounds the desired state the agent reads.
	maxState = 4 << 20
	// maxError bounds a build error in a report.
	maxError = 2000
)

// Run asks for the state and applies it until ctx ends.
func (a *Agent) Run(ctx context.Context) {
	if a.failed == nil {
		a.failed = map[string]string{}
	}
	var since int64 = -1
	for ctx.Err() == nil {
		desired, err := a.fetch(ctx, since)
		if err == nil && desired.Revision < since {
			// An older state than one already applied comes from a control
			// plane restored from a backup or a stale copy. Applying it would
			// remove what newer states built; a restart of the agent accepts it.
			err = fmt.Errorf("the control plane's revision went back from %d to %d", since, desired.Revision)
		}
		if err == nil {
			a.apply(ctx, desired)
			err = a.report(ctx, a.inventory(desired))
			since = desired.Revision
		}
		if err != nil && ctx.Err() == nil {
			slog.Warn("function host agent", "error", err)
			select {
			case <-ctx.Done():
			case <-time.After(agentRetry):
			}
		}
	}
}

// fetch waits for a state newer than since. The control plane answers at
// once when it has one, and otherwise at the end of the poll with the same
// revision, which serves as a heartbeat.
func (a *Agent) fetch(ctx context.Context, since int64) (Desired, error) {
	query := url.Values{"since": {strconv.FormatInt(since, 10)}, "wait": {strconv.Itoa(int(agentPoll / time.Second))}}
	ctx, cancel := context.WithTimeout(ctx, agentPoll+15*time.Second)
	defer cancel()
	var answer struct {
		Revision  *int64             `json:"revision"`
		Functions *[]DesiredFunction `json:"functions"`
	}
	if err := a.call(ctx, http.MethodGet, "/functions/v1/agent/state?"+query.Encode(), nil, &answer); err != nil {
		return Desired{}, err
	}
	// An empty list removes every function, so only a whole state counts:
	// an answer without both fields is an error, never "nothing".
	if answer.Revision == nil || answer.Functions == nil {
		return Desired{}, errors.New("the control plane's state lacks revision or functions")
	}
	desired := Desired{Revision: *answer.Revision, Functions: *answer.Functions}
	if err := desired.check(); err != nil {
		return Desired{}, fmt.Errorf("the control plane's state is refused: %w", err)
	}
	return desired, nil
}

// check refuses a state with any part the agent cannot use, before any file
// changes: a function skipped for a bad field would look unnamed, and its
// files would go.
func (d Desired) check() error {
	ids := map[string]bool{}
	for _, f := range d.Functions {
		if !nameRE.MatchString(f.ID) || ids[f.ID] {
			return fmt.Errorf("function id %q is invalid or repeated", f.ID)
		}
		ids[f.ID] = true
		if f.Versions == nil {
			return fmt.Errorf("function %s has no versions list", f.ID)
		}
		versions := map[string]bool{}
		for _, v := range f.Versions {
			if !versionRE.MatchString(v.Version) || versions[v.Version] {
				return fmt.Errorf("function %s: version %q is invalid or repeated", f.ID, v.Version)
			}
			versions[v.Version] = true
		}
		if f.Current != "" && !versions[f.Current] {
			return fmt.Errorf("function %s: current version %q is not listed", f.ID, f.Current)
		}
	}
	return nil
}

func (a *Agent) report(ctx context.Context, inventory Inventory) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return a.call(ctx, http.MethodPost, "/functions/v1/agent/report", inventory, nil)
}

func (a *Agent) call(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		content, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(content)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.Control+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+a.Token)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := a.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	content, err := io.ReadAll(io.LimitReader(resp.Body, maxState+1))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, bytes.TrimSpace(content[:min(len(content), 500)]))
	}
	if len(content) > maxState {
		return fmt.Errorf("%s %s: answer larger than %d bytes", method, path, maxState)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(content, out)
}

// apply brings the host to the desired state: builds first, then the live
// versions, then removals, so a function never loses its live version to a
// build that has not finished. Every change to a function's files happens
// under the function's lock; a function whose lock is held waits for the
// next pass.
func (a *Agent) apply(ctx context.Context, desired Desired) {
	wanted := map[string]map[string]bool{}
	for _, f := range desired.Functions {
		if !nameRE.MatchString(f.ID) {
			slog.Warn("desired function has an invalid id", "id", f.ID)
			continue
		}
		keep := map[string]bool{}
		for _, v := range f.Versions {
			if versionRE.MatchString(v.Version) {
				keep[v.Version] = true
			} else {
				slog.Warn("desired version is invalid", "function", f.ID, "version", v.Version)
			}
		}
		wanted[f.ID] = keep
		if ctx.Err() != nil {
			return
		}
		if !realDirs(a.Root, f.ID) {
			slog.Warn("function directory is not a plain directory", "function", f.ID)
			continue
		}
		unlock, err := a.Lock(f.ID)
		if err != nil {
			slog.Info("function busy, left for the next pass", "function", f.ID)
			continue
		}
		a.applyFunction(ctx, f, keep)
		unlock()
	}
	// Forget the failures the control plane no longer asks for.
	for key := range a.failed {
		id, version, _ := strings.Cut(key, "/")
		if !wanted[id][version] {
			delete(a.failed, key)
		}
	}
	if ctx.Err() == nil {
		a.remove(wanted)
	}
}

// applyFunction runs with the function's lock held.
func (a *Agent) applyFunction(ctx context.Context, f DesiredFunction, keep map[string]bool) {
	for _, v := range f.Versions {
		key := f.ID + "/" + v.Version
		// The live version stays, even one built before versions kept
		// their own function.json.
		if !keep[v.Version] || Built(a.Root, f.ID, v.Version) || a.failed[key] != "" || v.Version == liveVersion(a.Root, f.ID) {
			continue
		}
		if ctx.Err() != nil {
			return
		}
		// A build that a crash or a stop cut short left a directory without
		// function.json, and a version is built only once. The lock says no
		// build is writing it now.
		_ = os.RemoveAll(filepath.Join(a.Root, f.ID, "v", v.Version))
		start := time.Now()
		err := a.Build(ctx, Function{
			Name: f.ID, Version: v.Version, Port: v.Port, MemoryMB: v.MemoryMB, Mode: v.Mode,
			IdleSeconds: v.IdleSeconds, TimeoutSeconds: v.TimeoutSeconds,
			MaxInstances: v.MaxInstances, WakePath: v.WakePath,
		}, v.Image)
		if err != nil {
			if ctx.Err() != nil {
				return // a stop is not a failed build
			}
			message := err.Error()
			if len(message) > maxError {
				message = message[:maxError]
			}
			a.failed[key] = message
			slog.Warn("version not built", "function", f.ID, "version", v.Version, "error", err)
			continue
		}
		slog.Info("version built", "function", f.ID, "version", v.Version, "seconds", time.Since(start).Seconds())
	}
	if f.Current != "" && keep[f.Current] && liveVersion(a.Root, f.ID) != f.Current && Built(a.Root, f.ID, f.Current) {
		if err := Activate(a.Root, f.ID, f.Current); err != nil {
			slog.Warn("version not activated", "function", f.ID, "version", f.Current, "error", err)
		} else {
			a.Forget(f.ID)
			slog.Info("version live", "function", f.ID, "version", f.Current)
		}
	}
	// Versions the state no longer names go, except the live one.
	live := liveVersion(a.Root, f.ID)
	versions, err := os.ReadDir(filepath.Join(a.Root, f.ID, "v"))
	if err != nil {
		return
	}
	for _, v := range versions {
		if v.IsDir() && !keep[v.Name()] && v.Name() != live {
			_ = os.RemoveAll(filepath.Join(a.Root, f.ID, "v", v.Name()))
		}
	}
}

// remove deletes the functions the state does not name, each under its lock.
func (a *Agent) remove(wanted map[string]map[string]bool) {
	entries, err := os.ReadDir(a.Root)
	if err != nil {
		slog.Warn("functions not listed", "error", err)
		return
	}
	for _, entry := range entries {
		id := entry.Name()
		if !entry.IsDir() || !nameRE.MatchString(id) {
			continue // .jail, .lock and the kernel
		}
		if _, named := wanted[id]; named {
			continue
		}
		if !realDirs(a.Root, id) {
			slog.Warn("function directory is not a plain directory", "function", id)
			continue
		}
		unlock, err := a.Lock(id)
		if err != nil {
			continue // a build from the command line; the next pass removes it
		}
		// No new request finds the function, and Forget returns when no
		// instance of it runs.
		_ = os.Remove(filepath.Join(a.Root, id, "function.json"))
		a.Forget(id)
		if err := os.RemoveAll(filepath.Join(a.Root, id)); err != nil {
			slog.Warn("function not removed", "function", id, "error", err)
		} else {
			slog.Info("function removed", "function", id)
		}
		unlock()
	}
}

// realDirs reports whether a function's directory and its v directory, when
// they exist, are directories and not links: the agent removes files under
// them as root, and a link would lead it outside the functions' directory.
func realDirs(root, id string) bool {
	for _, path := range []string{filepath.Join(root, id), filepath.Join(root, id, "v")} {
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil || !info.IsDir() {
			return false
		}
	}
	return true
}

// inventory lists what the host holds of the functions the state names.
func (a *Agent) inventory(desired Desired) Inventory {
	inv := Inventory{Revision: desired.Revision, Functions: []HeldFunction{}}
	for _, f := range desired.Functions {
		if !nameRE.MatchString(f.ID) {
			continue
		}
		held := HeldFunction{ID: f.ID, Current: liveVersion(a.Root, f.ID), Versions: []HeldVersion{}}
		for _, v := range f.Versions {
			if message := a.failed[f.ID+"/"+v.Version]; message != "" {
				held.Versions = append(held.Versions, HeldVersion{Version: v.Version, State: "failed", Error: message})
				continue
			}
			if !Built(a.Root, f.ID, v.Version) {
				continue
			}
			dir := filepath.Join(a.Root, f.ID, "v", v.Version)
			version := HeldVersion{Version: v.Version, State: "ready", Bytes: diskUse(dir)}
			if built, err := readFunction(filepath.Join(dir, "function.json")); err == nil {
				version.Digest = built.Digest
			}
			held.Versions = append(held.Versions, version)
		}
		inv.Functions = append(inv.Functions, held)
	}
	return inv
}

// liveVersion is the version function.json names, or "".
func liveVersion(root, id string) string {
	f, err := readFunction(filepath.Join(root, id, "function.json"))
	if err != nil {
		return ""
	}
	return f.Version
}

func readFunction(path string) (Function, error) {
	var f Function
	content, err := os.ReadFile(path)
	if err == nil {
		err = json.Unmarshal(content, &f)
	}
	return f, err
}

// diskUse counts the blocks a directory's files take: a snapshot's memory
// file is sparse, and quota counts the disk it uses.
func diskUse(dir string) int64 {
	var total int64
	_ = filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return nil
		}
		if stat, ok := info.Sys().(*syscall.Stat_t); ok {
			total += stat.Blocks * 512
		}
		return nil
	})
	return total
}
