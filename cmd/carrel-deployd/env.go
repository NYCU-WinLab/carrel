package main

import (
	"bytes"
	"context"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Environment sets (#639): this agent makes a key pair on its first start
// and registers only the public key. carrel seals each granted set to it,
// so only this machine can open the values. They go to a root-only file in
// the agent's state directory, which a drop-in adds to the app's unit; the
// member's own /srv/apps/<app>/env is never touched.

var (
	envKEM  = hpke.MLKEM768X25519()
	envKDF  = hpke.HKDFSHA256()
	envAEAD = hpke.AES256GCM()
)

var envKeyRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

type envUpdate struct {
	Revision string `json:"revision"`
	Sets     []struct {
		Set     string `json:"set"`
		Version int    `json:"version"`
		Box     string `json:"box"`
	} `json:"sets"`
}

func (a *agent) envKeyFile() string { return filepath.Join(a.state, "env.key") }
func (a *agent) envFile() string    { return filepath.Join(a.state, "env") }
func (a *agent) dropIn() string {
	return filepath.Join(a.units, a.unit()+".d", "carrel-env.conf")
}

func envInfo(app, set string, version int) []byte {
	return fmt.Appendf(nil, "carrel-env/v1\x00%s\x00%s\x00%d", app, set, version)
}

func fingerprint(public []byte) string {
	sum := sha256.Sum256(public)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// writePrivate replaces path with content, readable by root only.
func writePrivate(path string, content []byte) error {
	pending := path + ".next"
	_ = os.Remove(pending)
	f, err := os.OpenFile(pending, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(content); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(pending, path)
}

// loadEnvKey reads this agent's private key, or makes one on the first
// start. The key never leaves the state directory.
func (a *agent) loadEnvKey() error {
	if err := os.MkdirAll(a.state, 0o700); err != nil {
		return err
	}
	raw, err := os.ReadFile(a.envKeyFile())
	if errors.Is(err, fs.ErrNotExist) {
		key, err := envKEM.GenerateKey()
		if err != nil {
			return err
		}
		raw, err = key.Bytes()
		if err != nil {
			return err
		}
		if err := writePrivate(a.envKeyFile(), raw); err != nil {
			return err
		}
		a.envKey = key
		return nil
	}
	if err != nil {
		return err
	}
	a.envKey, err = envKEM.NewPrivateKey(raw)
	return err
}

// registerEnvKey sends the public key until carrel answers. A carrel
// without environment sets answers 404; the agent asks again later.
func (a *agent) registerEnvKey(ctx context.Context) {
	if a.envKey == nil || a.envRegistered || time.Now().Before(a.envRetryAt) {
		return
	}
	public := a.envKey.PublicKey().Bytes()
	resp, err := a.request(ctx, "POST", "/apps/v1/agent/key", map[string]any{"kem": envKEM.ID(), "public": base64.StdEncoding.EncodeToString(public)})
	if err != nil {
		a.envRetryAt = time.Now().Add(time.Minute)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		a.envRetryAt = time.Now().Add(10 * time.Minute)
		return
	}
	var out struct{ State string }
	_ = json.NewDecoder(resp.Body).Decode(&out)
	a.envRegistered = true
	if out.State == "pending" {
		slog.Warn("env_key_pending: carrel holds another key for this app; a member must call env_trust with this fingerprint", "fingerprint", fingerprint(public))
		return
	}
	slog.Info("env_key_registered", "fingerprint", fingerprint(public))
}

// applyEnv writes an environment update and tells carrel how it went.
func (a *agent) applyEnv(ctx context.Context, u envUpdate) {
	message := ""
	if err := a.writeEnv(ctx, u); err != nil {
		message = err.Error()
		slog.Warn("env_failed", "revision", u.Revision, "error", message)
	} else {
		slog.Info("env_applied", "revision", u.Revision, "sets", len(u.Sets))
	}
	resp, err := a.request(ctx, "POST", "/apps/v1/agent/env", map[string]string{"revision": u.Revision, "error": message})
	if err != nil {
		slog.Warn("env_report_failed", "error", err)
		return
	}
	resp.Body.Close()
}

// openEnv opens every set and renders the environment file. A later set
// in name order wins a key two sets share.
func (a *agent) openEnv(u envUpdate) ([]byte, error) {
	if a.envKey == nil {
		return nil, errors.New("this agent has no key")
	}
	values, order := map[string]string{}, []string{}
	for _, s := range u.Sets {
		box, err := base64.StdEncoding.DecodeString(s.Box)
		if err != nil {
			return nil, fmt.Errorf("set %s is damaged", s.Set)
		}
		plain, err := hpke.Open(a.envKey, envKDF, envAEAD, envInfo(a.cfg.App, s.Set, s.Version), box)
		if err != nil {
			return nil, fmt.Errorf("set %s version %d does not open with this machine's key; if the machine was rebuilt, call env_trust and upload again", s.Set, s.Version)
		}
		var pairs []string
		if json.Unmarshal(plain, &pairs) != nil {
			return nil, fmt.Errorf("set %s is damaged", s.Set)
		}
		for _, pair := range pairs {
			key, value, _ := strings.Cut(pair, "=")
			if !envKeyRE.MatchString(key) || strings.IndexFunc(value, func(r rune) bool { return r < 0x20 && r != '\t' || r == 0x7f }) >= 0 {
				return nil, fmt.Errorf("set %s holds an invalid variable", s.Set)
			}
			if _, seen := values[key]; !seen {
				order = append(order, key)
			}
			values[key] = value
		}
	}
	// systemd's EnvironmentFile: a double-quoted value keeps spaces and
	// quotes, with backslash and the quote escaped; nothing is expanded.
	quote := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	var b bytes.Buffer
	b.WriteString("# Written by carrel-deployd from environment sets. Edit /srv/apps/" + a.cfg.App + "/env instead.\n")
	for _, key := range order {
		fmt.Fprintf(&b, "%s=\"%s\"\n", key, quote.Replace(values[key]))
	}
	return b.Bytes(), nil
}

// writeEnv opens the sets, writes the file and restarts the app. If the
// app fails its health check with the new file, the old one goes back.
func (a *agent) writeEnv(ctx context.Context, u envUpdate) error {
	content, err := a.openEnv(u)
	if err != nil {
		return err
	}
	old, err := os.ReadFile(a.envFile())
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := writePrivate(a.envFile(), content); err != nil {
		return err
	}
	if err := a.ensureDropIn(ctx); err != nil {
		return err
	}
	if _, err := os.Lstat(filepath.Join(a.root, "current")); err != nil {
		// No release runs yet: the first deploy starts with this file.
		return nil
	}
	a.inv.deploying.Lock()
	defer a.inv.deploying.Unlock()
	if err := a.restart(ctx); err != nil {
		if old != nil && writePrivate(a.envFile(), old) == nil {
			_ = a.restart(ctx)
			return fmt.Errorf("the app failed with the new environment (%v); the previous environment is back", err)
		}
		return fmt.Errorf("the app failed with the new environment: %v", err)
	}
	return nil
}

// ensureDropIn adds the environment file to the app's unit, after the
// member's own file, so a set's value wins a key both name.
func (a *agent) ensureDropIn(ctx context.Context) error {
	want := []byte("[Service]\nEnvironmentFile=-" + a.envFile() + "\n")
	if have, err := os.ReadFile(a.dropIn()); err == nil && bytes.Equal(have, want) {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(a.dropIn()), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(a.dropIn(), want, 0o644); err != nil {
		return err
	}
	return a.reload(ctx)
}

func systemdReload(ctx context.Context) error {
	if out, err := exec.CommandContext(ctx, "systemctl", "daemon-reload").CombinedOutput(); err != nil {
		return fmt.Errorf("daemon-reload: %s", strings.TrimSpace(string(out)))
	}
	return nil
}
