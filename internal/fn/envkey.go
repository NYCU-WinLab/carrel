package fn

import (
	"context"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// A function host's own key (#639): the control plane seals each
// function's environment to its public key, so only this host opens it.
// The suite is carrel's for environment sets: ML-KEM-768 with X25519,
// HKDF-SHA256 and AES-256-GCM.

var (
	envKEM  = hpke.MLKEM768X25519()
	envKDF  = hpke.HKDFSHA256()
	envAEAD = hpke.AES256GCM()
)

// envInfo binds a sealed environment to the function it belongs to.
func envInfo(id string) []byte { return []byte("carrel-fn-env/v1\x00" + id) }

// LoadEnvKey reads the host's private key from path, or makes one there,
// readable by root only, on the first start.
func LoadEnvKey(path string) (hpke.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err == nil {
		return envKEM.NewPrivateKey(raw)
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	key, err := envKEM.GenerateKey()
	if err != nil {
		return nil, err
	}
	raw, err = key.Bytes()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	if _, err := f.Write(raw); err != nil {
		f.Close()
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	return key, nil
}

// Fingerprint names a public key the way carrel shows it.
func Fingerprint(public []byte) string {
	sum := sha256.Sum256(public)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// registerKey sends the public key until the control plane answers. One
// that predates host keys refuses it; the agent asks again later.
func (a *Agent) registerKey(ctx context.Context) {
	if a.EnvKey == nil || a.keyRegistered || time.Now().Before(a.keyRetryAt) {
		return
	}
	public := a.EnvKey.PublicKey().Bytes()
	var answer struct{ State string }
	err := a.call(ctx, http.MethodPost, "/functions/v1/agent/key", map[string]any{"kem": envKEM.ID(), "public": base64.StdEncoding.EncodeToString(public)}, &answer)
	if err != nil {
		slog.Warn("host key not registered", "error", err)
		a.keyRetryAt = time.Now().Add(10 * time.Minute)
		return
	}
	a.keyRegistered = true
	if answer.State == "pending" {
		slog.Error("the control plane holds another key for this host; an operator must run carrel -trust-function-host-key", "fingerprint", Fingerprint(public))
		return
	}
	slog.Info("host key registered", "fingerprint", Fingerprint(public))
}

// openEnv opens an environment sealed to this host for function id.
func (a *Agent) openEnv(id, box string) ([]string, error) {
	if a.EnvKey == nil {
		return nil, errors.New("the environment is sealed to a host key, and this host has none")
	}
	raw, err := base64.StdEncoding.DecodeString(box)
	if err != nil {
		return nil, errors.New("the sealed environment is damaged")
	}
	plain, err := hpke.Open(a.EnvKey, envKDF, envAEAD, envInfo(id), raw)
	if err != nil {
		return nil, fmt.Errorf("the environment does not open with this host's key (%s); if the host was rebuilt, upload it again with function_env", Fingerprint(a.EnvKey.PublicKey().Bytes()))
	}
	var env []string
	if json.Unmarshal(plain, &env) != nil {
		return nil, errors.New("the sealed environment is damaged")
	}
	return env, nil
}
