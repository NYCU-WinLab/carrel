package fn

import (
	"context"
	"crypto/hpke"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTheHostKeyIsMadeOnceAndKeptPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "etc", "env.key")
	key, err := LoadEnvKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("key file %v %v", info, err)
	}
	again, err := LoadEnvKey(path)
	if err != nil || string(again.PublicKey().Bytes()) != string(key.PublicKey().Bytes()) {
		t.Fatal("a second start made another key")
	}
}

func TestAgentOpensAnEnvironmentSealedToItsKey(t *testing.T) {
	root := t.TempDir()
	key, _ := LoadEnvKey(filepath.Join(t.TempDir(), "env.key"))
	seal := func(id string, env ...string) string {
		plain, _ := json.Marshal(env)
		box, _ := hpke.Seal(key.PublicKey(), envKDF, envAEAD, envInfo(id), plain)
		return base64.StdEncoding.EncodeToString(box)
	}
	var registered map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/functions/v1/agent/key":
			_ = json.NewDecoder(r.Body).Decode(&registered)
			_, _ = w.Write([]byte(`{"state":"trusted"}`))
		case r.URL.Query().Get("version") == "v1":
			_, _ = w.Write([]byte(`{"env_box":"` + seal("t1-api", "A=1", "B=two words") + `"}`))
		case r.URL.Query().Get("version") == "v2":
			// Sealed for another function: it must not open as this one.
			_, _ = w.Write([]byte(`{"env_box":"` + seal("t1-other", "A=1") + `"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	var builds []string
	var got []string
	build := fakeBuild(root, &builds, nil)
	a := &Agent{Control: server.URL, Token: "cfh_test", Root: root, Lock: noLock, Forget: func(string) {}, failed: map[string]string{}, EnvKey: key,
		Build: func(ctx context.Context, f Function, image string, env []string, auth *RegistryAuth) error {
			got = env
			return build(ctx, f, image, env, auth)
		}}
	a.registerKey(context.Background())
	if !a.keyRegistered || registered["public"] != base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()) {
		t.Fatalf("registered %v", registered)
	}
	v1, v2 := version("v1"), version("v2")
	v1.HasEnv, v2.HasEnv = true, true
	a.apply(context.Background(), Desired{Revision: 1, Functions: []DesiredFunction{{ID: "t1-api", Current: "v1", Versions: []DesiredVersion{v1, v2}}}})
	if strings.Join(got, "|") != "A=1|B=two words" {
		t.Fatalf("env %q", got)
	}
	if !strings.Contains(a.failed["t1-api/v2"], "does not open") {
		t.Fatalf("failed %v", a.failed)
	}
}

func TestAgentOpensRegistryCredentialsSealedToItsKey(t *testing.T) {
	key, _ := LoadEnvKey(filepath.Join(t.TempDir(), "env.key"))
	seal := func(id, registry string, auth RegistryAuth) string {
		plain, _ := json.Marshal(auth)
		box, _ := hpke.Seal(key.PublicKey(), envKDF, envAEAD, append([]byte("carrel-fn-registry/v1\x00"+id+"\x00"), registry...), plain)
		return base64.StdEncoding.EncodeToString(box)
	}
	box := seal("t1-api", "ghcr.io", RegistryAuth{Registry: "ghcr.io", Username: "u", Password: "p"})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"auth_box":"` + box + `","registry":"` + r.URL.Query().Get("version") + `"}`))
	}))
	defer server.Close()
	a := &Agent{Control: server.URL, Token: "cfh_test", EnvKey: key}
	auth, err := a.fetchAuth(context.Background(), "t1-api", "ghcr.io")
	if err != nil || auth.Password != "p" {
		t.Fatalf("%+v %v", auth, err)
	}
	// Claimed for another registry, the same box does not open.
	if _, err := a.fetchAuth(context.Background(), "t1-api", "registry.example.org"); err == nil {
		t.Fatal("opened for another registry")
	}
}
