package carrel

import (
	"bytes"
	"context"
	"crypto/hpke"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func registerHostKey(t *testing.T, a *App, key hpke.PrivateKey) D {
	t.Helper()
	body, _ := json.Marshal(D{"kem": envSetKEM.ID(), "public": base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())})
	code, out := hostCall(t, a, "POST", "/functions/v1/agent/key", testHostToken, string(body))
	if code != 200 {
		t.Fatalf("register: %d %s", code, encoded(out))
	}
	return out
}

func sealedHostEnv(t *testing.T, a *App, version string) D {
	t.Helper()
	code, out := hostCall(t, a, "GET", "/functions/v1/agent/env?function=t1-hook&version="+version, testHostToken, "")
	if code != 200 {
		t.Fatalf("env: %d %s", code, encoded(out))
	}
	return out
}

func openHostEnv(t *testing.T, key hpke.PrivateKey, id string, out D) []string {
	t.Helper()
	box, _ := base64.StdEncoding.DecodeString(str(out["env_box"]))
	plain, err := hpke.Open(key, envSetKDF, envSetAEAD, functionEnvInfo(id), box)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	var pairs []string
	_ = json.Unmarshal(plain, &pairs)
	return pairs
}

func TestFunctionEnvironmentsAreSealedToTheHost(t *testing.T) {
	p, a := functionFixture(t)
	p.Config.FunctionEnvKey = testEnvKey
	alice := person("alice", false)
	call := func(tool string, args D) D { return a.Call(context.Background(), tool, args, alice) }
	assertOK(t, call("function_deploy", D{"name": "hook", "image": "ghcr.io/alice/hook:1", "port": 9000}))
	report(t, a, `{"revision":1,"functions":[{"id":"t1-hook","versions":[{"version":"v1","state":"ready"}]}]}`)

	// Before the host has a key: sealed under function_env_key, as before.
	const old = "old-marker-value"
	if code, out := putEnv(t, a, str(call("function_env", D{"function": "hook"})["url"]), "A="+old+"\n"); code != 200 {
		t.Fatalf("upload: %d %s", code, encoded(out))
	}
	v2 := str(p.Store.Get("functions", functionID(1, "hook"))["pending"])
	if got := sealedHostEnv(t, a, v2); strings.Join(strs(got["env"]), ",") != "A="+old {
		t.Fatalf("open env %s", encoded(got))
	}

	// The host registers: that value is sealed again to its key, and the
	// old ciphertext leaves the database files too.
	oldBox := str(p.Store.Get("function_versions", functionVersionID(functionID(1, "hook"), v2))["env"])
	key, _ := envSetKEM.GenerateKey()
	if out := registerHostKey(t, a, key); out["state"] != "trusted" || integer(out["resealed"]) != 1 {
		t.Fatalf("register %s", encoded(out))
	}
	got := sealedHostEnv(t, a, v2)
	if got["env"] != nil || strings.Join(openHostEnv(t, key, "t1-hook", got), ",") != "A="+old {
		t.Fatalf("resealed env %s", encoded(got))
	}
	report(t, a, `{"revision":2,"functions":[{"id":"t1-hook","current":"`+v2+`","versions":[{"version":"`+v2+`","state":"ready"}]}]}`)

	// A new upload goes to the host's key, and works with no function_env_key.
	p.Config.FunctionEnvKey = ""
	const marker = "host-marker-value"
	if code, out := putEnv(t, a, str(call("function_env", D{"function": "hook"})["url"]), "B="+marker+"\n"); code != 200 {
		t.Fatalf("upload: %d %s", code, encoded(out))
	}
	v3 := str(p.Store.Get("functions", functionID(1, "hook"))["pending"])
	got = sealedHostEnv(t, a, v3)
	if strings.Join(openHostEnv(t, key, "t1-hook", got), ",") != "B="+marker {
		t.Fatalf("v3 env %s", encoded(got))
	}
	// It does not open as another function's.
	box, _ := base64.StdEncoding.DecodeString(str(got["env_box"]))
	if _, err := hpke.Open(key, envSetKDF, envSetAEAD, functionEnvInfo("t1-other"), box); err == nil {
		t.Fatal("opened as another function's")
	}
	var path string
	if err := p.Store.DB.QueryRow("SELECT file FROM pragma_database_list WHERE name='main'").Scan(&path); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{path, path + "-wal"} {
		raw, _ := os.ReadFile(name)
		for _, value := range []string{marker, old, oldBox} {
			if bytes.Contains(raw, []byte(value)) {
				t.Fatalf("%s holds %s", name, value)
			}
		}
	}

	// A different key waits for an operator.
	other, _ := envSetKEM.GenerateKey()
	if out := registerHostKey(t, a, other); out["state"] != "pending" {
		t.Fatalf("changed key %s", encoded(out))
	}
	if _, err := p.TrustFunctionHostKey("fn01", "SHA256:"+strings.Repeat("A", 43)); err == nil {
		t.Fatal("trusted a wrong fingerprint")
	}
	fp := keyFingerprint(base64.StdEncoding.EncodeToString(other.PublicKey().Bytes()))
	if _, err := p.TrustFunctionHostKey("fn01", fp); err != nil {
		t.Fatal(err)
	}
	if out := registerHostKey(t, a, other); out["state"] != "trusted" {
		t.Fatalf("after trust %s", encoded(out))
	}
	// Another host's token cannot register for fn01.
	if code, _ := hostCall(t, a, "POST", "/functions/v1/agent/key", "cfh_wrong", `{}`); code != 403 {
		t.Fatalf("wrong token: %d", code)
	}
	// The reseal tool counts host-sealed values and leaves them alone.
	p.Config.FunctionEnvKey = testEnvKey
	if r, err := p.ResealFunctionValues(false); err != nil || integer(obj(r["counts"])["host"]) != 2 {
		t.Fatalf("reseal %v %v", r, err)
	}
}
