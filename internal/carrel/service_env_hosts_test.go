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
	return registerHostKeyOpening(t, a, key, "env", "registry")
}

func registerHostKeyOpening(t *testing.T, a *App, key hpke.PrivateKey, opens ...string) D {
	t.Helper()
	body, _ := json.Marshal(D{"kem": envSetKEM.ID(), "public": base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()), "opens": opens})
	code, out := hostCall(t, a, "POST", "/services/v1/agent/key", testHostToken, string(body))
	if code != 200 {
		t.Fatalf("register: %d %s", code, encoded(out))
	}
	return out
}

func sealedHostEnv(t *testing.T, a *App, version string) D {
	t.Helper()
	code, out := hostCall(t, a, "GET", "/services/v1/agent/env?service=t1-hook&version="+version, testHostToken, "")
	if code != 200 {
		t.Fatalf("env: %d %s", code, encoded(out))
	}
	return out
}

func openHostEnv(t *testing.T, key hpke.PrivateKey, id string, out D) []string {
	t.Helper()
	box, _ := base64.StdEncoding.DecodeString(str(out["env_box"]))
	plain, err := hpke.Open(key, envSetKDF, envSetAEAD, serviceEnvInfo(id), box)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	var pairs []string
	_ = json.Unmarshal(plain, &pairs)
	return pairs
}

func TestServiceEnvironmentsAreSealedToTheHost(t *testing.T) {
	p, a := serviceFixture(t)
	p.Config.ServiceEnvKey = testEnvKey
	alice := person("alice", false)
	call := func(tool string, args D) D { return a.Call(context.Background(), tool, args, alice) }
	assertOK(t, call("service_deploy", D{"name": "hook", "image": "ghcr.io/alice/hook:1", "port": 9000}))
	report(t, a, `{"revision":1,"services":[{"id":"t1-hook","versions":[{"version":"v1","state":"ready"}]}]}`)

	// Before the host has a key: sealed under service_env_key, as before.
	const old = "old-marker-value"
	if code, out := putEnv(t, a, str(call("service_env", D{"service": "hook"})["url"]), "A="+old+"\n"); code != 200 {
		t.Fatalf("upload: %d %s", code, encoded(out))
	}
	v2 := str(p.Store.Get("services", serviceID(1, "hook"))["pending"])
	if got := sealedHostEnv(t, a, v2); strings.Join(strs(got["env"]), ",") != "A="+old {
		t.Fatalf("open env %s", encoded(got))
	}

	// The host registers: that value is sealed again to its key, and the
	// old ciphertext leaves the database files too.
	oldBox := str(p.Store.Get("service_versions", serviceVersionID(serviceID(1, "hook"), v2))["env"])
	key, _ := envSetKEM.GenerateKey()
	if out := registerHostKey(t, a, key); out["state"] != "trusted" || integer(out["resealed"]) != 1 {
		t.Fatalf("register %s", encoded(out))
	}
	got := sealedHostEnv(t, a, v2)
	if got["env"] != nil || strings.Join(openHostEnv(t, key, "t1-hook", got), ",") != "A="+old {
		t.Fatalf("resealed env %s", encoded(got))
	}
	report(t, a, `{"revision":2,"services":[{"id":"t1-hook","current":"`+v2+`","versions":[{"version":"`+v2+`","state":"ready"}]}]}`)

	// A new upload goes to the host's key, and works with no service_env_key.
	p.Config.ServiceEnvKey = ""
	const marker = "host-marker-value"
	if code, out := putEnv(t, a, str(call("service_env", D{"service": "hook"})["url"]), "B="+marker+"\n"); code != 200 {
		t.Fatalf("upload: %d %s", code, encoded(out))
	}
	v3 := str(p.Store.Get("services", serviceID(1, "hook"))["pending"])
	got = sealedHostEnv(t, a, v3)
	if strings.Join(openHostEnv(t, key, "t1-hook", got), ",") != "B="+marker {
		t.Fatalf("v3 env %s", encoded(got))
	}
	// It does not open as another service's.
	box, _ := base64.StdEncoding.DecodeString(str(got["env_box"]))
	if _, err := hpke.Open(key, envSetKDF, envSetAEAD, serviceEnvInfo("t1-other"), box); err == nil {
		t.Fatal("opened as another service's")
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
	if _, err := p.TrustServiceHostKey("fn01", "SHA256:"+strings.Repeat("A", 43)); err == nil {
		t.Fatal("trusted a wrong fingerprint")
	}
	fp := keyFingerprint(base64.StdEncoding.EncodeToString(other.PublicKey().Bytes()))
	if _, err := p.TrustServiceHostKey("fn01", fp); err != nil {
		t.Fatal(err)
	}
	if out := registerHostKey(t, a, other); out["state"] != "trusted" {
		t.Fatalf("after trust %s", encoded(out))
	}
	// Another host's token cannot register for fn01.
	if code, _ := hostCall(t, a, "POST", "/services/v1/agent/key", "cfh_wrong", `{}`); code != 403 {
		t.Fatalf("wrong token: %d", code)
	}
	// The reseal tool counts host-sealed values and leaves them alone.
	p.Config.ServiceEnvKey = testEnvKey
	if r, err := p.ResealServiceValues(false); err != nil || integer(obj(r["counts"])["host"]) != 2 {
		t.Fatalf("reseal %v %v", r, err)
	}
}

func TestRegistryCredentialsAreSealedToTheHost(t *testing.T) {
	p, a := serviceFixture(t)
	p.Config.ServiceEnvKey = testEnvKey
	alice := person("alice", false)
	call := func(tool string, args D) D { return a.Call(context.Background(), tool, args, alice) }
	assertOK(t, call("service_deploy", D{"name": "hook", "image": "ghcr.io/alice/hook:1"}))
	v1 := str(p.Store.Get("services", serviceID(1, "hook"))["pending"])
	upload := func(secret string) {
		t.Helper()
		if code, out := putEnv(t, a, str(call("service_registry", D{"service": "hook"})["url"]), `{"username":"alice","password":"`+secret+`"}`); code != 200 {
			t.Fatalf("upload: %d %s", code, encoded(out))
		}
	}
	auth := func() D {
		t.Helper()
		code, out := hostCall(t, a, "GET", "/services/v1/agent/auth?service=t1-hook&version="+v1, testHostToken, "")
		if code != 200 {
			t.Fatalf("auth: %d %s", code, encoded(out))
		}
		return out
	}
	open := func(key hpke.PrivateKey, out D, registry string) D {
		t.Helper()
		box, _ := base64.StdEncoding.DecodeString(str(out["auth_box"]))
		plain, err := hpke.Open(key, envSetKDF, envSetAEAD, registryInfo("t1-hook", registry), box)
		if err != nil {
			return nil
		}
		var d D
		_ = json.Unmarshal(plain, &d)
		return d
	}
	// Before a key: open credentials, as before.
	const old = "ghp_old-marker"
	upload(old)
	if got := obj(auth()["auth"]); got["password"] != old {
		t.Fatalf("open auth %s", encoded(got))
	}
	oldBox := str(p.Store.Get("services", serviceID(1, "hook"))["registry_auth"])
	// Registration moves them to the host's key.
	key, _ := envSetKEM.GenerateKey()
	if out := registerHostKey(t, a, key); integer(out["resealed"]) != 1 {
		t.Fatalf("register %s", encoded(out))
	}
	got := auth()
	if got["auth"] != nil || got["registry"] != "ghcr.io" || open(key, got, "ghcr.io")["password"] != old {
		t.Fatalf("sealed auth %s", encoded(got))
	}
	// Bound to the registry: it does not open as another registry's.
	if open(key, got, "registry.example.org") != nil {
		t.Fatal("opened for another registry")
	}
	// A new upload goes to the key, with no service_env_key.
	p.Config.ServiceEnvKey = ""
	const marker = "ghp_new-marker"
	upload(marker)
	if open(key, auth(), "ghcr.io")["password"] != marker {
		t.Fatal("new upload not sealed to the host")
	}
	var path string
	if err := p.Store.DB.QueryRow("SELECT file FROM pragma_database_list WHERE name='main'").Scan(&path); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{path, path + "-wal"} {
		raw, _ := os.ReadFile(name)
		for _, value := range []string{old, marker, oldBox} {
			if bytes.Contains(raw, []byte(value)) {
				t.Fatalf("%s holds %s", name, value)
			}
		}
	}
}

func TestAHostThatRegisteredBeforeStillGetsLaterValuesMoved(t *testing.T) {
	p, a := serviceFixture(t)
	p.Config.ServiceEnvKey = testEnvKey
	alice := person("alice", false)
	assertOK(t, a.Call(context.Background(), "service_deploy", D{"name": "hook", "image": "ghcr.io/alice/hook:1"}, alice))
	key, _ := envSetKEM.GenerateKey()
	registerHostKey(t, a, key)
	// A value sealed under service_env_key after registration, as a
	// release that sealed only environments left registry credentials.
	f := p.Store.Get("services", serviceID(1, "hook"))
	f["registry"], f["registry_auth"] = "ghcr.io", p.sealValue(str(f["id"])+"#registry", D{"registry": "ghcr.io", "username": "u", "password": "p"})
	p.Store.Put("services", f["id"], 1, f)
	if out := registerHostKey(t, a, key); out["state"] != "trusted" || integer(out["resealed"]) != 1 {
		t.Fatalf("second start %s", encoded(out))
	}
	if !hostSealed(str(p.Store.Get("services", serviceID(1, "hook"))["registry_auth"])) {
		t.Fatal("not moved")
	}
}

func TestAnAgentThatOpensOnlyEnvironmentsKeepsOpenCredentials(t *testing.T) {
	p, a := serviceFixture(t)
	p.Config.ServiceEnvKey = testEnvKey
	alice := person("alice", false)
	call := func(tool string, args D) D { return a.Call(context.Background(), tool, args, alice) }
	assertOK(t, call("service_deploy", D{"name": "hook", "image": "ghcr.io/alice/hook:1"}))
	v1 := str(p.Store.Get("services", serviceID(1, "hook"))["pending"])
	// An agent of #783 registers its key without naming registry.
	key, _ := envSetKEM.GenerateKey()
	registerHostKeyOpening(t, a, key)
	if code, _ := putEnv(t, a, str(call("service_registry", D{"service": "hook"})["url"]), `{"username":"u","password":"p"}`); code != 200 {
		t.Fatalf("upload: %d", code)
	}
	code, out := hostCall(t, a, "GET", "/services/v1/agent/auth?service=t1-hook&version="+v1, testHostToken, "")
	if code != 200 || obj(out["auth"])["password"] != "p" {
		t.Fatalf("old agent auth: %d %s", code, encoded(out))
	}
	// Upgraded, it says so at its next start, and the credentials move.
	if out := registerHostKeyOpening(t, a, key, "env", "registry"); integer(out["resealed"]) != 1 {
		t.Fatalf("upgraded %s", encoded(out))
	}
	if _, out := hostCall(t, a, "GET", "/services/v1/agent/auth?service=t1-hook&version="+v1, testHostToken, ""); out["auth_box"] == nil {
		t.Fatalf("not moved %s", encoded(out))
	}
}
