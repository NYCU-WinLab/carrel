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

// envAgentKey is what carrel-deployd makes on its first start.
func envAgentKey(t *testing.T, a *App, token string) hpke.PrivateKey {
	t.Helper()
	key, err := envSetKEM.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	public := base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
	body, _ := json.Marshal(D{"kem": envSetKEM.ID(), "public": public})
	code, out := do(t, a, "POST", "/apps/v1/agent/key", token, bytes.NewReader(body))
	if code != 200 || out["state"] != "trusted" {
		t.Fatalf("register: %d %s", code, encoded(out))
	}
	return key
}

// openSets is the agent opening what carrel sent it.
func openSets(t *testing.T, key hpke.PrivateKey, app string, env D) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	for _, s := range arr(env["sets"]) {
		set := obj(s)
		box, _ := base64.StdEncoding.DecodeString(str(set["box"]))
		plain, err := hpke.Open(key, envSetKDF, envSetAEAD, envInfo(app, str(set["set"]), integer(set["version"])), box)
		if err != nil {
			t.Fatalf("open %s: %v", set["set"], err)
		}
		var pairs []string
		_ = json.Unmarshal(plain, &pairs)
		out[str(set["set"])] = pairs
	}
	return out
}

func TestEnvironmentSetsAreSealedToEachAppAndOnlyThere(t *testing.T) {
	p, a, site := appFixture(t)
	p.Config.FunctionEnvKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	ctx, alice := context.Background(), person("alice", false)
	call := func(tool string, args D) D { return a.Call(ctx, tool, args, alice) }
	seedMachine(p, "api", 10101)
	r := call("app_link", D{"machine": "api", "name": "api", "repo": "alice/api", "start": "x", "port": 8000})
	assertOK(t, r)
	api := str(r["agent_token"])

	// An upload with nobody granted is refused and keeps the link.
	r = call("env_upload", D{"set": "shared"})
	assertOK(t, r)
	link := strings.TrimPrefix(str(r["url"]), "https://carrel.test")
	const marker = "s3cr3t-marker-value"
	file := "DATABASE_URL=postgres://u:" + marker + "@db/x\nMODE=prod\n"
	if code, _ := do(t, a, "PUT", link, "", strings.NewReader(file)); code != 409 {
		t.Fatalf("upload with no reader: %d", code)
	}
	assertOK(t, call("env_access", D{"set": "shared", "grant": []any{"site", "api"}}))
	// Neither agent has a key yet.
	if code, _ := do(t, a, "PUT", link, "", strings.NewReader(file)); code != 409 {
		t.Fatalf("upload with no key: %d", code)
	}
	siteKey := envAgentKey(t, a, site)
	code, out := do(t, a, "PUT", link, "", strings.NewReader(file))
	if code != 200 || integer(out["version"]) != 1 || len(arr(out["sealed_to"])) != 1 || len(arr(out["waiting_for_key"])) != 1 {
		t.Fatalf("upload: %d %s", code, encoded(out))
	}
	// The link was single-use.
	if code, _ := do(t, a, "PUT", link, "", strings.NewReader(file)); code != 404 {
		t.Fatalf("second use: %d", code)
	}

	// The site's agent gets its copy on the next poll and opens it.
	code, next := do(t, a, "POST", "/apps/v1/agent/next", site, nil)
	env := obj(next["env"])
	if code != 200 || str(env["revision"]) == "" {
		t.Fatalf("next: %d %s", code, encoded(next))
	}
	if got := openSets(t, siteKey, "site", env)["shared"]; len(got) != 2 || got[1] != "MODE=prod" {
		t.Fatalf("opened %v", got)
	}
	// The copy does not open as another app's or with another key.
	other, _ := envSetKEM.GenerateKey()
	box, _ := base64.StdEncoding.DecodeString(str(obj(arr(env["sets"])[0])["box"]))
	if _, err := hpke.Open(siteKey, envSetKDF, envSetAEAD, envInfo("api", "shared", 1), box); err == nil {
		t.Fatal("opened as another app's copy")
	}
	if _, err := hpke.Open(other, envSetKDF, envSetAEAD, envInfo("site", "shared", 1), box); err == nil {
		t.Fatal("opened with another key")
	}
	if code, _ := do(t, a, "POST", "/apps/v1/agent/env", site, strings.NewReader(`{"revision":"`+str(env["revision"])+`"}`)); code != 200 {
		t.Fatalf("report: %d", code)
	}

	// The api's agent registers; a second upload reaches both.
	apiKey := envAgentKey(t, a, api)
	r = call("env_upload", D{"set": "shared"})
	link = strings.TrimPrefix(str(r["url"]), "https://carrel.test")
	if code, out := do(t, a, "PUT", link, "", strings.NewReader(file+"V=2\n")); code != 200 || len(arr(out["sealed_to"])) != 2 {
		t.Fatalf("second upload: %d %s", code, encoded(out))
	}
	_, next = do(t, a, "POST", "/apps/v1/agent/next", api, nil)
	if got := openSets(t, apiKey, "api", obj(next["env"]))["shared"]; len(got) != 3 {
		t.Fatalf("api opened %v", got)
	}

	// Neither the database nor the configuration holds the value.
	var path string
	if err := p.Store.DB.QueryRow("SELECT file FROM pragma_database_list WHERE name='main'").Scan(&path); err != nil {
		t.Fatal(err)
	}
	config, _ := json.Marshal(p.Config)
	for _, name := range []string{path, path + "-wal"} {
		raw, _ := os.ReadFile(name)
		if bytes.Contains(raw, []byte(marker)) {
			t.Fatalf("%s holds the value", name)
		}
	}
	if bytes.Contains(config, []byte(marker)) {
		t.Fatal("the configuration holds the value")
	}
	for _, row := range p.Store.Objects("env_sets", 1) {
		if strings.Contains(string(encoded(row)), marker) {
			t.Fatal("the set record holds the value")
		}
	}
	listed := string(encoded(call("env_list", D{})))
	if strings.Contains(listed, marker) || !strings.Contains(listed, "DATABASE_URL") {
		t.Fatalf("env_list: %s", listed)
	}

	// Revoking the api after it applied the set: it is told to drop it.
	apiEnv := obj(next["env"])
	if code, _ := do(t, a, "POST", "/apps/v1/agent/env", api, strings.NewReader(`{"revision":"`+str(apiEnv["revision"])+`"}`)); code != 200 {
		t.Fatalf("api report: %d", code)
	}
	assertOK(t, call("env_access", D{"set": "shared", "revoke": []any{"api"}}))
	_, next = do(t, a, "POST", "/apps/v1/agent/next", api, nil)
	if env := obj(next["env"]); env["revision"] != "none" || len(arr(env["sets"])) != 0 {
		t.Fatalf("revoked app still gets %s", encoded(next))
	}
	r = call("env_upload", D{"set": "shared"})
	link = strings.TrimPrefix(str(r["url"]), "https://carrel.test")
	if code, out := do(t, a, "PUT", link, "", strings.NewReader("V=3\n")); code != 200 || string(encoded(out["sealed_to"])) != `["site"]` {
		t.Fatalf("third upload: %d %s", code, encoded(out))
	}
	for _, row := range p.Store.Objects("env_sets", 1) {
		if envSealed(row)[appID(1, "api")] != nil {
			t.Fatal("a revoked app still has a sealed copy")
		}
	}
}

func TestAChangedAgentKeyWaitsForEnvTrust(t *testing.T) {
	_, a, site := appFixture(t)
	ctx, alice := context.Background(), person("alice", false)
	envAgentKey(t, a, site)
	// The machine was rebuilt: its agent made another key.
	key, _ := envSetKEM.GenerateKey()
	public := base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
	body, _ := json.Marshal(D{"kem": envSetKEM.ID(), "public": public})
	code, out := do(t, a, "POST", "/apps/v1/agent/key", site, bytes.NewReader(body))
	if code != 200 || out["state"] != "pending" {
		t.Fatalf("changed key: %d %s", code, encoded(out))
	}
	got := obj(obj(a.Call(ctx, "app_get", D{"app": "site"}, alice)["app"])["env"])
	if got["new_key_fingerprint"] != keyFingerprint(public) {
		t.Fatalf("app_get env %s", encoded(got))
	}
	assertCode(t, a.Call(ctx, "env_trust", D{"app": "site", "fingerprint": "SHA256:" + strings.Repeat("A", 43)}, alice), "invalid")
	assertOK(t, a.Call(ctx, "env_trust", D{"app": "site", "fingerprint": keyFingerprint(public)}, alice))
	got = obj(obj(a.Call(ctx, "app_get", D{"app": "site"}, alice)["app"])["env"])
	if got["fingerprint"] != keyFingerprint(public) || got["new_key_fingerprint"] != nil {
		t.Fatalf("after trust %s", encoded(got))
	}
	// A key of another suite is refused.
	if code, _ := do(t, a, "POST", "/apps/v1/agent/key", site, strings.NewReader(`{"kem":32,"public":"AAAA"}`)); code != 400 {
		t.Fatalf("other suite: %d", code)
	}
}

func TestAnUnlinkedAppLosesItsGrants(t *testing.T) {
	p, a, site := appFixture(t)
	ctx, alice := context.Background(), person("alice", false)
	envAgentKey(t, a, site)
	assertOK(t, a.Call(ctx, "env_upload", D{"set": "shared"}, alice))
	assertOK(t, a.Call(ctx, "env_access", D{"set": "shared", "grant": []any{"site"}}, alice))
	assertOK(t, a.Call(ctx, "app_unlink", D{"app": "site", "confirm": "site"}, alice))
	if s := p.Store.Get("env_sets", envSetID(1, "shared")); len(envRecipients(s)) != 0 {
		t.Fatalf("grants kept: %s", encoded(s))
	}
	assertCode(t, a.Call(ctx, "env_remove", D{"set": "shared", "confirm": "other"}, alice), "invalid")
	assertOK(t, a.Call(ctx, "env_remove", D{"set": "shared", "confirm": "shared"}, alice))
	if p.Store.Get("env_sets", envSetID(1, "shared")) != nil {
		t.Fatal("set kept")
	}
}
