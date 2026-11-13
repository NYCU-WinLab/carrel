package carrel

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// A function's environment (PLAN 7.11) never travels in tool arguments:
// function_env gives a single-use link, the member's agent pipes an
// environment file to it, and the values are kept encrypted with
// function_env_key. Each upload makes a new version from the current one,
// because the values are part of its snapshot. A version keeps the
// environment it was built with, so a rollback brings back its values too.
// The host gets the values in its desired state and writes them into the
// version's root file system.

const (
	functionEnvLinkTTL = 15 * 60
	maxFunctionEnv     = 64 << 10
	maxFunctionEnvVars = 200
)

var functionEnvKeyRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

// reservedFunctionEnv are set by the platform for every function.
var reservedFunctionEnv = map[string]bool{"PORT": true, "HOME": true}

// parseFunctionEnv reads an environment file: KEY=VALUE lines, blank lines,
// comments, an optional "export " and one pair of matching quotes around a
// value. It returns the pairs in file order, a key given twice keeping its
// last value.
func parseFunctionEnv(content []byte) []string {
	if len(content) > maxFunctionEnv {
		fail("invalid", "The environment file exceeds 64 KiB")
	}
	values, order := map[string]string{}, []string{}
	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(make([]byte, 0, 4096), maxFunctionEnv+1)
	line := 0
	for scanner.Scan() {
		line++
		text := strings.TrimSpace(strings.TrimSuffix(scanner.Text(), "\r"))
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		text = strings.TrimPrefix(text, "export ")
		key, value, ok := strings.Cut(text, "=")
		key = strings.TrimSpace(key)
		if !ok || !functionEnvKeyRE.MatchString(key) {
			fail("invalid", "Line "+strconv.Itoa(line)+" is not KEY=VALUE with a key of letters, digits and _")
		}
		if reservedFunctionEnv[key] {
			fail("invalid", key+" is set by the platform")
		}
		value = strings.TrimSpace(value)
		if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
			value = value[1 : len(value)-1]
		}
		if strings.ContainsRune(value, 0) {
			fail("invalid", "Line "+strconv.Itoa(line)+" holds a NUL byte")
		}
		if _, seen := values[key]; !seen {
			order = append(order, key)
		}
		values[key] = value
	}
	if scanner.Err() != nil {
		fail("invalid", "The environment file could not be read")
	}
	if len(order) > maxFunctionEnvVars {
		fail("invalid", "The environment file holds more than 200 variables")
	}
	pairs := []string{}
	for _, key := range order {
		pairs = append(pairs, key+"="+values[key])
	}
	return pairs
}

func envKeys(pairs []string) []string {
	keys := []string{}
	for _, pair := range pairs {
		key, _, _ := strings.Cut(pair, "=")
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func (p *Platform) functionEnvAEAD() cipher.AEAD {
	key, err := base64.StdEncoding.DecodeString(p.Config.FunctionEnvKey)
	if p.Config.FunctionEnvKey == "" || err != nil || len(key) != 32 {
		fail("unavailable", "Function environments are not configured on this platform")
	}
	block, err := aes.NewCipher(key)
	must(err)
	aead, err := cipher.NewGCM(block)
	must(err)
	return aead
}

// sealFunctionEnv encrypts pairs for one function: the function's id is the
// additional data, so a sealed environment cannot be moved to another.
func (p *Platform) sealFunctionEnv(fid string, pairs []string) string {
	aead := p.functionEnvAEAD()
	plain, err := json.Marshal(pairs)
	must(err)
	nonce := make([]byte, aead.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	must(err)
	return base64.StdEncoding.EncodeToString(aead.Seal(nonce, nonce, plain, []byte(fid)))
}

func (p *Platform) openFunctionEnv(fid, sealed string) []string {
	if sealed == "" {
		return nil
	}
	aead := p.functionEnvAEAD()
	raw, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil || len(raw) < aead.NonceSize() {
		fail("internal", "A function environment is damaged")
	}
	plain, err := aead.Open(nil, raw[:aead.NonceSize()], raw[aead.NonceSize():], []byte(fid))
	if err != nil {
		slog.Error("function_env_open_failed", "function", fid)
		fail("internal", "A function environment cannot be decrypted")
	}
	var pairs []string
	if json.Unmarshal(plain, &pairs) != nil {
		fail("internal", "A function environment is damaged")
	}
	return pairs
}

// functionEnv runs function_env: a link to upload a new environment, or
// clear, which builds a version without one.
func (e *Execution) functionEnv(a, w, t D) D {
	n, dry := integer(t["n"]), boolean(a["dry_run"])
	f := e.Function(t, a["function"])
	e.P.functionEnvAEAD()
	if boolean(a["clear"]) {
		return e.newFunctionVersion(t, f, nil, "", dry)
	}
	if dry {
		return D{"dry_run": true, "function": f["name"]}
	}
	token := "cfe_" + random(32)
	expires := now() + functionEnvLinkTTL
	e.S.Put("function_env_links", digest(token), n, D{"id": digest(token), "tenant_n": n, "function": f["id"], "sub": w["sub"], "expires": expires})
	url := strings.TrimRight(e.P.Config.Origin, "/") + "/functions/v1/env/" + token
	return D{
		"function": f["name"], "url": url, "expires_at": expires, "single_use": true,
		"upload":      "curl --fail-with-body -X PUT --data-binary @.env " + url,
		"next_action": "Run the upload line in the directory of the environment file. Its values replace the function's whole environment and a new version builds; follow it with function_get and wait_seconds. Never paste the values into a tool argument.",
	}
}

// newFunctionVersion builds a version from the function's current spec
// with a new environment: env is the sealed environment, keys its names.
func (e *Execution) newFunctionVersion(t, f D, keys []string, env string, dry bool) D {
	if str(f["pending"]) != "" {
		fail("conflict", "A build of this function is in progress; follow it with function_get and wait_seconds", D{"pending": f["pending"]})
	}
	var base D
	for _, v := range e.FunctionVersions(f) {
		if v["version"] == f["current"] || (base == nil && str(f["current"]) == "") {
			base = v
		}
	}
	if base == nil {
		fail("conflict", "The function has no version to rebuild; deploy it first", D{"recovery": "resolve_prerequisite"})
	}
	spec := pick(base, functionSpecKeys...)
	if keys == nil {
		keys = []string{}
	}
	return e.startFunctionVersion(t, f, spec, D{}, D{"env": env, "env_keys": keys}, dry)
}

// ReceiveFunctionEnv takes an upload to a function_env link.
func (p *Platform) ReceiveFunctionEnv(ctx context.Context, token string, body io.Reader) D {
	if !strings.HasPrefix(token, "cfe_") {
		fail("not_found", "Unknown or used link")
	}
	content, err := io.ReadAll(io.LimitReader(body, maxFunctionEnv+1))
	if err != nil {
		fail("invalid", "Upload did not complete")
	}
	// Parse first: a file with a mistake leaves the link usable.
	pairs := parseFunctionEnv(content)
	e := p.execution(ctx)
	p.writer.Lock()
	defer p.writer.Unlock()
	link := e.S.Get("function_env_links", digest(token))
	if link == nil || num(link["expires"]) < now() {
		fail("not_found", "Unknown, used or expired link; ask function_env for a new one")
	}
	n := integer(link["tenant_n"])
	t := e.S.TenantN(n)
	if t == nil || t["status"] != "active" {
		fail("forbidden", "Tenant is suspended")
	}
	f := e.S.Get("functions", str(link["function"]))
	if f == nil {
		e.S.Remove("function_env_links", link["id"])
		fail("not_found", "The function was removed")
	}
	sealed := p.sealFunctionEnv(str(f["id"]), pairs)
	r := e.newFunctionVersion(t, f, envKeys(pairs), sealed, false)
	e.S.Remove("function_env_links", link["id"])
	p.Store.Log(str(link["sub"]), n, "function_env_upload", D{"function": f["name"], "keys": envKeys(pairs)}, "ok")
	return merge(r, D{"keys": envKeys(pairs)})
}
