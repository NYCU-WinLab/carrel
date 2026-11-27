package carrel

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

// Members keep their SSH public keys on the lab portal. A machine created
// with no key in the request and none saved in the tenant gets its creator's
// portal key, so a member who keeps a key there never passes one. The portal
// decides which key it serves and whether the member is served at all;
// carrel asks only for the caller's own username.
//
// The keys are read once, when the call arrives: before the writer lock, so
// a slow portal holds nobody up, and before the operation is stored, so a
// resumed creation uses the keys the first attempt read.

const (
	portalKeysTimeout = 5 * time.Second
	portalKeysMax     = 20
)

var (
	portalUsername = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	// Type and key only: the portal's comment never reaches a machine.
	portalKey = regexp.MustCompile(`^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp[0-9]+) [A-Za-z0-9+/=]+`)
)

// withoutPortalKeys drops portal_keys and ca_principal from a call's
// arguments. Neither is an argument a caller may send, and both stay out of
// an operation's fingerprint so a retried submission matches after the
// member changed their key.
func withoutPortalKeys(a D) D {
	out := without(a, "portal_keys", "ca_principal")
	list, ok := a["machines"].([]any)
	if !ok {
		return out
	}
	machines := make([]any, len(list))
	for i, m := range list {
		if d, ok := m.(D); ok {
			m = without(d, "portal_keys", "ca_principal")
		}
		machines[i] = m
	}
	out["machines"] = machines
	return out
}

// withPortalKeys puts the caller's portal keys beside every machine of a
// creation that names no key. MachineSpec uses them after the request's own
// keys and the tenant's saved keys.
func (e *Execution) withPortalKeys(tool string, a, w D) D {
	if tool != "machine_create" && tool != "deployment_plan" && tool != "deployment_apply" {
		return a
	}
	a = withoutPortalKeys(a)
	if e.P.Config.PortalKeysURL == "" {
		return a
	}
	// A tenant with saved keys uses them, so its creations never ask the
	// portal. A caller outside the tenant fails later, when it is resolved.
	var t D
	if attempt(func() { t = e.Tenant(w, str(a["tenant"])) }) == nil && len(rowsOf[sshKey](e.S, "keys", integer(t["n"]))) > 0 {
		return a
	}
	var keys []any
	read := false
	fill := func(m D) D {
		if len(arr(m["ssh_keys"])) > 0 {
			return m
		}
		if !read {
			keys, read = e.portalKeys(str(w["username"])), true
		}
		if len(keys) == 0 {
			return m
		}
		return merge(m, D{"portal_keys": keys})
	}
	if tool == "machine_create" {
		return fill(a)
	}
	machines := []any{}
	for _, m := range dicts(a["machines"]) {
		machines = append(machines, fill(m))
	}
	if len(machines) > 0 {
		a["machines"] = machines
	}
	return a
}

// portalKeys reads one member's keys from the portal. Any failure reads as
// no keys: the creation then asks for one, as it did before the portal.
func (e *Execution) portalKeys(username string) []any {
	username = strings.ToLower(username)
	if !portalUsername.MatchString(username) {
		return nil
	}
	token, err := os.ReadFile(e.P.Config.PortalKeysTokenFile)
	if err != nil || strings.TrimSpace(string(token)) == "" {
		slog.Warn("portal_keys_unavailable", "event", "portal_keys_unavailable", "reason", "token")
		return nil
	}
	ctx, cancel := context.WithTimeout(e.Ctx, portalKeysTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", strings.TrimRight(e.P.Config.PortalKeysURL, "/")+"/"+username+"?format=text", nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	// A redirect is never followed: it would carry the read key to another
	// address, and over http if the portal were downgraded.
	client := &http.Client{Timeout: portalKeysTimeout, Transport: e.P.HTTP.Transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		slog.Warn("portal_keys_unavailable", "event", "portal_keys_unavailable", "reason", "request")
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		slog.Warn("portal_keys_unavailable", "event", "portal_keys_unavailable", "reason", "status", "status", resp.StatusCode)
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil
	}
	keys := []any{}
	for _, line := range strings.Split(string(body), "\n") {
		if key := portalKey.FindString(strings.TrimSpace(line)); key != "" && len(keys) < portalKeysMax {
			keys = append(keys, key)
		}
	}
	return keys
}
