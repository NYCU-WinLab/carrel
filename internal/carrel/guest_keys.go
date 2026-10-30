package carrel

import (
	"crypto/subtle"
	_ "embed"
	"net/http"
	"regexp"
	"sort"
	"strings"
)

// A machine whose owner installs carrel-keys (issue #209) also accepts the
// keys saved in its tenant, so every member of a group tenant can reach the
// group's existing machines. The guest pulls the keys: the guest agent keeps
// its file commands blocked (PLAN 7.7), and installing the puller is the
// owner's choice, made over the owner's own SSH, as with carrel-deployd.

//go:embed keys_install.sh
var keysInstallScript string

var keyComment = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// guestMachine is the machine that sent a guest call: the call must come
// from the machine's own address and carry its readiness token.
func (e *Execution) guestMachine(body D, source string) D {
	m := e.S.Get("machines", str(body["vmid"]))
	if m == nil || source != str(m["ip"]) || str(m["readiness_token"]) == "" || subtle.ConstantTimeCompare([]byte(str(body["token"])), []byte(str(m["readiness_token"]))) != 1 {
		fail("forbidden", "Invalid guest call")
	}
	return m
}

// GuestKeys renders the tenant's saved keys as authorized_keys lines.
// A line holds the key type, the key and a comment naming who saved it:
// no options, so a saved key cannot carry command= or from= into the guest.
func (e *Execution) GuestKeys(body D, source string) string {
	m := e.guestMachine(body, source)
	n := integer(m["tenant_n"])
	if m["state"] == "deleting" || e.S.TenantN(n)["status"] != "active" {
		fail("forbidden", "Invalid guest call")
	}
	keys := rowsOf[sshKey](e.S, "keys", n)
	sort.Slice(keys, func(i, j int) bool { return keys[i].ID < keys[j].ID })
	var b strings.Builder
	for _, k := range keys {
		key := jumpKey.FindString(strings.TrimSpace(k.Key))
		if key == "" {
			continue
		}
		comment := "carrel:" + k.ID
		if keyComment.MatchString(k.By) {
			comment = "carrel:" + k.By
		}
		b.WriteString(key + " " + comment + "\n")
	}
	return b.String()
}

func (a *App) keysRoutes(mux *http.ServeMux) {
	p := a.Platform
	mux.HandleFunc("GET /keys/v1/install.sh", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
		_, _ = w.Write([]byte(strings.ReplaceAll(keysInstallScript, "@ORIGIN@", p.appOrigin())))
	})
}
