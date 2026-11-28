package carrel

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

const testSourceSecret = "11111111-2222-3333-4444-555555555555"

// proxmoxFake answers like the read-only part of a Proxmox API.
func proxmoxFake(t *testing.T, tokenID, secret string) (*httptest.Server, string) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("source called with %s", r.Method)
		}
		if r.Header.Get("Authorization") != "PVEAPIToken="+tokenID+"="+secret {
			http.Error(w, `{"data":null}`, http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api2/json/version":
			fmt.Fprint(w, `{"data":{"version":"8.4.1","release":"8.4"}}`)
		case "/api2/json/storage":
			fmt.Fprint(w, `{"data":[{"storage":"local","type":"dir"},{"storage":"tank","type":"zfspool"},{"storage":"local-zfs","type":"zfspool"}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	sum := sha256.Sum256(srv.Certificate().Raw)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return srv, strings.Join(parts, ":")
}

func sourceArgs(srv *httptest.Server, fingerprint string) D {
	return D{"name": "old-lab", "api_url": srv.URL, "token_id": "carrel@pve!import", "secret": testSourceSecret, "fingerprint": fingerprint}
}

func TestSourceAdd(t *testing.T) {
	var logs bytes.Buffer
	saved := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(saved) })
	p, _ := fixture(t)
	p.Config.SourceDir = t.TempDir()
	srv, fp := proxmoxFake(t, "carrel@pve!import", testSourceSecret)
	admin, alice := person("root", true), person("alice", false)
	run := func(a, who D) D { return p.Execute(context.Background(), "source_add", a, who) }

	// A member is refused, and nothing is stored.
	if r := run(sourceArgs(srv, fp), alice); r["ok"] == true || obj(r["error"])["code"] != "forbidden" {
		t.Fatalf("non-admin: %v", r)
	}
	if p.Store.SiteGet("source", "old-lab") != nil {
		t.Fatal("a refused call stored a source")
	}

	// A wrong secret is rejected.
	bad := sourceArgs(srv, fp)
	bad["secret"] = "99999999-2222-3333-4444-555555555555"
	if r := run(bad, admin); r["ok"] == true || obj(r["error"])["code"] != "invalid" {
		t.Fatalf("bad token: %v", r)
	}
	// A certificate that does not match the pin is rejected.
	other := strings.Repeat("AA:", 31) + "AA"
	if r := run(sourceArgs(srv, other), admin); r["ok"] == true || obj(r["error"])["code"] != "invalid" {
		t.Fatalf("bad fingerprint: %v", r)
	}
	// A plain http address never gets the token.
	plain := sourceArgs(srv, fp)
	plain["api_url"] = strings.Replace(srv.URL, "https://", "http://", 1)
	if r := run(plain, admin); r["ok"] == true || obj(r["error"])["code"] != "invalid" {
		t.Fatalf("http url: %v", r)
	}

	// dry_run checks the token and stores nothing.
	dry := sourceArgs(srv, fp)
	dry["dry_run"] = true
	r := run(dry, admin)
	if r["ok"] != true || r["dry_run"] != true {
		t.Fatalf("dry run: %v", r)
	}
	if p.Store.SiteGet("source", "old-lab") != nil {
		t.Fatal("dry_run stored a source")
	}
	if _, err := os.Stat(p.execution(context.Background()).sourceSecretPath("old-lab")); err == nil {
		t.Fatal("dry_run wrote the secret")
	}

	// The real call stores the record and the secret file.
	r = run(sourceArgs(srv, fp), admin)
	if r["ok"] != true {
		t.Fatalf("source_add: %v", r)
	}
	src := obj(r["source"])
	if src["version"] != "8.4.1" || fmt.Sprint(src["storage_types"]) != "[dir zfspool]" {
		t.Errorf("source = %v", src)
	}
	rec := p.Store.SiteGet("source", "old-lab")
	if rec == nil || rec["fingerprint"] != fp {
		t.Fatalf("record = %v", rec)
	}
	path := p.execution(context.Background()).sourceSecretPath("old-lab")
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0600 {
		t.Errorf("secret file: %v %v", info, err)
	}

	// The secret is in no result, record, audit row or log line.
	rows := fmt.Sprint(r, rec, p.Store.Rows("SELECT args, outcome FROM audit"), logs.String())
	if strings.Contains(rows, testSourceSecret) || strings.Contains(rows, "99999999-2222") {
		t.Errorf("a secret leaked: %s", rows)
	}

	// The secret can come from the file instead of the argument.
	fromFile := sourceArgs(srv, fp)
	delete(fromFile, "secret")
	if r := run(fromFile, admin); r["ok"] != true {
		t.Fatalf("secret from file: %v", r)
	}
}
