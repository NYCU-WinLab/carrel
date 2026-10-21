package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOnlyPublicAddressesAreAllowed(t *testing.T) {
	site := []netip.Prefix{netip.MustParsePrefix("140.113.60.184/32")}
	for addr, want := range map[string]bool{
		"1.1.1.1": true, "140.113.60.185": true, "2606:4700::1111": true,
		"10.200.1.10": false, "192.168.11.41": false, "127.0.0.1": false, "169.254.169.254": false,
		"100.64.0.1": false, "140.113.60.184": false, "::1": false, "::ffff:10.0.0.1": false,
		"fd00::1": false, "224.0.0.1": false, "0.0.0.0": false,
	} {
		if got := allowed(netip.MustParseAddr(addr), site); got != want {
			t.Errorf("%s: %v", addr, got)
		}
	}
}

func refusedCode(err error) string {
	var r refusal
	if errors.As(err, &r) {
		return r.code
	}
	return ""
}

func TestFetchChecksEveryStep(t *testing.T) {
	body := strings.Repeat("carrel", 1000)
	sum := sha256.Sum256([]byte(body))
	good := hex.EncodeToString(sum[:])
	hops := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/file.iso":
			w.Write([]byte(body))
		case "/loop":
			hops++
			http.Redirect(w, r, "/loop", http.StatusFound)
		case "/to-ftp":
			http.Redirect(w, r, "ftp://example.com/x", http.StatusFound)
		case "/to-file":
			http.Redirect(w, r, "/file.iso", http.StatusFound)
		}
	}))
	defer srv.Close()
	dir := t.TempDir()
	srvURL, _ := url.Parse(srv.URL)
	ports[srvURL.Port()] = true
	defer delete(ports, srvURL.Port())
	count := 0
	run := func(path, digest string, max int64) (result, error) {
		count++
		out := filepath.Join(dir, fmt.Sprint(count))
		return fetch(job{URL: srv.URL + path, SHA256: digest, MaxBytes: max, Format: "iso", Out: out})
	}
	// The test server is on loopback: refused until the test allows it.
	if _, err := run("/file.iso", good, 1<<20); refusedCode(err) != "address_refused" {
		t.Fatal("reached loopback", err)
	}
	permit = func(netip.Addr, []netip.Prefix) bool { return true }
	defer func() { permit = allowed }()
	if r, err := run("/file.iso", good, 1<<20); err != nil || !r.OK || r.Size != int64(len(body)) {
		t.Fatal(r, err)
	}
	if _, err := run("/to-file", good, 1<<20); err != nil {
		t.Fatal("one redirect must work", err)
	}
	if _, err := run("/file.iso", strings.Repeat("0", 64), 1<<20); refusedCode(err) != "checksum_mismatch" {
		t.Fatal(err)
	}
	if _, err := run("/file.iso", good, 100); refusedCode(err) != "too_large" {
		t.Fatal(err)
	}
	if _, err := run("/loop", good, 1<<20); refusedCode(err) != "too_many_redirects" || hops != 4 {
		t.Fatal(err, hops)
	}
	if _, err := run("/to-ftp", good, 1<<20); refusedCode(err) != "invalid_url" {
		t.Fatal(err)
	}
	if _, err := fetch(job{URL: "http://user:pw@example.com/x", SHA256: good, MaxBytes: 1, Format: "iso", Out: filepath.Join(dir, "x")}); refusedCode(err) != "invalid_url" {
		t.Fatal(err)
	}
	if _, err := fetch(job{URL: "https://example.com:8443/x", SHA256: good, MaxBytes: 1, Format: "iso", Out: filepath.Join(dir, "y")}); refusedCode(err) != "invalid_url" {
		t.Fatal(err)
	}
	// Nothing is left behind by a refusal.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 2 { // the two downloads that succeeded
		t.Fatal("left files", len(entries))
	}
}

func TestImagesThatNameOtherFilesAreRefused(t *testing.T) {
	if _, err := exec.LookPath("qemu-img"); err != nil {
		t.Skip("qemu-img not installed")
	}
	dir := t.TempDir()
	q := func(args ...string) {
		if out, err := exec.Command("qemu-img", args...).CombinedOutput(); err != nil {
			t.Fatal(string(out))
		}
	}
	base, plain, backed, datafile, encrypted, raw := filepath.Join(dir, "base.qcow2"), filepath.Join(dir, "plain.qcow2"), filepath.Join(dir, "backed.qcow2"), filepath.Join(dir, "data.qcow2"), filepath.Join(dir, "enc.qcow2"), filepath.Join(dir, "disk.raw")
	q("create", "-f", "qcow2", base, "1G")
	q("create", "-f", "qcow2", plain, "1G")
	q("create", "-f", "qcow2", "-b", base, "-F", "qcow2", backed)
	q("create", "-f", "qcow2", "-o", "data_file="+filepath.Join(dir, "external.raw"), datafile, "1G")
	q("create", "-f", "qcow2", "--object", "secret,id=s,data=pw", "-o", "encrypt.format=luks,encrypt.key-secret=s", encrypted, "1G")
	q("create", "-f", "raw", raw, "1G")
	if v, err := checkImage(plain, "qcow2"); err != nil || v != 1<<30 {
		t.Fatal("refused a plain image", err)
	}
	if _, err := checkImage(raw, "raw"); err != nil {
		t.Fatal("refused a raw image", err)
	}
	for name, c := range map[string][2]string{"backing file": {backed, "qcow2"}, "data file": {datafile, "qcow2"}, "encrypted": {encrypted, "qcow2"}, "qcow2 sent as raw": {plain, "raw"}, "raw sent as qcow2": {raw, "qcow2"}} {
		if _, err := checkImage(c[0], c[1]); refusedCode(err) != "image_refused" {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
	q("create", "-f", "qcow2", filepath.Join(dir, "huge.qcow2"), "1001G")
	if _, err := checkImage(filepath.Join(dir, "huge.qcow2"), "qcow2"); refusedCode(err) != "image_refused" {
		t.Error("accepted a 1001 GB disk")
	}
}

func TestAServerThatStopsSendingIsCutOff(t *testing.T) {
	stall := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000000")
		w.Write([]byte("x"))
		w.(http.Flusher).Flush()
		<-stall
	}))
	// The handler must return before Close can.
	defer srv.Close()
	defer close(stall)
	u, _ := url.Parse(srv.URL)
	ports[u.Port()] = true
	defer delete(ports, u.Port())
	permit = func(netip.Addr, []netip.Prefix) bool { return true }
	defer func() { permit = allowed }()
	saved := slowCheck
	slowCheck.window, slowCheck.least = 300*time.Millisecond, 1000
	defer func() { slowCheck = saved }()
	start := time.Now()
	_, err := fetch(job{URL: srv.URL + "/x", SHA256: strings.Repeat("0", 64), MaxBytes: 1 << 20, Format: "iso", Out: filepath.Join(t.TempDir(), "x")})
	if refusedCode(err) != "too_slow" || time.Since(start) > 5*time.Second {
		t.Fatal(err, time.Since(start))
	}
}
