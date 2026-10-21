// carrel-fetch downloads one tenant image or ISO for carrel (PLAN 7.8). It
// runs in the unprivileged fetch container (CT 103) on the fetch network, so
// it cannot reach Proxmox, the NAS or other tenants; it still refuses every
// address that is not on the public internet, pins each name to the address
// it checked, and stops at the size and time limits it is given.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"time"
)

type job struct {
	URL      string   `json:"url"`
	SHA256   string   `json:"sha256"`
	MaxBytes int64    `json:"max_bytes"`
	Format   string   `json:"format"`
	Out      string   `json:"out"`
	Refused  []string `json:"refused"` // the site's own addresses
}

type result struct {
	OK     bool   `json:"ok"`
	Size   int64  `json:"size,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
	Code   string `json:"code,omitempty"`
	Error  string `json:"error,omitempty"`
}

const (
	maxRedirects = 3
	slowWindow   = 60 * time.Second
	slowBytes    = 2 << 20 * 60 // 2 MB/s over the window
	maxDuration  = 3 * time.Hour
	maxVirtualGB = 1000
)

type refusal struct{ code, msg string }

func (r refusal) Error() string { return r.msg }

var private = []netip.Prefix{}

func init() {
	for _, p := range []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/3", "::/128", "::1/128", "::ffff:0:0/96", "64:ff9b::/96", "100::/64", "2001:db8::/32", "fc00::/7", "fe80::/10", "ff00::/8"} {
		private = append(private, netip.MustParsePrefix(p))
	}
}

// ports a URL may name; the fetch network passes only these anyway.
var ports = map[string]bool{"": true, "80": true, "443": true}

// permit is allowed; tests swap it to reach a local server.
var permit = allowed

// allowed reports whether an address is on the public internet and not one
// of the site's own.
func allowed(a netip.Addr, refused []netip.Prefix) bool {
	a = a.Unmap()
	for _, p := range append(private, refused...) {
		if p.Contains(a) {
			return false
		}
	}
	return a.IsGlobalUnicast()
}

func checkURL(u *url.URL) error {
	if u.Scheme != "https" && u.Scheme != "http" {
		return refusal{"invalid_url", "only http and https"}
	}
	if u.User != nil {
		return refusal{"invalid_url", "credentials in the URL are refused"}
	}
	if !ports[u.Port()] {
		return refusal{"invalid_url", "only ports 80 and 443"}
	}
	return nil
}

func client(refused []netip.Prefix) *http.Client {
	dialer := &net.Dialer{Timeout: 15 * time.Second}
	transport := &http.Transport{
		Proxy: nil,
		// The name resolves once; the connection goes to the address that
		// was checked, so DNS cannot point it elsewhere in between.
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
			if err != nil || len(ips) == 0 {
				return nil, refusal{"dns_failed", "name does not resolve"}
			}
			for _, ip := range ips {
				if !permit(ip, refused) {
					return nil, refusal{"address_refused", "the name resolves to an address that is not public"}
				}
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
		},
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		MaxIdleConns:          1,
	}
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > maxRedirects {
				return refusal{"too_many_redirects", "more than 3 redirects"}
			}
			return checkURL(req.URL)
		},
	}
}

// meter counts bytes and stops at the size limit.
type meter struct {
	r     io.Reader
	total atomic.Int64
	limit int64
}

func (m *meter) Read(p []byte) (int, error) {
	n, err := m.r.Read(p)
	if m.total.Add(int64(n)) > m.limit {
		return n, refusal{"too_large", "the file is larger than allowed"}
	}
	return n, err
}

// watch cancels a download that stays slow, even one whose server stopped
// sending: a blocked Read never returns to check the rate itself.
func watch(ctx context.Context, cancel context.CancelCauseFunc, m *meter, window time.Duration, least int64) {
	tick := time.NewTicker(window)
	defer tick.Stop()
	last := int64(0)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			now := m.total.Load()
			if now-last < least {
				cancel(refusal{"too_slow", "the download stayed under 2 MB/s for 60 seconds"})
				return
			}
			last = now
		}
	}
}

// slowCheck is the window and the least bytes in it; tests shorten them.
var slowCheck = struct {
	window time.Duration
	least  int64
}{slowWindow, slowBytes}

func fetch(j job) (result, error) {
	u, err := url.Parse(j.URL)
	if err != nil {
		return result{}, refusal{"invalid_url", "unparsable URL"}
	}
	if err := checkURL(u); err != nil {
		return result{}, err
	}
	refused := []netip.Prefix{}
	for _, r := range j.Refused {
		p, err := netip.ParsePrefix(r)
		if err != nil {
			return result{}, fmt.Errorf("bad refused prefix")
		}
		refused = append(refused, p)
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	ctx, stop := context.WithTimeoutCause(ctx, maxDuration, refusal{"too_slow", "the download ran longer than 3 hours"})
	defer stop()
	req, _ := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	req.Header.Set("User-Agent", "carrel-fetch")
	resp, err := client(refused).Do(req)
	if err != nil {
		var r refusal
		if errors.As(err, &r) {
			return result{}, r
		}
		return result{}, refusal{"fetch_failed", "the server could not be reached"}
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return result{}, refusal{"fetch_failed", fmt.Sprintf("the server answered %d", resp.StatusCode)}
	}
	if resp.ContentLength > j.MaxBytes {
		return result{}, refusal{"too_large", "the file is larger than allowed"}
	}
	f, err := os.OpenFile(j.Out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return result{}, err
	}
	h := sha256.New()
	m := &meter{r: resp.Body, limit: j.MaxBytes}
	go watch(ctx, cancel, m, slowCheck.window, slowCheck.least)
	n, err := io.Copy(io.MultiWriter(f, h), m)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(j.Out)
		var r refusal
		if errors.As(err, &r) || errors.As(context.Cause(ctx), &r) {
			return result{}, r
		}
		return result{}, refusal{"fetch_failed", "the download broke off"}
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if sum != strings.ToLower(j.SHA256) {
		os.Remove(j.Out)
		return result{}, refusal{"checksum_mismatch", "the file does not match its SHA-256"}
	}
	if j.Format != "iso" {
		if err := checkImage(j.Out, j.Format); err != nil {
			os.Remove(j.Out)
			return result{}, err
		}
	}
	return result{OK: true, Size: n, SHA256: sum}, nil
}

// checkImage refuses a disk image that names other files or claims another
// format: a backing file could copy another tenant's disk into this one.
func checkImage(path, format string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, "qemu-img", "info", "--output=json", "-f", format, path).Output()
	if err != nil {
		return refusal{"image_refused", "qemu-img cannot read the file as " + format}
	}
	var info map[string]any
	if json.Unmarshal(out, &info) != nil {
		return refusal{"image_refused", "qemu-img gave no answer"}
	}
	probe, err := exec.CommandContext(ctx, "qemu-img", "info", "--output=json", path).Output()
	var probed map[string]any
	if err != nil || json.Unmarshal(probe, &probed) != nil || probed["format"] != format {
		return refusal{"image_refused", "the file is not " + format}
	}
	if info["backing-filename"] != nil || info["full-backing-filename"] != nil || info["backing-filename-format"] != nil {
		return refusal{"image_refused", "images with a backing file are refused"}
	}
	if specific, ok := info["format-specific"].(map[string]any); ok {
		data, _ := specific["data"].(map[string]any)
		if data["data-file"] != nil || data["encrypt"] != nil || data["encrypted"] == true {
			return refusal{"image_refused", "images with a data file or encryption are refused"}
		}
	}
	if info["encrypted"] == true {
		return refusal{"image_refused", "encrypted images are refused"}
	}
	if size, _ := info["virtual-size"].(float64); size > maxVirtualGB*(1<<30) {
		return refusal{"image_refused", "the virtual size is over 1000 GB"}
	}
	return nil
}

func main() {
	var j job
	in, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<16))
	if err == nil {
		err = json.Unmarshal(in, &j)
	}
	r := result{}
	if err == nil && (j.Out == "" || j.MaxBytes <= 0 || len(j.SHA256) != 64 || (j.Format != "iso" && j.Format != "qcow2" && j.Format != "raw")) {
		err = refusal{"invalid_request", "incomplete job"}
	}
	if err == nil {
		r, err = fetch(j)
	}
	if err != nil {
		r = result{Code: "fetch_failed", Error: "the download failed"}
		var ref refusal
		if errors.As(err, &ref) {
			r = result{Code: ref.code, Error: ref.msg}
		}
	}
	json.NewEncoder(os.Stdout).Encode(r)
	if !r.OK {
		os.Exit(1)
	}
}
