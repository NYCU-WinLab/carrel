package pveread

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func fixtureReader(t *testing.T, handler http.HandlerFunc) *Reader {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	reader, err := New(Config{Base: server.URL, CA: ca, Node: "carrel01", Authorization: "PVEAPIToken=fixture"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reader.Close)
	return reader
}
func TestInventoryUsesVerifiedHTTPSAndBoundedParallelGETs(t *testing.T) {
	var mu sync.Mutex
	active, peak, calls := 0, 0, 0
	reader := fixtureReader(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.Header.Get("Authorization") != "PVEAPIToken=fixture" {
			t.Error("invalid request")
		}
		data := any(map[string]any{})
		if r.URL.Path == "/api2/json/access/permissions" {
			data = map[string]any{"/storage/local-lvm": map[string]any{"Datastore.Audit": 1, "Datastore.Allocate": 1}}
		} else {
			mu.Lock()
			active++
			calls++
			peak = max(peak, active)
			mu.Unlock()
			time.Sleep(20 * time.Millisecond)
			mu.Lock()
			active--
			mu.Unlock()
			if strings.HasSuffix(r.URL.Path, "/content") {
				data = []any{map[string]any{"volid": "local-lvm:vm-100-disk-0", "size": 123, "content": "images"}}
			} else if strings.HasSuffix(r.URL.Path, "/resources") {
				data = []any{}
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
	})
	result, err := reader.Read(context.Background(), "inventory")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 4 || calls != 4 || peak < 2 || peak > 4 {
		t.Fatalf("calls=%d peak=%d result=%v", calls, peak, result)
	}
}
func TestAuditorOnlyPermissionsFailClosed(t *testing.T) {
	calls := 0
	reader := fixtureReader(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"/storage/local-lvm": map[string]any{"Datastore.Audit": 1}}})
	})
	if _, err := reader.Read(context.Background(), "inventory"); err == nil || calls != 1 {
		t.Fatal("accepted filtered volume inventory")
	}
}
func TestTopologyOnlyQueriesValidatedTenantNames(t *testing.T) {
	var mu sync.Mutex
	paths := []string{}
	reader := fixtureReader(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		data := any([]any{})
		if r.URL.Path == "/api2/json/cluster/sdn/vnets" {
			data = []any{map[string]any{"vnet": "t001"}, map[string]any{"vnet": "t002"}, map[string]any{"vnet": "../../access"}, map[string]any{"vnet": "p00101"}}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
	})
	result, err := reader.Read(context.Background(), "topology")
	if err != nil {
		t.Fatal(err)
	}
	if len(result["subnets"].(map[string]any)) != 2 || len(paths) != 3 {
		t.Fatal(result, paths)
	}
	if _, err := reader.Read(context.Background(), "/access/users"); err == nil || len(paths) != 3 {
		t.Fatal("arbitrary API path accepted")
	}
}
func TestHTTPFailureAndRedirectDoNotExposeToken(t *testing.T) {
	for _, mode := range []string{"failure", "redirect"} {
		t.Run(mode, func(t *testing.T) {
			reader := fixtureReader(t, func(w http.ResponseWriter, r *http.Request) {
				if mode == "redirect" {
					http.Redirect(w, r, "https://example.com/collect", 302)
				} else {
					w.WriteHeader(500)
					_, _ = w.Write([]byte("PVEAPIToken=fixture"))
				}
			})
			_, err := reader.Read(context.Background(), "topology")
			if err == nil || strings.Contains(err.Error(), "fixture") {
				t.Fatalf("unsafe diagnostic %v", err)
			}
		})
	}
}
func TestInventoryReadsTheConfiguredStorage(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data := any(map[string]any{})
		switch {
		case r.URL.Path == "/api2/json/access/permissions":
			if r.URL.Query().Get("path") != "/storage/local-zfs" {
				t.Errorf("permissions path %q", r.URL.Query().Get("path"))
			}
			data = map[string]any{"/storage/local-zfs": map[string]any{"Datastore.Audit": 1, "Datastore.Allocate": 1}}
		case strings.Contains(r.URL.Path, "/storage/") && !strings.Contains(r.URL.Path, "/storage/local-zfs/"):
			t.Errorf("read another storage: %s", r.URL.Path)
		case strings.HasSuffix(r.URL.Path, "/content"), strings.HasSuffix(r.URL.Path, "/resources"):
			data = []any{}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
	}))
	t.Cleanup(server.Close)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	reader, err := New(Config{Base: server.URL, CA: ca, Node: "carrel02", Storage: "local-zfs", Authorization: "PVEAPIToken=fixture"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reader.Close)
	if _, err := reader.Read(context.Background(), "inventory"); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{Base: server.URL, CA: ca, Node: "carrel02", Storage: "../access", Authorization: "x"}); err == nil {
		t.Fatal("accepted an invalid storage id")
	}
}
