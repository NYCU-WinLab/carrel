package freeze

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/NYCU-WinLab/carrel/internal/pluginpb"
)

const token = "PVEAPIToken=root@pam!carrel-freeze=secret"

// fakePVE answers the version and the token's permissions by path.
func fakePVE(privs map[string][]string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != token {
			http.Error(w, "authentication failure", http.StatusUnauthorized)
			return
		}
		reply := func(v any) { _ = json.NewEncoder(w).Encode(map[string]any{"data": v}) }
		switch r.URL.Path {
		case "/api2/json/version":
			reply(map[string]any{"version": "9.2"})
		case "/api2/json/access/permissions":
			path := r.URL.Query().Get("path")
			held := map[string]int{}
			for _, p := range privs[path] {
				held[p] = 1
			}
			reply(map[string]any{path: held})
		default:
			http.NotFound(w, r)
		}
	}
}

// fixture is a server of a site with this storage and these privileges.
func fixture(t *testing.T, storage string, privs map[string][]string) *server {
	t.Helper()
	return fixtureWith(t, storage, fakePVE(privs))
}

func fixtureWith(t *testing.T, storage string, h http.HandlerFunc) *server {
	t.Helper()
	ts := httptest.NewTLSServer(h)
	t.Cleanup(ts.Close)
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(dir, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("STATE_DIRECTORY", state)
	t.Setenv("CARREL_PVE_URL", ts.URL)
	t.Setenv("CARREL_PVE_TOKEN", token)
	t.Setenv("CARREL_PVE_NODE", "pve")
	t.Setenv("CARREL_PVE_CA", ca)
	t.Setenv("CARREL_BACKUP_STORAGE", storage)
	return newServer()
}

func probe(t *testing.T, s *server) *pluginpb.ProbeResponse {
	t.Helper()
	p, err := s.Probe(context.Background(), &pluginpb.ProbeRequest{})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDescribeListsBothOperations(t *testing.T) {
	d := Describe()
	if d.Name != "freeze" {
		t.Fatalf("name %q", d.Name)
	}
	got := map[string]*pluginpb.OperationType{}
	for _, op := range d.Operations {
		got[op.Name] = op
		if !op.Member || op.Toolset != "machines" || op.ObjectKind != "frozen" {
			t.Errorf("operation %s: %+v", op.Name, op)
		}
		var schema map[string]any
		if json.Unmarshal([]byte(op.ParamsSchema), &schema) != nil {
			t.Errorf("operation %s: schema is not JSON", op.Name)
		}
	}
	if len(got) != 2 || got["machine_freeze"] == nil || got["machine_thaw"] == nil {
		t.Fatalf("operations: %v", got)
	}
	if len(d.Objects) != 1 || !d.Objects[0].Gone || d.Objects[0].Name != "frozen" {
		t.Fatalf("objects: %v", d.Objects)
	}
}

// Describe repeats the descriptions of the tools in the live contract.
func TestDescribeMatchesTheContract(t *testing.T) {
	raw, err := os.ReadFile("../../internal/carrel/contract.json")
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		Tools []struct {
			Name        string `json:"name"`
			Description string `json:"description"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	for _, op := range Describe().Operations {
		i := slices.IndexFunc(c.Tools, func(x struct {
			Name        string `json:"name"`
			Description string `json:"description"`
		}) bool {
			return x.Name == op.Name
		})
		if i < 0 || c.Tools[i].Description != op.Description {
			t.Errorf("operation %s differs from the contract", op.Name)
		}
	}
}

func TestProbeWithNoBackupStorageIsUnsupported(t *testing.T) {
	p := probe(t, fixture(t, "", nil))
	if p.Supported || p.Reason != "The site has no backup storage (backup_storage) to freeze machines to" {
		t.Fatalf("probe: %+v", p)
	}
}

func TestProbeNeedsThePrivilegesOnTheStorage(t *testing.T) {
	vms := []string{"VM.Audit", "VM.Backup", "VM.Allocate", "VM.Config.Options"}
	all := map[string][]string{"/vms": vms, "/storage/pbs": {"Datastore.Audit", "Datastore.AllocateSpace", "Datastore.Allocate"}, "/nodes/pve": {"Sys.Audit"}}
	if p := probe(t, fixture(t, "pbs", all)); !p.Supported {
		t.Fatalf("probe: %+v", p)
	}
	short := map[string][]string{"/vms": vms, "/storage/pbs": {"Datastore.Audit", "Datastore.Allocate"}, "/nodes/pve": {"Sys.Audit"}}
	p := probe(t, fixture(t, "pbs", short))
	if p.Supported || p.Reason != "the token lacks Datastore.AllocateSpace on /storage/pbs" {
		t.Fatalf("probe: %+v", p)
	}
	// Without Sys.Audit the token sees only its own tasks, not the starts of others.
	noAudit := map[string][]string{"/vms": vms, "/storage/pbs": all["/storage/pbs"]}
	if p := probe(t, fixture(t, "pbs", noAudit)); p.Supported || p.Reason != "the token lacks Sys.Audit on /nodes/pve" {
		t.Fatalf("probe: %+v", p)
	}
}

func TestThawDoesNotRunYet(t *testing.T) {
	s := fixture(t, "pbs", nil)
	if _, err := s.StartOperation(context.Background(), &pluginpb.StartRequest{Operation: "machine_thaw"}); err == nil {
		t.Fatal("started")
	}
}
