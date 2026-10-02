package carrel

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func runQueue(p *Platform) { p.wg.Add(1); go p.Operations.Loop(); p.Operations.Recover() }
func awaitState(t *testing.T, p *Platform, id, state string) D {
	t.Helper()
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		op := p.Store.Get("operations", id)
		if op["state"] == state || op["phase"] == state {
			return op
		}
		if contains(terminal, op["state"]) {
			t.Fatalf("unexpected outcome: %s", encoded(op))
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("job did not reach %s: %s", state, encoded(p.Store.Get("operations", id)))
	return nil
}

func TestRestartResumesReadinessWithoutRepeatingMutation(t *testing.T) {
	for _, tool := range []string{"machine_create", "snapshot_rollback", "machine_power"} {
		t.Run(tool, func(t *testing.T) {
			p, b := fixture(t)
			m := seedMachine(p, "recover", 10100)
			m["state"] = "initializing"
			m["operation_id"] = "recover-job"
			p.Store.Put("machines", 10100, 1, m)
			op := D{"id": "recover-job", "tenant_n": 1, "tool": tool, "args": D{}, "who": person("alice", false), "state": "running", "phase": "waiting_for_guest", "prepared_result": D{"machine": D{"name": "recover"}}, "rollback_restore": D{"boot_id": "old-boot"}, "power_restore": D{"boot_id": "old-boot"}}
			p.Operations.Save(op)
			p.Store.Put("guest_reports", 10100, 1, D{"boot_id": "new-boot", "reported_at": now(), "initialization_status": "complete", "application_status": "not_checked"})
			p.sshProbe = func(context.Context, D) bool { return true }
			// Reopen the same SQLite file as a new control-plane process would.
			path := str(p.Store.Rows("PRAGMA database_list")[0]["file"])
			must(p.Store.DB.Close())
			reopened, err := OpenStore(path)
			must(err)
			p.Store = reopened
			t.Cleanup(func() { reopened.DB.Close() })
			runQueue(p)
			awaitState(t, p, "recover-job", "succeeded")
			if b.count("create") != 0 || b.count("action") != 0 {
				t.Fatal("replayed an applied action")
			}
			if p.Store.Get("machines", "10100")["state"] != "ready" {
				t.Fatal("readiness not restored")
			}
		})
	}
}

func TestSuspensionDuringProbeCannotRestoreReadyState(t *testing.T) {
	p, _ := fixture(t)
	m := seedMachine(p, "suspend", 10100)
	m["state"] = "initializing"
	p.Store.Put("machines", 10100, 1, m)
	p.sshProbe = func(context.Context, D) bool {
		p.Store.Exec("UPDATE tenants SET status='suspended' WHERE n=1")
		return true
	}
	p.Store.Put("guest_reports", 10100, 1, D{"reported_at": now(), "initialization_status": "complete", "application_status": "not_checked"})
	err := attempt(func() { p.execution(context.Background()).WaitReady(m, "") })
	if err == nil || obj(failureResult(err)["error"])["code"] != "forbidden" {
		t.Fatal("suspension ignored")
	}
	if p.Store.Get("machines", "10100")["state"] == "ready" {
		t.Fatal("stale readiness overwrote suspension")
	}
}

func TestConcurrentCreatesCountPendingReservations(t *testing.T) {
	p, b := fixture(t)
	obj(obj(b.inventory["status"])["cpuinfo"])["cpus"] = 1
	runQueue(p)
	who := person("alice", false)
	args := D{"name": "one", "cpu": 3, "wait_seconds": 0, "ssh_keys": []any{"ssh-ed25519 AAAA test"}}
	one := p.Execute(context.Background(), "machine_create", args, who)
	assertOK(t, one)
	awaitState(t, p, str(obj(one["operation"])["id"]), "waiting_for_guest")
	two := p.Execute(context.Background(), "machine_create", merge(args, D{"name": "two"}), who)
	assertOK(t, two)
	result := awaitState(t, p, str(obj(two["operation"])["id"]), "failed")
	if obj(result["error"])["code"] != "capacity_exhausted" || b.count("create") != 1 {
		t.Fatal("pending allocation was overcommitted")
	}
}

func TestDeploymentFailureCleansOnlyNewResources(t *testing.T) {
	p, b := fixture(t)
	original := seedMachine(p, "existing", 10100)
	b.call = func(r D, _ string) (any, error) {
		if r["op"] == "inventory" {
			return baseInventory(), nil
		}
		if r["op"] == "create" {
			m := obj(r["machine"])
			p.Store.Put("guest_reports", m["vmid"], 1, D{"reported_at": now(), "initialization_status": "failed", "application_status": "failed"})
		}
		return D{}, nil
	}
	runQueue(p)
	r := p.Execute(context.Background(), "deployment_apply", D{"machines": []D{{"name": "failed", "ssh_keys": []any{"ssh-ed25519 AAAA test"}}}, "wait_seconds": 0}, person("alice", false))
	assertOK(t, r)
	awaitState(t, p, str(obj(r["operation"])["id"]), "rolled_back")
	if len(p.Store.Objects("machines")) != 1 || !equal(p.Store.Get("machines", "10100"), original) {
		t.Fatal("pre-existing machine changed")
	}
	if len(p.Store.Objects("ports")) != 0 {
		t.Fatal("new grant leaked")
	}
}

func TestBackupRoundTripPreservesDatabaseConfigAndSymlinks(t *testing.T) {
	p, b := fixture(t)
	root := t.TempDir()
	config := filepath.Join(root, "etc")
	must(os.MkdirAll(config, 0700))
	p.Config["database"] = filepath.Join(root, "state.db")
	p.Config["certificate_dir"] = filepath.Join(root, "certificates")
	for _, name := range []string{"config.json", "node_key", "node_key.pub", "ssh_config", "known_hosts"} {
		must(os.WriteFile(filepath.Join(config, name), []byte("fixture"), 0600))
	}
	cert := p.execution(context.Background()).CertificateDir()
	must(os.MkdirAll(filepath.Join(cert, "archive"), 0700))
	must(os.MkdirAll(filepath.Join(cert, "live"), 0700))
	must(os.WriteFile(filepath.Join(cert, "archive", "certificate"), []byte("certificate"), 0600))
	must(os.Symlink("../archive/certificate", filepath.Join(cert, "live", "certificate")))
	p.Store.OAuthPut("client", "old-client", D{"client_id": "old-client"}, 0)
	b.call = func(r D, target string) (any, error) {
		if r["op"] != "backup" || target != "carrel-edge" {
			t.Fatal("wrong backup destination")
		}
		raw, err := base64.StdEncoding.DecodeString(str(r["archive"]))
		must(err)
		gz, err := gzip.NewReader(bytes.NewReader(raw))
		must(err)
		defer gz.Close()
		archive := tar.NewReader(gz)
		files := map[string]bool{}
		for {
			h, err := archive.Next()
			if err == io.EOF {
				break
			}
			must(err)
			if filepath.IsAbs(h.Name) || strings.Contains(h.Name, "..") {
				t.Fatal("unsafe archive path")
			}
			files[h.Name] = true
			if h.Name == "carrel.db" {
				content, err := io.ReadAll(archive)
				must(err)
				dbfile := filepath.Join(root, "restored.db")
				must(os.WriteFile(dbfile, content, 0600))
				restored, err := OpenStore(dbfile)
				must(err)
				defer restored.DB.Close()
				if len(restored.Tenants()) != 3 || restored.OAuthGet("client", "old-client") == nil {
					t.Fatal("backup lost persisted state")
				}
			}
			if h.Name == "certificates/live/certificate" && (h.Typeflag != tar.TypeSymlink || h.Linkname != "../archive/certificate") {
				t.Fatal("certificate link lost")
			}
		}
		if !files["etc/carrel/node_key"] || !files["certificates/live/certificate"] {
			t.Fatal("incomplete backup")
		}
		return D{"stored": true}, nil
	}
	if _, err := p.Backup(context.Background(), config); err != nil {
		t.Fatal(err)
	}
}

func TestPythonReceiptEscaping(t *testing.T) {
	if got := pythonJSON(D{"html": "<tag>&", "text": "中文🦞\n\x7f"}); got != `{"html": "<tag>&", "text": "\u4e2d\u6587\ud83e\udd9e\n\u007f"}` {
		t.Fatal(got)
	}
}
