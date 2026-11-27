package carrel

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// legacySnapshot is a core snapshot row as the release before wrote it.
func legacySnapshot(vmid int, name string, change D) D {
	return merge(D{"id": fmt.Sprintf("%d-%s", vmid, name), "vmid": vmid, "name": name, "disk_gb": 20, "state": "ready",
		"operation_id": "op-" + name, "configuration": D{"cpu": 1, "disk_gb": 20, "memory_mb": 1024, "nics": []any{}}}, change)
}

// unmigrated is a site whose start has not moved the snapshots yet.
func unmigrated(t *testing.T) *Platform {
	t.Helper()
	p, _ := fixture(t)
	p.Store.SiteRemove("migration", snapshotMigration)
	return p
}

// The move carries each ready row into the plugin ledger and drops it from
// the core table, so a release before #663 counts it once. A row that
// release writes later is moved at the next start.
func TestSnapshotMigrationMovesReadyRows(t *testing.T) {
	p := unmigrated(t)
	old := legacySnapshot(10100, "before", nil)
	p.Store.Put("snapshots", old["id"], 1, old)
	r, err := MigrateSnapshots(p.Store)
	if err != nil || r["moved"] != 1 {
		t.Fatal(r, err)
	}
	rec := p.Store.Get(pluginObjectRows, pluginObjectID("snapshot", "snapshot", 10100, "before"))
	if rec["state"] != "ready" || num(obj(rec["charge"])["snapshot_gb"]) != 20 || num(obj(rec["charge"])["snapshots"]) != 1 ||
		len(arr(rec["holds"])) != 3 || rec["operation_id"] != "op-before" || obj(rec["configuration"])["cpu"] == nil {
		t.Fatal(string(encoded(rec)))
	}
	if p.Store.Get("snapshots", str(old["id"])) != nil {
		t.Fatal("the old row is still counted by the release before")
	}
	if r, err := MigrateSnapshots(p.Store); err != nil || r["moved"] != 0 {
		t.Fatal("second run", r, err)
	}
	// A rollback to the release before took a snapshot; the next start moves it.
	later := legacySnapshot(10100, "later", nil)
	p.Store.Put("snapshots", later["id"], 1, later)
	if r, err := MigrateSnapshots(p.Store); err != nil || r["moved"] != 1 || p.Store.Get(pluginObjectRows, pluginObjectID("snapshot", "snapshot", 10100, "later")) == nil {
		t.Fatal("after a rollback", r, err)
	}
	if m := p.Store.SiteGet("migration", snapshotMigration); num(m["moved"]) != 2 {
		t.Fatal(m)
	}
}

// Anything the move cannot carry stops it, and nothing is written.
func TestSnapshotMigrationRefusesWhatItCannotCarry(t *testing.T) {
	for name, c := range map[string]struct {
		setup func(p *Platform)
		want  string
	}{
		"creating": {func(p *Platform) {
			p.Store.Put("snapshots", "10100-s1", 1, legacySnapshot(10100, "s1", D{"state": "creating"}))
		}, "not ready"},
		"short name": {func(p *Platform) { p.Store.Put("snapshots", "10100-a", 1, legacySnapshot(10100, "a", nil)) }, "name the plugin refuses"},
		"no configuration": {func(p *Platform) {
			p.Store.Put("snapshots", "10100-s1", 1, without(legacySnapshot(10100, "s1", nil), "configuration"))
		}, "no configuration"},
		"active operation": {func(p *Platform) {
			p.Store.Put("snapshots", "10100-s1", 1, legacySnapshot(10100, "s1", nil))
			p.Store.Put("operations", "op1", 1, D{"id": "op1", "tool": "snapshot_delete", "state": "running"})
		}, "still running"},
	} {
		t.Run(name, func(t *testing.T) {
			p := unmigrated(t)
			c.setup(p)
			before, core := len(p.Store.Objects(pluginObjectRows)), len(p.Store.Objects("snapshots"))
			r, err := MigrateSnapshots(p.Store)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatal(r, err)
			}
			if len(p.Store.Objects(pluginObjectRows)) != before || len(p.Store.Objects("snapshots")) != core || p.Store.SiteGet("migration", snapshotMigration) != nil {
				t.Fatal("a refused move changed rows")
			}
		})
	}
}

// The tool and quota rows the move writes are the ones the plugin's report
// writes, so the first report changes nothing.
func TestSnapshotMigrationWritesWhatThePluginReports(t *testing.T) {
	p, b := fixture(t)
	rows := func() string {
		return string(encoded([]any{p.Store.SiteRows(pluginToolRows), p.Store.SiteRows(pluginQuotaRows)}))
	}
	before := rows()
	withSnapshotPlugin(t, p, b, nil)
	p.pluginRegistry()
	if after := rows(); !equal(decode(`{"v":`+before+`}`), decode(`{"v":`+after+`}`)) {
		t.Fatalf("migration wrote\n%s\nthe report wrote\n%s", before, after)
	}
}

// A core snapshot operation that failed before the switch is not retried
// as a plugin run: it names no plugin, and the core no longer runs it.
func TestACoreSnapshotOperationIsNotRetriedAfterTheSwitch(t *testing.T) {
	p, b := fixture(t)
	withSnapshotPlugin(t, p, b, nil)
	p.Store.Put("operations", "op1", 1, D{"id": "op1", "tenant_n": 1, "tool": "snapshot_create", "state": "failed",
		"args": D{"machine": "web", "name": "s1"}, "next_action": "operation_retry", "error": D{"code": "internal"}})
	r := p.Execute(context.Background(), "operation_retry", D{"id": "op1"}, person("alice", false))
	if f := failure(r); f["code"] != "conflict" || f["recovery"] != "retry_new_call" || !strings.Contains(str(f["message"]), "run the tool again") {
		t.Fatal(string(encoded(r)))
	}
	if op := p.Store.Get("operations", "op1"); op["state"] != "failed" || len(p.Store.Objects(pluginObjectRows)) != 0 {
		t.Fatal("the refused retry changed something")
	}
}

// Moving back before a rollback gives the release before its own rows again,
// as they were, and the next start moves them forward once more.
func TestSnapshotsMoveBackForARollback(t *testing.T) {
	p := unmigrated(t)
	old := legacySnapshot(10100, "before", nil)
	p.Store.Put("snapshots", old["id"], 1, old)
	if _, err := MigrateSnapshots(p.Store); err != nil {
		t.Fatal(err)
	}
	// A snapshot the plugin took after the switch goes back too.
	putSnapshotRecord(p, 1, 10100, "after", 30, "", D{"cpu": 2, "disk_gb": 30, "memory_mb": 2048, "nics": []any{}})
	r, err := MoveSnapshotsBack(p.Store)
	if err != nil || r["moved_back"] != 2 {
		t.Fatal(r, err)
	}
	if got := p.Store.Get("snapshots", str(old["id"])); !equal(decode(string(encoded(got))), decode(string(encoded(old)))) {
		t.Fatalf("moved back %s, was %s", encoded(got), encoded(old))
	}
	if got := p.Store.Get("snapshots", "10100-after"); num(got["disk_gb"]) != 30 || obj(got["configuration"])["cpu"] == nil || got["state"] != "ready" {
		t.Fatal(string(encoded(got)))
	}
	if len(p.Store.Objects(pluginObjectRows)) != 0 || p.Store.SiteGet("migration", snapshotMigration) != nil {
		t.Fatal("the ledger or the marker kept snapshots")
	}
	if len(p.Store.SiteRows(pluginQuotaRows)) != 0 || len(p.Store.SiteRows(pluginToolRows)) != 0 {
		t.Fatal("the move back left the plugin's site rows")
	}
	if r, err := MigrateSnapshots(p.Store); err != nil || r["moved"] != 2 || len(p.Store.Objects("snapshots")) != 0 {
		t.Fatal("forward again", r, err)
	}
}

// The move back refuses, changing nothing, while a snapshot runs or a
// record is not ready. A core row under a record's name is replaced instead
// (TestSnapshotCollisionKeepsTheRecord).
func TestSnapshotsMoveBackRefuses(t *testing.T) {
	for name, setup := range map[string]func(p *Platform){
		"running": func(p *Platform) {
			p.Store.Put("operations", "op1", 1, D{"id": "op1", "tool": "snapshot_create", "state": "running"})
		},
		"not ready": func(p *Platform) { putSnapshotRecord(p, 1, 10100, "busy", 20, "deleting", D{"cpu": 1}) },
	} {
		t.Run(name, func(t *testing.T) {
			p, _ := fixture(t)
			putSnapshotRecord(p, 1, 10100, "s1", 20, "", D{"cpu": 1})
			setup(p)
			ledger, core := len(p.Store.Objects(pluginObjectRows)), len(p.Store.Objects("snapshots"))
			if r, err := MoveSnapshotsBack(p.Store); err == nil {
				t.Fatal(r)
			}
			if len(p.Store.Objects(pluginObjectRows)) != ledger || len(p.Store.Objects("snapshots")) != core || p.Store.SiteGet("migration", snapshotMigration) == nil {
				t.Fatal("a refused move back changed rows")
			}
		})
	}
}

// The move deletes the core row by its key, not by the id in its data.
func TestSnapshotsMoveDeletesByRowKey(t *testing.T) {
	p := unmigrated(t)
	old := legacySnapshot(10100, "before", nil)
	p.Store.Put("snapshots", "other-key", 1, old)
	if _, err := MigrateSnapshots(p.Store); err != nil {
		t.Fatal(err)
	}
	if len(p.Store.Objects("snapshots")) != 0 {
		t.Fatal("the core row stayed")
	}
	if r, err := MigrateSnapshots(p.Store); err != nil || r["moved"] != 0 {
		t.Fatal(r, err)
	}
}

// A name collision merges only when both rows agree on configuration and
// size; otherwise it stops the move and changes nothing (#723).
func TestSnapshotCollision(t *testing.T) {
	cfg := D{"cpu": 1, "disk_gb": 20, "memory_mb": 1024, "nics": []any{}}
	for name, c := range map[string]struct {
		move func(*Store) (D, error)
		key  string
	}{"back": {MoveSnapshotsBack, "replaced"}, "forward": {MigrateSnapshots, "dropped"}} {
		for _, differ := range []D{nil, {"configuration": merge(cfg, D{"memory_mb": 8192})}, {"disk_gb": 40}} {
			t.Run(fmt.Sprintf("%s/%v", name, differ), func(t *testing.T) {
				p, _ := fixture(t)
				putSnapshotRecord(p, 1, 10100, "s1", 20, "", cfg)
				p.Store.Put("snapshots", "10100-s1", 1, legacySnapshot(10100, "s1", merge(D{"configuration": cfg}, differ)))
				ledger, core := len(p.Store.Objects(pluginObjectRows)), len(p.Store.Objects("snapshots"))
				r, err := c.move(p.Store)
				if differ != nil {
					if err == nil || !strings.Contains(err.Error(), "differ") || len(p.Store.Objects(pluginObjectRows)) != ledger || len(p.Store.Objects("snapshots")) != core {
						t.Fatal("a differing collision merged", r, err)
					}
					return
				}
				if err != nil || !equal(r[c.key], []any{"10100-s1"}) {
					t.Fatal(r, err)
				}
				if name == "back" && (len(p.Store.Objects(pluginObjectRows)) != 0 || p.Store.Get("snapshots", "10100-s1") == nil) {
					t.Fatal("move back left the ledger")
				}
				if name == "forward" && (len(p.Store.Objects("snapshots")) != 0 || p.Store.Get(pluginObjectRows, pluginObjectID("snapshot", "snapshot", 10100, "s1")) == nil) {
					t.Fatal("move forward left a core row")
				}
			})
		}
	}
}
