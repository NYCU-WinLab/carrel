package carrel

import (
	"encoding/json"
	"fmt"
	"regexp"
)

// snapshotMigration is the site row that marks the move of the core
// snapshot rows into the plugin ledger as done (#663).
const snapshotMigration = "snapshot_plugin_objects"

// snapshotPluginName is the rule the snapshot plugin holds names to: PVE
// refuses a one-character snapshot name.
var snapshotPluginName = regexp.MustCompile(`^[a-z][a-z0-9-]{1,31}$`)

// snapshotPluginQuota and snapshotPluginTools are what the snapshot plugin
// declares (plugins/snapshot Describe; a test holds them equal). The
// migration writes them, so a call before the first report answers
// unavailable and the limits stay where they were.
var snapshotPluginQuota = []D{
	{"name": "snapshot_gb", "default_limit": 200.0, "unit": "GiB", "measured": true, "plugin": "snapshot"},
	{"name": "snapshots", "default_limit": 4.0, "unit": "", "measured": false, "plugin": "snapshot"},
}

var snapshotPluginTools = []D{
	{"name": "snapshot_create", "plugin": "snapshot", "member": true, "read_only": false, "kind": "snapshot", "dims": []any{"snapshots", "snapshot_gb"}},
	{"name": "snapshot_delete", "plugin": "snapshot", "member": true, "read_only": false, "kind": "snapshot", "dims": []any{"snapshots", "snapshot_gb"}},
	{"name": "snapshot_list", "plugin": "snapshot", "member": true, "read_only": true, "kind": "snapshot", "dims": []any{"snapshots", "snapshot_gb"}},
	{"name": "snapshot_rollback", "plugin": "snapshot", "member": true, "read_only": false, "kind": "snapshot", "dims": []any{"snapshots", "snapshot_gb"}},
}

// MigrateSnapshots moves every core snapshot row into the plugin ledger, in
// one transaction, at each start before any operation is recovered. A move,
// not a copy: a binary rollback to a release before #663 still counts and
// holds the moved snapshots as plugin objects, once, and a snapshot that
// release takes is moved at the next start. Anything the move cannot carry
// stops the start: an operation on snapshots still running, a snapshot that
// is not ready, a name the plugin refuses, a row with no configuration, or
// a record that exists already. The plugin's tool and quota rows are written
// on the first move only, so a later report's values are not undone.
func MigrateSnapshots(s *Store) (result D, err error) {
	defer func() {
		if r := recover(); r != nil {
			result, err = nil, fmt.Errorf("snapshot migration: %v", r)
		}
	}()
	moved := 0
	s.Transaction(func(tx *Store) {
		rows := tx.Rows("SELECT tenant, data FROM objects WHERE kind='snapshots' ORDER BY id")
		done := tx.SiteGet("migration", snapshotMigration)
		if done != nil && len(rows) == 0 {
			return
		}
		for _, op := range tx.ActiveOperations() {
			switch op["tool"] {
			case "snapshot_create", "snapshot_delete", "snapshot_rollback":
				panic(fmt.Sprintf("operation %s (%s) is still %s: let it end first", op["id"], op["tool"], op["state"]))
			}
		}
		for _, r := range rows {
			var snap snapshotRecord
			must(json.Unmarshal([]byte(str(r["data"])), &snap))
			n := integer(r["tenant"])
			switch {
			case snap.State != "" && snap.State != "ready":
				panic(fmt.Sprintf("snapshot %s is %s, not ready", snap.ID, snap.State))
			case !snapshotPluginName.MatchString(snap.Name):
				panic(fmt.Sprintf("snapshot %s has a name the plugin refuses", snap.ID))
			case snap.Configuration == nil:
				panic(fmt.Sprintf("snapshot %s has no configuration", snap.ID))
			}
			id := pluginObjectID("snapshot", "snapshot", snap.VMID, snap.Name)
			if tx.Get(pluginObjectRows, id) != nil {
				panic(fmt.Sprintf("plugin object %s exists already", id))
			}
			rec := pluginObject{ID: id, Plugin: "snapshot", Kind: "snapshot", Name: snap.Name, VMID: snap.VMID, State: "ready",
				Charge: map[string]float64{"snapshots": 1, "snapshot_gb": float64(snap.DiskGB)}, Holds: []string{"freeze", "migrate", "backfill"},
				DiskGB: snap.DiskGB, OperationID: snap.OperationID, Configuration: snap.Configuration}
			tx.Put(pluginObjectRows, id, n, decode(string(encoded(rec))))
			tx.Remove("snapshots", snap.ID)
			moved++
		}
		total := moved
		if done == nil {
			for _, q := range snapshotPluginQuota {
				tx.SitePut(pluginQuotaRows, str(q["name"]), q)
			}
			for _, t := range snapshotPluginTools {
				tx.SitePut(pluginToolRows, str(t["name"]), t)
			}
		} else {
			total += integer(done["moved"])
		}
		tx.SitePut("migration", snapshotMigration, D{"moved": total, "at": now()})
	})
	return D{"moved": moved}, nil
}
