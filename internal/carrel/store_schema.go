package carrel

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"time"
)

// schemaMigrations brings the store from one schema version to the next:
// entry i moves version i to i+1, and the database keeps the version in
// PRAGMA user_version (#565). A migration that changes what the JSON in
// objects.data means is a schema change too, and gets an entry. Never edit
// or reorder an entry once released; append a new one.
//
// MigrateSnapshots is not an entry: it must also run after a release before
// #663 wrote core snapshot rows again, whatever the version says.
var schemaMigrations = []func(*sql.Tx) error{
	// 0 to 1: the tables every release before #565 made at each start.
	func(tx *sql.Tx) error {
		_, err := tx.Exec(`CREATE TABLE IF NOT EXISTS tenants(n INTEGER PRIMARY KEY AUTOINCREMENT,subject TEXT UNIQUE NOT NULL,slug TEXT UNIQUE NOT NULL,quota TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'active');
CREATE TABLE IF NOT EXISTS objects(kind TEXT NOT NULL,id TEXT NOT NULL,tenant INTEGER NOT NULL,data TEXT NOT NULL,PRIMARY KEY(kind,id),FOREIGN KEY(tenant) REFERENCES tenants(n));
CREATE INDEX IF NOT EXISTS objects_tenant ON objects(tenant,kind);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,at INTEGER NOT NULL,actor TEXT NOT NULL,tenant INTEGER,tool TEXT NOT NULL,args TEXT NOT NULL,outcome TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS oauth(kind TEXT NOT NULL,id TEXT NOT NULL,data TEXT NOT NULL,expires INTEGER NOT NULL,PRIMARY KEY(kind,id));
CREATE TABLE IF NOT EXISTS site(kind TEXT NOT NULL,id TEXT NOT NULL,data TEXT NOT NULL,PRIMARY KEY(kind,id));`)
		return err
	},
	// 1 to 2: each tenant's event log (#642).
	func(tx *sql.Tx) error {
		_, err := tx.Exec(`CREATE TABLE events(id INTEGER PRIMARY KEY AUTOINCREMENT,tenant INTEGER NOT NULL,at REAL NOT NULL,type TEXT NOT NULL,data TEXT NOT NULL);
CREATE INDEX events_tenant ON events(tenant,id);`)
		return err
	},
	// 2 to 3: when a tenant's alumni grace started and why (#861). NULL:
	// no grace.
	func(tx *sql.Tx) error {
		_, err := tx.Exec(`ALTER TABLE tenants ADD COLUMN grace_started_at INTEGER;
ALTER TABLE tenants ADD COLUMN grace_reason TEXT;`)
		return err
	},
	// 3 to 4: functions are services (#908). The kinds, the field that names
	// a service in versions, links and domains, the quota keys, the quota
	// request dimensions and quota warnings, the event types, the types a
	// webhook subscribes to and the service an unfinished domain operation
	// names move to the new names. The audit log keeps the tool names it
	// recorded.
	func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE objects SET kind='services' WHERE kind='functions';
UPDATE objects SET kind='service_versions' WHERE kind='function_versions';
UPDATE objects SET kind='service_env_links' WHERE kind='function_env_links';
UPDATE objects SET data=json_set(json_remove(data,'$.function'),'$.service',json_extract(data,'$.function'))
 WHERE kind IN ('service_versions','service_env_links','domains') AND json_type(data,'$.function') IS NOT NULL;
UPDATE objects SET data=json_set(data,'$.dimension','services') WHERE kind='requests' AND json_extract(data,'$.dimension')='functions';
UPDATE objects SET data=json_set(data,'$.dimension','service_gb') WHERE kind='requests' AND json_extract(data,'$.dimension')='function_gb';
UPDATE objects SET data=json_set(data,'$.types',(SELECT json_group_array(CASE WHEN value LIKE 'function.version.%' THEN 'service.version.'||substr(value,18) ELSE value END) FROM json_each(data,'$.types')))
 WHERE kind='webhooks' AND json_type(data,'$.types')='array';
UPDATE objects SET data=json_set(json_remove(data,'$.args.function'),'$.args.service',json_extract(data,'$.args.function'))
 WHERE kind='operations' AND json_type(data,'$.args.function') IS NOT NULL;
UPDATE site SET data=json_set(json_remove(data,'$.functions'),'$.services',json(data->'$.functions')) WHERE kind='quota_warnings' AND json_type(data,'$.functions') IS NOT NULL;
UPDATE site SET data=json_set(json_remove(data,'$.function_gb'),'$.service_gb',json(data->'$.function_gb')) WHERE kind='quota_warnings' AND json_type(data,'$.function_gb') IS NOT NULL;
UPDATE events SET data=json_set(data,'$.dimension',CASE json_extract(data,'$.dimension') WHEN 'functions' THEN 'services' ELSE 'service_gb' END)
 WHERE type='quota.warning' AND json_extract(data,'$.dimension') IN ('functions','function_gb');
UPDATE site SET kind='services' WHERE kind='functions';
UPDATE site SET kind='service_hosts' WHERE kind='function_hosts';
UPDATE site SET kind='service_host_keys' WHERE kind='function_host_keys';
UPDATE tenants SET quota=json_set(json_remove(quota,'$.functions'),'$.services',json_extract(quota,'$.functions')) WHERE json_type(quota,'$.functions') IS NOT NULL;
UPDATE tenants SET quota=json_set(json_remove(quota,'$.function_gb'),'$.service_gb',json_extract(quota,'$.function_gb')) WHERE json_type(quota,'$.function_gb') IS NOT NULL;
UPDATE events SET type='service.version.'||substr(type,18) WHERE type LIKE 'function.version.%';
UPDATE events SET data=json_set(json_remove(data,'$.function'),'$.service',json_extract(data,'$.function')) WHERE json_type(data,'$.function') IS NOT NULL;`)
		return err
	},
	// 4 to 5: the idempotency fingerprints of rows migration 4 renamed (#922).
	// A quota request keeps the fingerprint of its old dimension name and a
	// queued domain_add keeps the one of args.function, so a retry with the
	// same key and the new names would answer conflict. Each fingerprint is
	// computed again from the stored fields, the way FileRequest and the
	// operation queue compute it.
	func(tx *sql.Tx) error {
		type row struct {
			id   string
			data string
		}
		load := func(q string) ([]row, error) {
			rs, err := tx.Query(q)
			if err != nil {
				return nil, err
			}
			defer rs.Close()
			var out []row
			for rs.Next() {
				var r row
				if err := rs.Scan(&r.id, &r.data); err != nil {
					return nil, err
				}
				out = append(out, r)
			}
			return out, rs.Err()
		}
		refresh := func(kind, q string, fingerprint func(D) string) error {
			rows, err := load(q)
			if err != nil {
				return err
			}
			for _, r := range rows {
				var d D
				if err := json.Unmarshal([]byte(r.data), &d); err != nil {
					return err
				}
				f := fingerprint(d)
				if d["fingerprint"] == f {
					continue
				}
				d["fingerprint"] = f
				if _, err := tx.Exec(`UPDATE objects SET data=? WHERE kind=? AND id=? AND data=?`, string(encoded(d)), kind, r.id, r.data); err != nil {
					return err
				}
			}
			return nil
		}
		if err := refresh("requests", `SELECT id,data FROM objects WHERE kind='requests' AND json_extract(data,'$.kind')='quota' AND json_extract(data,'$.dimension') IN ('services','service_gb') AND json_type(data,'$.fingerprint')='text'`, func(d D) string {
			a := D{}
			for _, k := range []string{"dimension", "amount", "reason", "until"} {
				if v := d[k]; v != nil {
					a[k] = v
				}
			}
			return digest(string(encoded(quotaRequestKind.fingerprint(a))))
		}); err != nil {
			return err
		}
		return refresh("operations", `SELECT id,data FROM objects WHERE kind='operations' AND json_extract(data,'$.tool')='domain_add' AND json_type(data,'$.args.service') IS NOT NULL AND json_type(data,'$.fingerprint')='text'`, func(d D) string {
			return digest(string(encoded([]any{d["tool"], withoutPortalKeys(obj(d["args"]))})))
		})
	},
}

// SchemaVersion is the version this release writes and reads.
var SchemaVersion = len(schemaMigrations)

// schemaLockWait bounds how long an opener waits for the schema lock.
var schemaLockWait = 60 * time.Second

// lockSchema takes the exclusive lock without blocking forever: it retries
// LOCK_NB until schemaLockWait passes, then fails naming the lock file.
func lockSchema(lock *os.File, name string) error {
	deadline := time.Now().Add(schemaLockWait)
	for {
		err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return nil
		}
		if err != syscall.EWOULDBLOCK && err != syscall.EINTR {
			return err
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("timed out after %s waiting for the schema lock %s: another process is migrating or hung; stop it, then retry", schemaLockWait, name)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// migrateSchema refuses a database newer than this release, then applies
// each missing migration in its own transaction, which also records the new
// version. A database that holds tables already is copied first, whole and
// consistent, to <path>.schema-<from>-<stamp>; of the earlier copies from the
// same version only the oldest stays, so a migration that keeps failing keeps
// at most 2 copies. Every opener holds <path>-schema.lock meanwhile and reads
// the version under it, so the service, -backup and -reseal never apply a
// migration twice.
func migrateSchema(db *sql.DB, path string) (D, error) {
	if path != ":memory:" {
		lock, err := os.OpenFile(path+"-schema.lock", os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			return nil, err
		}
		defer lock.Close()
		if err := lockSchema(lock, path+"-schema.lock"); err != nil {
			return nil, err
		}
	}
	var version int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return nil, err
	}
	if version > SchemaVersion {
		return nil, fmt.Errorf("the database has schema version %d; this release knows up to %d: run a newer release, or stop carrel and restore %s.schema-%d-<stamp>, the copy taken before the upgrade, which loses every write since", version, SchemaVersion, path, SchemaVersion)
	}
	if version == SchemaVersion {
		return D{"version": version}, nil
	}
	out := D{"from": version, "version": SchemaVersion}
	var tables int
	if err := db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table'").Scan(&tables); err != nil {
		return nil, err
	}
	if tables > 0 && path != ":memory:" {
		// Always copy the data about to be migrated. Of the earlier copies from
		// this version keep the oldest, which the stamp sorts first, and drop
		// the rest, so a migration that keeps failing keeps at most 2 copies.
		earlier, _ := filepath.Glob(fmt.Sprintf("%s.schema-%d-*", path, version))
		sort.Strings(earlier)
		copy := fmt.Sprintf("%s.schema-%d-%s", path, version, time.Now().UTC().Format("20060102-150405.000000000"))
		if _, err := db.Exec("VACUUM INTO ?", copy); err != nil {
			return nil, fmt.Errorf("copy the database before migrating: %w", err)
		}
		if err := os.Chmod(copy, 0o600); err != nil {
			return nil, err
		}
		out["backup"] = copy
		if len(earlier) > 0 {
			out["first_backup"] = earlier[0]
			for _, old := range earlier[1:] {
				if err := os.Remove(old); err != nil && !os.IsNotExist(err) {
					slog.Warn("schema_copy_not_removed", "path", old, "error", err.Error())
				}
			}
		}
	}
	for v := version; v < SchemaVersion; v++ {
		tx, err := db.Begin()
		if err != nil {
			return nil, err
		}
		if err := schemaMigrations[v](tx); err != nil {
			tx.Rollback()
			return nil, fmt.Errorf("schema migration %d to %d: %w", v, v+1, err)
		}
		if _, err := tx.Exec(fmt.Sprintf("PRAGMA user_version=%d", v+1)); err != nil {
			tx.Rollback()
			return nil, err
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
	}
	return out, nil
}
