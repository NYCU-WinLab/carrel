package carrel

import (
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
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
}

// SchemaVersion is the version this release writes and reads.
var SchemaVersion = len(schemaMigrations)

// migrateSchema refuses a database newer than this release, then applies
// each missing migration in its own transaction, which also records the new
// version. A database that holds tables already is copied first, whole and
// consistent, to <path>.schema-<from>-<stamp>; an older copy from the same
// version goes, so a migration that keeps failing keeps one copy. Every
// opener holds <path>-schema.lock meanwhile and reads the version under it,
// so the service, -backup and -reseal never apply a migration twice.
func migrateSchema(db *sql.DB, path string) (D, error) {
	if path != ":memory:" {
		lock, err := os.OpenFile(path+"-schema.lock", os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			return nil, err
		}
		defer lock.Close()
		if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
			return nil, err
		}
	}
	var version int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return nil, err
	}
	if version > SchemaVersion {
		return nil, fmt.Errorf("the database has schema version %d; this release knows up to %d: run a newer release, or restore the backup taken before the upgrade", version, SchemaVersion)
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
		earlier, _ := filepath.Glob(fmt.Sprintf("%s.schema-%d-*", path, version))
		copy := fmt.Sprintf("%s.schema-%d-%s", path, version, time.Now().UTC().Format("20060102-150405.000000000"))
		if _, err := db.Exec("VACUUM INTO ?", copy); err != nil {
			return nil, fmt.Errorf("copy the database before migrating: %w", err)
		}
		if err := os.Chmod(copy, 0o600); err != nil {
			return nil, err
		}
		for _, old := range earlier {
			if err := os.Remove(old); err != nil && !os.IsNotExist(err) {
				slog.Warn("schema_copy_not_removed", "path", old, "error", err.Error())
			}
		}
		out["backup"] = copy
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
