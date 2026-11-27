package carrel

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func schemaVersionOf(t *testing.T, path string) int {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var v int
	must(db.QueryRow("PRAGMA user_version").Scan(&v))
	return v
}

// atVersion makes a database file at schema version v, with one tenant.
func atVersion(t *testing.T, v int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "carrel.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for i := 0; i < v; i++ {
		tx, _ := db.Begin()
		must(schemaMigrations[i](tx))
		must(tx.Commit())
	}
	if v == 0 {
		// A release before #565: its tables, no version.
		tx, _ := db.Begin()
		must(schemaMigrations[0](tx))
		must(tx.Commit())
	}
	_, err = db.Exec("INSERT INTO tenants(subject,slug,quota) VALUES('sub','alice','{}')")
	must(err)
	_, err = db.Exec("PRAGMA user_version=" + itoaSchema(v))
	must(err)
	return path
}

func itoaSchema(v int) string { return strconv.Itoa(v) }

// Every earlier schema opens as the current one, keeps its rows, and leaves
// a copy of itself taken before the first migration.
func TestEveryEarlierSchemaMigrates(t *testing.T) {
	for v := 0; v < SchemaVersion; v++ {
		path := atVersion(t, v)
		s, err := OpenStore(path)
		if err != nil {
			t.Fatalf("from %d: %v", v, err)
		}
		if s.Schema["version"] != SchemaVersion || s.Schema["from"] != v || len(s.Tenants()) != 1 {
			t.Fatalf("from %d: %v", v, s.Schema)
		}
		s.DB.Close()
		backup := str(s.Schema["backup"])
		info, err := os.Stat(backup)
		if err != nil || info.Mode().Perm() != 0o600 || schemaVersionOf(t, backup) != v {
			t.Fatalf("from %d: copy %s %v", v, backup, err)
		}
		if schemaVersionOf(t, path) != SchemaVersion {
			t.Fatalf("from %d: version not recorded", v)
		}
		// A second open has nothing to do.
		s, err = OpenStore(path)
		if err != nil || s.Schema["from"] != nil || s.Schema["backup"] != nil {
			t.Fatal(s.Schema, err)
		}
		s.DB.Close()
	}
}

// A new database starts at the current version and needs no copy.
func TestANewDatabaseStartsCurrent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "carrel.db")
	s, err := OpenStore(path)
	if err != nil || s.Schema["version"] != SchemaVersion || s.Schema["backup"] != nil {
		t.Fatal(s.Schema, err)
	}
	s.DB.Close()
	if matches, _ := filepath.Glob(path + ".schema-*"); len(matches) != 0 {
		t.Fatal("a new database was copied", matches)
	}
}

// A database from a newer release is refused, and left as it is.
func TestANewerSchemaIsRefused(t *testing.T) {
	path := atVersion(t, SchemaVersion)
	db, _ := sql.Open("sqlite", path)
	_, err := db.Exec("PRAGMA user_version=" + itoaSchema(SchemaVersion+1))
	must(err)
	db.Close()
	if _, err := OpenStore(path); err == nil || !strings.Contains(err.Error(), "schema version") {
		t.Fatal(err)
	}
	if schemaVersionOf(t, path) != SchemaVersion+1 {
		t.Fatal("the newer database was changed")
	}
}

// A migration that fails keeps the version it started from.
func TestAFailedMigrationKeepsTheVersion(t *testing.T) {
	saved, savedVersion := schemaMigrations, SchemaVersion
	defer func() { schemaMigrations, SchemaVersion = saved, savedVersion }()
	schemaMigrations = append(append([]func(*sql.Tx) error{}, saved...), func(tx *sql.Tx) error {
		if _, err := tx.Exec("CREATE TABLE half(x)"); err != nil {
			return err
		}
		return errors.New("broken")
	})
	SchemaVersion = len(schemaMigrations)
	path := atVersion(t, savedVersion)
	if _, err := OpenStore(path); err == nil || !strings.Contains(err.Error(), "broken") {
		t.Fatal(err)
	}
	if schemaVersionOf(t, path) != savedVersion {
		t.Fatal("the version moved")
	}
	db, _ := sql.Open("sqlite", path)
	defer db.Close()
	var n int
	must(db.QueryRow("SELECT count(*) FROM sqlite_master WHERE name='half'").Scan(&n))
	if n != 0 {
		t.Fatal("a failed migration left a table")
	}
}

// 2 openers at once apply a migration once: the second waits on the lock
// and finds the version already moved (#741 review).
func TestConcurrentOpenersMigrateOnce(t *testing.T) {
	saved, savedVersion := schemaMigrations, SchemaVersion
	defer func() { schemaMigrations, SchemaVersion = saved, savedVersion }()
	schemaMigrations = append(append([]func(*sql.Tx) error{}, saved...), func(tx *sql.Tx) error {
		time.Sleep(300 * time.Millisecond)
		_, err := tx.Exec("UPDATE tenants SET slug=slug||'+'")
		return err
	})
	SchemaVersion = len(schemaMigrations)
	path := atVersion(t, savedVersion)
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			s, err := OpenStore(path)
			if err == nil {
				s.DB.Close()
			}
			errs <- err
		}()
	}
	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	s, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.DB.Close()
	if slug := s.Tenants()[0]["slug"]; slug != "alice+" {
		t.Fatalf("slug %v: the migration ran %d times", slug, strings.Count(str(slug), "+"))
	}
	if copies, _ := filepath.Glob(path + ".schema-*"); len(copies) != 1 {
		t.Fatal("copies", copies)
	}
}

// A migration that keeps failing keeps 2 copies, not one per attempt: the
// oldest stays and the newest is replaced on every attempt.
func TestAFailingMigrationKeepsOneCopy(t *testing.T) {
	saved, savedVersion := schemaMigrations, SchemaVersion
	defer func() { schemaMigrations, SchemaVersion = saved, savedVersion }()
	schemaMigrations = append(append([]func(*sql.Tx) error{}, saved...), func(tx *sql.Tx) error { return errors.New("broken") })
	SchemaVersion = len(schemaMigrations)
	path := atVersion(t, savedVersion)
	pattern := fmt.Sprintf("%s.schema-%d-*", path, savedVersion)
	var first, second []string
	for i := 0; i < 3; i++ {
		if _, err := OpenStore(path); err == nil || !strings.Contains(err.Error(), "broken") {
			t.Fatal("a broken migration passed", err)
		}
		switch i {
		case 0:
			first, _ = filepath.Glob(pattern)
		case 1:
			second, _ = filepath.Glob(pattern)
		}
	}
	copies, _ := filepath.Glob(pattern)
	if len(first) != 1 || len(second) != 2 || len(copies) != 2 {
		t.Fatal("copies", first, second, copies)
	}
	if copies[0] != first[0] || copies[1] == second[1] {
		t.Fatal("the oldest copy must stay and the newest be replaced", first, second, copies)
	}
}

// An earlier copy from the same version is kept, copies between it and the
// new one go, and a new copy holds the data being migrated (#743).
func TestTheOldestCopyIsKept(t *testing.T) {
	saved, savedVersion := schemaMigrations, SchemaVersion
	defer func() { schemaMigrations, SchemaVersion = saved, savedVersion }()
	schemaMigrations = append(append([]func(*sql.Tx) error{}, saved...), func(tx *sql.Tx) error { return errors.New("broken") })
	SchemaVersion = len(schemaMigrations)
	path := atVersion(t, savedVersion)
	first := fmt.Sprintf("%s.schema-%d-20000101-000000.000000000", path, savedVersion)
	middle := fmt.Sprintf("%s.schema-%d-20010101-000000.000000000", path, savedVersion)
	for _, f := range []string{first, middle} {
		if err := os.WriteFile(f, []byte("old"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := OpenStore(path); err == nil || !strings.Contains(err.Error(), "broken") {
		t.Fatal("the broken migration", err)
	}
	copies, _ := filepath.Glob(fmt.Sprintf("%s.schema-%d-*", path, savedVersion))
	if len(copies) != 2 || copies[0] != first {
		t.Fatal("copies", copies)
	}
	if data, err := os.ReadFile(first); err != nil || string(data) != "old" {
		t.Fatal("the oldest copy changed", err)
	}
	db, err := sql.Open("sqlite", copies[1])
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var slug string
	if err := db.QueryRow("SELECT slug FROM tenants").Scan(&slug); err != nil || slug != "alice" {
		t.Fatal("the new copy", slug, err)
	}
}

// The result names the new copy as backup and the kept one as first_backup.
func TestMigrateReportsBothCopies(t *testing.T) {
	path := atVersion(t, SchemaVersion-1)
	first := fmt.Sprintf("%s.schema-%d-20000101-000000.000000000", path, SchemaVersion-1)
	if err := os.WriteFile(first, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.DB.Close()
	if s.Schema["first_backup"] != first || s.Schema["backup"] == nil || s.Schema["backup"] == first {
		t.Fatal("schema", s.Schema)
	}
}

func TestSchemaLockWaitIsBounded(t *testing.T) {
	old := schemaLockWait
	schemaLockWait = 200 * time.Millisecond
	defer func() { schemaLockWait = old }()
	path := filepath.Join(t.TempDir(), "carrel.db")
	held, err := os.OpenFile(path+"-schema.lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	if err := lockSchema(held, path+"-schema.lock"); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, err = migrateSchema(db, path)
	if err == nil || !strings.Contains(err.Error(), "carrel.db-schema.lock") {
		t.Fatalf("want a timeout naming the lock file, got %v", err)
	}
}
