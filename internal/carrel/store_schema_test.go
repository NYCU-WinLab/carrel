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

// A migration that keeps failing keeps one copy, not one per attempt.
func TestAFailingMigrationKeepsOneCopy(t *testing.T) {
	saved, savedVersion := schemaMigrations, SchemaVersion
	defer func() { schemaMigrations, SchemaVersion = saved, savedVersion }()
	schemaMigrations = append(append([]func(*sql.Tx) error{}, saved...), func(tx *sql.Tx) error { return errors.New("broken") })
	SchemaVersion = len(schemaMigrations)
	path := atVersion(t, savedVersion)
	for i := 0; i < 3; i++ {
		if _, err := OpenStore(path); err == nil {
			t.Fatal("a broken migration passed")
		}
	}
	if copies, _ := filepath.Glob(fmt.Sprintf("%s.schema-%d-*", path, savedVersion)); len(copies) != 1 {
		t.Fatal("copies", copies)
	}
}

// An earlier copy from the same version is kept; no newer copy replaces it.
func TestTheOldestCopyIsKept(t *testing.T) {
	saved, savedVersion := schemaMigrations, SchemaVersion
	defer func() { schemaMigrations, SchemaVersion = saved, savedVersion }()
	schemaMigrations = append(append([]func(*sql.Tx) error{}, saved...), func(tx *sql.Tx) error { return errors.New("broken") })
	SchemaVersion = len(schemaMigrations)
	path := atVersion(t, savedVersion)
	first := fmt.Sprintf("%s.schema-%d-20000101-000000.000000000", path, savedVersion)
	if err := os.WriteFile(first, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	OpenStore(path)
	copies, _ := filepath.Glob(fmt.Sprintf("%s.schema-%d-*", path, savedVersion))
	if data, err := os.ReadFile(first); len(copies) != 1 || err != nil || string(data) != "old" {
		t.Fatal("copies", copies, err)
	}
}
