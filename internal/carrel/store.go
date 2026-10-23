package carrel

import (
	"context"
	"database/sql"
	"encoding/json"
	_ "modernc.org/sqlite"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var DefaultQuota = D{"vcpu": 8, "memory_mb": 16384, "disk_gb": 100, "machines": 8, "ips": 8, "public_ports": 10, "domains": 10, "networks": 4, "snapshots": 4, "snapshot_gb": 100, "images_gb": 20}

type sqlAccess interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}
type Store struct {
	DB *sql.DB
	q  sqlAccess
}

func OpenStore(path string) (*Store, error) {
	if path != ":memory:" {
		if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
			return nil, e
		}
	}
	db, e := sql.Open("sqlite", path)
	if e != nil {
		return nil, e
	}
	db.SetMaxOpenConns(1)
	s := &Store{db, db}
	_, e = db.Exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=10000;
CREATE TABLE IF NOT EXISTS tenants(n INTEGER PRIMARY KEY AUTOINCREMENT,subject TEXT UNIQUE NOT NULL,slug TEXT UNIQUE NOT NULL,quota TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'active');
CREATE TABLE IF NOT EXISTS objects(kind TEXT NOT NULL,id TEXT NOT NULL,tenant INTEGER NOT NULL,data TEXT NOT NULL,PRIMARY KEY(kind,id),FOREIGN KEY(tenant) REFERENCES tenants(n));
CREATE INDEX IF NOT EXISTS objects_tenant ON objects(tenant,kind);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,at INTEGER NOT NULL,actor TEXT NOT NULL,tenant INTEGER,tool TEXT NOT NULL,args TEXT NOT NULL,outcome TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS oauth(kind TEXT NOT NULL,id TEXT NOT NULL,data TEXT NOT NULL,expires INTEGER NOT NULL,PRIMARY KEY(kind,id));
CREATE TABLE IF NOT EXISTS site(kind TEXT NOT NULL,id TEXT NOT NULL,data TEXT NOT NULL,PRIMARY KEY(kind,id));`)
	if e != nil {
		db.Close()
		return nil, e
	}
	return s, nil
}
func (s *Store) Exec(q string, args ...any) {
	_, e := s.q.ExecContext(context.Background(), q, args...)
	must(e)
}
func (s *Store) Rows(q string, args ...any) []D {
	rows, e := s.q.QueryContext(context.Background(), q, args...)
	must(e)
	defer rows.Close()
	cols, e := rows.Columns()
	must(e)
	result := []D{}
	for rows.Next() {
		vals := make([]any, len(cols))
		ptr := make([]any, len(cols))
		for i := range vals {
			ptr[i] = &vals[i]
		}
		must(rows.Scan(ptr...))
		d := D{}
		for i, k := range cols {
			if b, ok := vals[i].([]byte); ok {
				vals[i] = string(b)
			}
			d[k] = vals[i]
		}
		result = append(result, d)
	}
	must(rows.Err())
	return result
}
func (s *Store) Transaction(f func(*Store)) {
	tx, e := s.DB.BeginTx(context.Background(), nil)
	must(e)
	defer tx.Rollback()
	f(&Store{s.DB, tx})
	must(tx.Commit())
}
func decode(s string) D { var d D; must(json.Unmarshal([]byte(s), &d)); return d }
func (s *Store) Tenants() []D {
	rows := s.Rows("SELECT * FROM tenants ORDER BY n")
	for _, r := range rows {
		r["quota"] = merge(DefaultQuota, decode(str(r["quota"])))
	}
	return rows
}
func (s *Store) Tenant(subject string) D {
	return find(s.Tenants(), func(t D) bool { return t["subject"] == subject })
}
func (s *Store) TenantN(n int) D {
	return find(s.Tenants(), func(t D) bool { return integer(t["n"]) == n })
}
func (s *Store) Register(subject, slug string) D {
	r := s.Rows("SELECT seq FROM sqlite_sequence WHERE name='tenants'")
	if len(r) > 0 && integer(r[0]["seq"]) >= 254 {
		fail("quota_exceeded", "Tenant serial space exhausted")
	}
	s.Exec("INSERT INTO tenants(subject,slug,quota) VALUES(?,?,?)", subject, slug, string(encoded(DefaultQuota)))
	return s.Tenant(subject)
}
func (s *Store) Objects(kind string, tenant ...int) []D {
	r := []D{}
	for _, data := range s.objectData(kind, tenant...) {
		r = append(r, decode(data))
	}
	return r
}
func (s *Store) objectData(kind string, tenant ...int) []string {
	q := "SELECT data FROM objects WHERE kind=?"
	a := []any{kind}
	if len(tenant) > 0 {
		q += " AND tenant=?"
		a = append(a, tenant[0])
	}
	q += " ORDER BY id"
	r := []string{}
	for _, v := range s.Rows(q, a...) {
		r = append(r, str(v["data"]))
	}
	return r
}

// operationRetention keeps finished operations for idempotent resubmission
// and operation_get; the audit table keeps the history after that.
const operationRetention = 30 * 86400

// terminalStates is the terminal list as an SQL value list.
const terminalStates = "'succeeded','failed','rolled_back','cleanup_failed'"

// ActiveOperations lists unfinished operations without decoding finished ones.
func (s *Store) ActiveOperations(tenant ...int) []D {
	q := "SELECT data FROM objects WHERE kind='operations' AND json_extract(data,'$.state') NOT IN (" + terminalStates + ")"
	a := []any{}
	if len(tenant) > 0 {
		q += " AND tenant=?"
		a = append(a, tenant[0])
	}
	r := []D{}
	for _, v := range s.Rows(q+" ORDER BY id", a...) {
		r = append(r, decode(str(v["data"])))
	}
	return r
}

// OperationByKey finds a tenant's operation by its idempotency key.
func (s *Store) OperationByKey(tenant int, key string) D {
	r := s.Rows("SELECT data FROM objects WHERE kind='operations' AND tenant=? AND json_extract(data,'$.idempotency_key')=? ORDER BY id LIMIT 1", tenant, key)
	if len(r) == 0 {
		return nil
	}
	return decode(str(r[0]["data"]))
}

// RecentOperations returns a tenant's newest operations first.
func (s *Store) RecentOperations(tenant, limit int) []D {
	r := []D{}
	for _, v := range s.Rows("SELECT data FROM objects WHERE kind='operations' AND tenant=? ORDER BY json_extract(data,'$.created_at') DESC LIMIT ?", tenant, limit) {
		r = append(r, decode(str(v["data"])))
	}
	return r
}

// PruneOperations deletes finished operations older than the retention. A
// cleanup_failed operation still holds resources that only its retry
// releases, so it stays.
func (s *Store) PruneOperations() {
	s.Exec("DELETE FROM objects WHERE kind='operations' AND json_extract(data,'$.state') IN ('succeeded','failed','rolled_back') AND json_extract(data,'$.updated_at') < ?", now()-operationRetention)
}

func (s *Store) Get(kind, id string) D {
	r := s.Rows("SELECT data FROM objects WHERE kind=? AND id=?", kind, id)
	if len(r) == 0 {
		return nil
	}
	return decode(str(r[0]["data"]))
}
func (s *Store) Put(kind string, id any, n int, value D) {
	s.Exec("INSERT INTO objects VALUES(?,?,?,?) ON CONFLICT(kind,id) DO UPDATE SET data=excluded.data", kind, str(id), n, string(encoded(value)))
}

// SiteGet and SitePut keep state that belongs to no tenant, such as a
// drained node.
func (s *Store) SiteGet(kind, id string) D {
	r := s.Rows("SELECT data FROM site WHERE kind=? AND id=?", kind, id)
	if len(r) == 0 {
		return nil
	}
	return decode(str(r[0]["data"]))
}

// SiteRows lists a kind's site state in id order.
func (s *Store) SiteRows(kind string) []D {
	out := []D{}
	for _, r := range s.Rows("SELECT data FROM site WHERE kind=? ORDER BY id", kind) {
		out = append(out, decode(str(r["data"])))
	}
	return out
}
func (s *Store) SiteRemove(kind, id string) {
	s.Exec("DELETE FROM site WHERE kind=? AND id=?", kind, id)
}
func (s *Store) SitePut(kind, id string, value D) {
	s.Exec("INSERT INTO site VALUES(?,?,?) ON CONFLICT(kind,id) DO UPDATE SET data=excluded.data", kind, id, string(encoded(value)))
}
func (s *Store) Remove(kind string, id any) {
	s.Exec("DELETE FROM objects WHERE kind=? AND id=?", kind, str(id))
}

var secretName = regexp.MustCompile(`(?i)secret|password|token|authorization|cookie|private.?key|runcmd|user.?data`)

func mask(v any, name string) any {
	if secretName.MatchString(name) {
		return "[redacted]"
	}
	switch x := v.(type) {
	case map[string]any:
		r := D{}
		for k, v := range x {
			r[k] = mask(v, k)
		}
		return r
	case []any:
		r := []any{}
		for _, v := range x {
			r = append(r, mask(v, name))
		}
		return r
	}
	return v
}
func (s *Store) Log(actor string, tenant any, tool string, args D, outcome string) {
	s.Exec("INSERT INTO audit(at,actor,tenant,tool,args,outcome) VALUES(?,?,?,?,?,?)", time.Now().Unix(), actor, tenant, tool, string(encoded(mask(args, ""))), outcome)
}
func (s *Store) OAuthGet(kind, id string) D {
	r := s.Rows("SELECT data FROM oauth WHERE kind=? AND id=? AND (expires=0 OR expires>?)", kind, id, time.Now().Unix())
	if len(r) == 0 {
		return nil
	}
	return decode(str(r[0]["data"]))
}
func (s *Store) OAuthPut(kind, id string, d D, ttl int) {
	exp := int64(0)
	if ttl > 0 {
		exp = time.Now().Unix() + int64(ttl)
	}
	s.Exec("INSERT OR REPLACE INTO oauth VALUES(?,?,?,?)", kind, id, string(encoded(d)), exp)
}
func (s *Store) OAuthPop(kind, id string) D {
	var d D
	s.Transaction(func(tx *Store) {
		d = tx.OAuthGet(kind, id)
		tx.Exec("DELETE FROM oauth WHERE kind=? AND id=?", kind, id)
	})
	return d
}
func (s *Store) PurgeOAuth() {
	s.Exec("DELETE FROM oauth WHERE expires!=0 AND expires<=?", time.Now().Unix())
}
func (s *Store) Desired() D {
	state := D{"tenants": s.Tenants()}
	ms := s.Objects("machines")
	deleting, addresses := map[int]bool{}, map[string]bool{}
	for _, m := range ms {
		if m["state"] == "deleting" {
			deleting[integer(m["vmid"])] = true
			addresses[str(m["ip"])] = true
		}
	}
	for _, k := range []string{"machines", "networks", "ports", "peers", "domains"} {
		state[k] = filter(s.Objects(k), func(o D) bool {
			return o["state"] != "deleting" && !deleting[integer(o["vmid"])] && !addresses[str(o["target"])] && !addresses[strings.TrimSuffix(str(o["source"]), "/32")]
		})
	}
	// Sent only when a tenant has one, so requests without any stay as they were.
	if vips := filter(s.Objects("vips"), func(o D) bool { return o["state"] != "deleting" }); len(vips) > 0 {
		state["vips"] = vips
	}
	// And public address bindings (issue #91).
	if bound := desiredPublicIPs(s); len(bound) > 0 {
		state["public_ips"] = bound
	}
	// The same for VPN clients; an expired one is gone before its record.
	if clients := filter(s.Objects("vpn_clients"), func(o D) bool { return o["state"] != "deleting" && num(o["expires_at"]) > now() }); len(clients) > 0 {
		state["vpn_clients"] = clients
	}
	return state
}
