"""Durable desired state. Single writer process, WAL, transactional reservations."""

import json
import re
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

DEFAULT_QUOTA = {
    "vcpu": 8,
    "memory_mb": 16384,
    "disk_gb": 100,
    "machines": 4,
    "ips": 4,
    "public_ports": 10,
    "domains": 10,
    "networks": 4,
    "snapshots": 4,
    "snapshot_gb": 100,
    "images_gb": 20,
}


def mask(value, name=""):
    if re.search(
        r"secret|password|token|authorization|cookie|private.?key|runcmd|user.?data", name, re.IGNORECASE
    ):
        return "[redacted]"
    if isinstance(value, dict):
        return {k: mask(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [mask(v, name) for v in value]
    return value


class Store:
    def __init__(self, path):
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
PRAGMA busy_timeout=10000;
CREATE TABLE IF NOT EXISTS tenants (
 n INTEGER PRIMARY KEY AUTOINCREMENT, subject TEXT UNIQUE NOT NULL,
 slug TEXT UNIQUE NOT NULL, quota TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active'
);
CREATE TABLE IF NOT EXISTS objects (
 kind TEXT NOT NULL, id TEXT NOT NULL, tenant INTEGER NOT NULL, data TEXT NOT NULL,
 PRIMARY KEY(kind,id), FOREIGN KEY(tenant) REFERENCES tenants(n)
);
CREATE INDEX IF NOT EXISTS objects_tenant ON objects(tenant,kind);
CREATE TABLE IF NOT EXISTS audit (
 id INTEGER PRIMARY KEY, at INTEGER NOT NULL, actor TEXT NOT NULL, tenant INTEGER,
 tool TEXT NOT NULL, args TEXT NOT NULL, outcome TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS oauth (
 kind TEXT NOT NULL, id TEXT NOT NULL, data TEXT NOT NULL, expires INTEGER NOT NULL,
 PRIMARY KEY(kind,id)
);
""")

    def tenants(self):
        return [self._tenant(r) for r in self.db.execute("SELECT * FROM tenants ORDER BY n")]

    @staticmethod
    def _tenant(row):
        if not row:
            return None
        return {**dict(row), "quota": {**DEFAULT_QUOTA, **json.loads(row["quota"])}}

    @contextmanager
    def transaction(self):
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield
            self.db.execute("COMMIT")
        except BaseException:
            self.db.execute("ROLLBACK")
            raise

    def tenant(self, subject):
        return self._tenant(self.db.execute("SELECT * FROM tenants WHERE subject=?", (subject,)).fetchone())

    def register(self, subject, slug):
        row = self.db.execute("SELECT seq FROM sqlite_sequence WHERE name='tenants'").fetchone()
        if row and row[0] >= 254:
            raise ValueError("tenant serial space exhausted")
        self.db.execute(
            "INSERT INTO tenants(subject,slug,quota) VALUES(?,?,?)",
            (subject, slug, json.dumps(DEFAULT_QUOTA)),
        )
        t = self.tenant(subject)
        return t

    def objects(self, kind, tenant=None):
        if tenant is None:
            rows = self.db.execute("SELECT data FROM objects WHERE kind=? ORDER BY id", (kind,))
        else:
            rows = self.db.execute(
                "SELECT data FROM objects WHERE kind=? AND tenant=? ORDER BY id", (kind, tenant)
            )
        return [json.loads(r[0]) for r in rows]

    def put(self, kind, id, tenant, value):
        from .operations import operation_id

        if kind not in ("operations", "guest_reports", "requests", "certificates") and operation_id():
            old = self.db.execute(
                "SELECT data FROM objects WHERE kind=? AND id=?", (kind, str(id))
            ).fetchone()
            if not old:
                value = {**value, "operation_id": operation_id()}
            elif json.loads(old[0]).get("operation_id"):
                value = {"operation_id": json.loads(old[0])["operation_id"], **value}
        self.db.execute(
            "INSERT INTO objects VALUES(?,?,?,?) ON CONFLICT(kind,id) DO UPDATE SET data=excluded.data",
            (kind, str(id), tenant, json.dumps(value)),
        )

    def remove(self, kind, id):
        self.db.execute("DELETE FROM objects WHERE kind=? AND id=?", (kind, str(id)))

    def log(self, actor, tenant, tool, args, outcome):
        self.db.execute(
            "INSERT INTO audit(at,actor,tenant,tool,args,outcome) VALUES(?,?,?,?,?,?)",
            (int(time.time()), actor, tenant, tool, json.dumps(mask(args)), outcome),
        )

    def oauth_get(self, kind, id):
        r = self.db.execute(
            "SELECT data FROM oauth WHERE kind=? AND id=? AND expires>?", (kind, id, int(time.time()))
        ).fetchone()
        return json.loads(r[0]) if r else None

    def oauth_put(self, kind, id, data, ttl):
        self.db.execute(
            "INSERT OR REPLACE INTO oauth VALUES(?,?,?,?)",
            (kind, id, json.dumps(data), int(time.time()) + ttl),
        )

    def oauth_pop(self, kind, id):
        r = self.oauth_get(kind, id)
        self.db.execute("DELETE FROM oauth WHERE kind=? AND id=?", (kind, id))
        return r

    def purge_oauth(self):
        self.db.execute("DELETE FROM oauth WHERE expires<?", (int(time.time()),))

    def desired(self):
        state = {
            "tenants": self.tenants(),
            **{k: self.objects(k) for k in ["machines", "networks", "ports", "peers", "domains"]},
        }
        deleting = {m["vmid"] for m in state["machines"] if m.get("state") == "deleting"}
        addresses = {m["ip"] for m in state["machines"] if m["vmid"] in deleting}
        for kind in ("machines", "networks", "ports", "peers", "domains"):
            state[kind] = [
                o
                for o in state[kind]
                if o.get("state") != "deleting"
                and o.get("vmid") not in deleting
                and o.get("target") not in addresses
                and o.get("source", "").removesuffix("/32") not in addresses
            ]
        return state
