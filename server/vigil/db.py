"""SQLite storage layer.

One writer connection (serialised by a lock) and one reader connection per
thread. WAL mode lets the API read while the pipeline writes. Events are
indexed on the fields analysts filter by most, and the raw message is
indexed with FTS5 for free-text search.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id            INTEGER PRIMARY KEY,
    ts            REAL NOT NULL,
    ingest_ts     REAL NOT NULL,
    host          TEXT,
    agent_id      TEXT,
    source        TEXT,            -- file path, journald, syslog:udp, ...
    product       TEXT,            -- linux, windows, nginx, ...
    service       TEXT,            -- sshd, sudo, security, ...
    category      TEXT,            -- authentication, process_creation, webserver, ...
    action        TEXT,            -- ssh_login_failed, sudo_command, http_request ...
    outcome       TEXT,            -- success / failure / unknown
    user_name     TEXT,
    src_ip        TEXT,
    src_country   TEXT,
    severity      INTEGER DEFAULT 0,
    message       TEXT,
    fields        TEXT NOT NULL    -- full normalised event as JSON
);
CREATE INDEX IF NOT EXISTS ix_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS ix_events_host_ts ON events(host, ts);
CREATE INDEX IF NOT EXISTS ix_events_src_ts ON events(src_ip, ts);
CREATE INDEX IF NOT EXISTS ix_events_user_ts ON events(user_name, ts);
CREATE INDEX IF NOT EXISTS ix_events_action_ts ON events(action, ts);

CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(
    message, content='events', content_rowid='id', tokenize='unicode61 tokenchars ''._-:/'''
);
CREATE TRIGGER IF NOT EXISTS events_ai AFTER INSERT ON events BEGIN
    INSERT INTO events_fts(rowid, message) VALUES (new.id, new.message);
END;
CREATE TRIGGER IF NOT EXISTS events_ad AFTER DELETE ON events BEGIN
    INSERT INTO events_fts(events_fts, rowid, message) VALUES ('delete', old.id, old.message);
END;

CREATE TABLE IF NOT EXISTS alerts (
    id            INTEGER PRIMARY KEY,
    rule_id       TEXT NOT NULL,
    rule_title    TEXT NOT NULL,
    rule_type     TEXT NOT NULL,     -- sigma / correlation / ueba / threatintel / system
    severity      TEXT NOT NULL,     -- informational, low, medium, high, critical
    risk          INTEGER NOT NULL,
    first_ts      REAL NOT NULL,
    last_ts       REAL NOT NULL,
    created_ts    REAL NOT NULL,
    count         INTEGER NOT NULL DEFAULT 1,
    host          TEXT,
    user_name     TEXT,
    src_ip        TEXT,
    dedup_key     TEXT,
    tactics       TEXT NOT NULL DEFAULT '[]',
    techniques    TEXT NOT NULL DEFAULT '[]',
    event_ids     TEXT NOT NULL DEFAULT '[]',
    details       TEXT NOT NULL DEFAULT '{}',
    status        TEXT NOT NULL DEFAULT 'new',   -- new, in_progress, closed
    resolution    TEXT,                          -- true_positive, false_positive, benign
    assignee      TEXT,
    incident_id   INTEGER
);
CREATE INDEX IF NOT EXISTS ix_alerts_created ON alerts(created_ts);
CREATE INDEX IF NOT EXISTS ix_alerts_dedup ON alerts(dedup_key, last_ts);
CREATE INDEX IF NOT EXISTS ix_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS ix_alerts_incident ON alerts(incident_id);

CREATE TABLE IF NOT EXISTS incidents (
    id            INTEGER PRIMARY KEY,
    title         TEXT NOT NULL,
    severity      TEXT NOT NULL,
    risk          INTEGER NOT NULL DEFAULT 0,
    status        TEXT NOT NULL DEFAULT 'new',
    resolution    TEXT,
    assignee      TEXT,
    first_ts      REAL NOT NULL,
    last_ts       REAL NOT NULL,
    created_ts    REAL NOT NULL,
    alert_count   INTEGER NOT NULL DEFAULT 0,
    entities      TEXT NOT NULL DEFAULT '{}',   -- {"ip": [...], "user": [...], "host": [...]}
    tactics       TEXT NOT NULL DEFAULT '[]',
    techniques    TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS ix_incidents_last ON incidents(last_ts);

CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY,
    target_type TEXT NOT NULL,
    target_id INTEGER NOT NULL,
    author TEXT NOT NULL,
    ts REAL NOT NULL,
    body TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_comments_target ON comments(target_type, target_id);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY,
    ts REAL NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT,
    details TEXT
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'analyst',
    created_ts REAL NOT NULL,
    disabled INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    created_ts REAL NOT NULL,
    expires_ts REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS agents (
    id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL,
    hostname TEXT NOT NULL,
    os TEXT,
    version TEXT,
    ip TEXT,
    enrolled_ts REAL NOT NULL,
    last_seen REAL,
    events_received INTEGER NOT NULL DEFAULT 0,
    inputs TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'active',
    silent_alerted INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ueba_models (
    entity TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    updated_ts REAL NOT NULL,
    state TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS rule_state (
    rule_id TEXT PRIMARY KEY,
    enabled INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS stats_minute (
    minute INTEGER PRIMARY KEY,
    events INTEGER NOT NULL DEFAULT 0
);
"""


class Database:
    def __init__(self, path: Path | str):
        self.path = str(path)
        self._write_lock = threading.RLock()
        self._local = threading.local()
        self._writer = self._connect()
        self._writer.executescript(SCHEMA)
        self._writer.commit()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, check_same_thread=False, timeout=30, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=30000")
        return conn

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        """Serialised write transaction."""
        with self._write_lock:
            self._writer.execute("BEGIN IMMEDIATE")
            try:
                yield self._writer
            except BaseException:
                self._writer.execute("ROLLBACK")
                raise
            else:
                self._writer.execute("COMMIT")

    @property
    def reader(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = self._connect()
            conn.execute("PRAGMA query_only=ON")
            self._local.conn = conn
        return conn

    def query(self, sql: str, params: Any = ()) -> list[dict]:
        return [dict(r) for r in self.reader.execute(sql, params).fetchall()]

    def query_one(self, sql: str, params: Any = ()) -> dict | None:
        row = self.reader.execute(sql, params).fetchone()
        return dict(row) if row else None

    def execute(self, sql: str, params: Any = ()) -> sqlite3.Cursor:
        with self.tx() as c:
            return c.execute(sql, params)

    # ---- settings key/value -------------------------------------------------
    def get_setting(self, key: str, default: Any = None) -> Any:
        row = self.query_one("SELECT value FROM settings WHERE key=?", (key,))
        return json.loads(row["value"]) if row else default

    def set_setting(self, key: str, value: Any) -> None:
        self.execute(
            "INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, json.dumps(value)),
        )

    def audit(self, actor: str, action: str, target: str = "", details: Any = None) -> None:
        self.execute(
            "INSERT INTO audit_log(ts, actor, action, target, details) VALUES(?,?,?,?,?)",
            (time.time(), actor, action, target, json.dumps(details) if details is not None else None),
        )

    def close(self) -> None:
        self._writer.close()


def loads(row: dict, *keys: str) -> dict:
    """Decode JSON columns of a row in place."""
    for k in keys:
        if k in row and isinstance(row[k], str):
            row[k] = json.loads(row[k])
    return row
