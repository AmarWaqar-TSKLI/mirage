"""SQLite storage for events, alerts, attackers, and active responses."""

import json
import sqlite3
import threading
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id            TEXT PRIMARY KEY,
    ts            TEXT NOT NULL,
    source        TEXT NOT NULL,
    event_type    TEXT NOT NULL,
    src_ip        TEXT NOT NULL,
    src_port      INTEGER,
    session_id    TEXT,
    asset         TEXT,
    honeytoken_id TEXT,
    stage         INTEGER NOT NULL DEFAULT 0,
    techniques    TEXT NOT NULL DEFAULT '[]',
    engage        TEXT NOT NULL DEFAULT '[]',
    details       TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS events_ip ON events (src_ip, ts);

CREATE TABLE IF NOT EXISTS alerts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            TEXT NOT NULL,
    event_id      TEXT NOT NULL REFERENCES events (id),
    src_ip        TEXT NOT NULL,
    severity      TEXT NOT NULL,
    title         TEXT NOT NULL,
    honeytoken_id TEXT,
    stage         INTEGER NOT NULL DEFAULT 0,
    techniques    TEXT NOT NULL DEFAULT '[]',
    engage        TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS attackers (
    ip            TEXT PRIMARY KEY,
    first_seen    TEXT NOT NULL,
    last_seen     TEXT NOT NULL,
    event_count   INTEGER NOT NULL DEFAULT 0,
    max_stage     INTEGER NOT NULL DEFAULT 0,
    risk_score    INTEGER NOT NULL DEFAULT 0,
    playbook      TEXT NOT NULL DEFAULT 'watch',
    contained_at  TEXT,
    techniques    TEXT NOT NULL DEFAULT '[]',
    tokens        TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS responses (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            TEXT NOT NULL,
    src_ip        TEXT NOT NULL,
    playbook      TEXT NOT NULL,
    action        TEXT NOT NULL,
    status        TEXT NOT NULL,
    details       TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS responses_ip ON responses (src_ip, ts);
"""

JSON_COLUMNS = {"techniques", "engage", "details", "tokens"}


def _row(row: sqlite3.Row) -> dict:
    return {k: json.loads(row[k]) if k in JSON_COLUMNS else row[k] for k in row.keys()}


class Store:
    def __init__(self, path: str | Path):
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript(SCHEMA)
        self.lock = threading.Lock()

    def insert_event(self, e: dict) -> None:
        self.db.execute(
            "INSERT INTO events VALUES (:id, :ts, :source, :event_type, :src_ip, :src_port, :session_id,"
            " :asset, :honeytoken_id, :stage, :techniques, :engage, :details)",
            {**e, "techniques": json.dumps(e["techniques"]), "engage": json.dumps(e["engage"]),
             "details": json.dumps(e["details"])},
        )

    def insert_alert(self, a: dict) -> dict:
        cur = self.db.execute(
            "INSERT INTO alerts (ts, event_id, src_ip, severity, title, honeytoken_id, stage, techniques, engage)"
            " VALUES (:ts, :event_id, :src_ip, :severity, :title, :honeytoken_id, :stage, :techniques, :engage)",
            {**a, "techniques": json.dumps(a["techniques"]), "engage": json.dumps(a["engage"])},
        )
        return {**a, "id": cur.lastrowid}

    def insert_response(self, r: dict) -> dict:
        cur = self.db.execute(
            "INSERT INTO responses (ts, src_ip, playbook, action, status, details)"
            " VALUES (:ts, :src_ip, :playbook, :action, :status, :details)",
            {**r, "details": json.dumps(r.get("details", {}))},
        )
        return {**r, "id": cur.lastrowid}

    def get_attacker(self, ip: str) -> dict | None:
        row = self.db.execute("SELECT * FROM attackers WHERE ip = ?", (ip,)).fetchone()
        return _row(row) if row else None

    def upsert_attacker(self, a: dict) -> None:
        self.db.execute(
            "INSERT INTO attackers VALUES (:ip, :first_seen, :last_seen, :event_count, :max_stage, :risk_score, :playbook, :contained_at, :techniques, :tokens)"
            " ON CONFLICT (ip) DO UPDATE SET last_seen = excluded.last_seen, event_count = excluded.event_count,"
            " max_stage = excluded.max_stage, risk_score = excluded.risk_score, playbook = excluded.playbook,"
            " contained_at = coalesce(excluded.contained_at, attackers.contained_at), techniques = excluded.techniques, tokens = excluded.tokens",
            {
                "risk_score": 0,
                "playbook": "watch",
                "contained_at": None,
                **a,
                "techniques": json.dumps(a["techniques"]),
                "tokens": json.dumps(a["tokens"]),
            },
        )

    def clear_containment(self, ip: str) -> None:
        # upsert_attacker coalesces contained_at (so ingest never wipes it), so a
        # deliberate operator release needs to force it back to NULL here.
        self.db.execute("UPDATE attackers SET contained_at = NULL, playbook = 'watch' WHERE ip = ?", (ip,))

    def commit(self) -> None:
        self.db.commit()

    def recent(self, table: str, limit: int, ip: str | None = None) -> list[dict]:
        assert table in {"events", "alerts", "responses"}
        where, args = ("WHERE src_ip = ?", [ip]) if ip else ("", [])
        rows = self.db.execute(f"SELECT * FROM {table} {where} ORDER BY ts DESC LIMIT ?", [*args, limit])
        return [_row(r) for r in rows]

    def attackers(self) -> list[dict]:
        rows = self.db.execute("SELECT * FROM attackers ORDER BY last_seen DESC")
        return [_row(r) for r in rows]
