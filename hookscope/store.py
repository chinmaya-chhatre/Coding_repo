"""SQLite-backed storage for captured webhook events."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    source        TEXT NOT NULL,
    received_at   TEXT NOT NULL,
    headers       TEXT NOT NULL,
    body          TEXT NOT NULL,
    verification  TEXT NOT NULL,
    reason        TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS forwards (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id      INTEGER NOT NULL REFERENCES events(id),
    rule          TEXT NOT NULL,
    target_url    TEXT NOT NULL,
    forwarded_at  TEXT NOT NULL,
    status_code   INTEGER,
    elapsed_ms    INTEGER NOT NULL,
    error         TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS forwards_event_id ON forwards(event_id);
"""


class EventStore:
    def __init__(self, path: str) -> None:
        self.path = path
        with self._connect() as conn:
            conn.executescript(SCHEMA)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def add(self, source: str, headers: dict[str, str], body: str, verification: str, reason: str) -> int:
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO events (source, received_at, headers, body, verification, reason) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    source,
                    _now(),
                    json.dumps(headers),
                    body,
                    verification,
                    reason,
                ),
            )
            return int(cur.lastrowid)

    def get(self, event_id: int) -> dict | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
        return _to_dict(row) if row else None

    def list(self, limit: int = 50, source: str | None = None) -> list[dict]:
        query = "SELECT * FROM events"
        params: list = []
        if source:
            query += " WHERE source = ?"
            params.append(source)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [_to_dict(r) for r in rows]

    def add_forward(
        self,
        event_id: int,
        rule: str,
        target_url: str,
        status_code: int | None,
        elapsed_ms: int,
        error: str = "",
    ) -> int:
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO forwards "
                "(event_id, rule, target_url, forwarded_at, status_code, elapsed_ms, error) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (event_id, rule, target_url, _now(), status_code, elapsed_ms, error),
            )
            return int(cur.lastrowid)

    def list_forwards(self, event_id: int) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM forwards WHERE event_id = ? ORDER BY id", (event_id,)
            ).fetchall()
        return [dict(r) for r in rows]


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _to_dict(row: sqlite3.Row) -> dict:
    event = dict(row)
    event["headers"] = json.loads(event["headers"])
    return event
