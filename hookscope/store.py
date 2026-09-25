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
                    datetime.now(UTC).isoformat(timespec="seconds"),
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


def _to_dict(row: sqlite3.Row) -> dict:
    event = dict(row)
    event["headers"] = json.loads(event["headers"])
    return event
