"""SQLite-backed storage for captured webhook events."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, date, datetime, timedelta

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
    error         TEXT NOT NULL DEFAULT '',
    attempt       INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS forwards_event_id ON forwards(event_id);
"""


class EventStore:
    def __init__(self, path: str) -> None:
        self.path = path
        with self._connect() as conn:
            conn.executescript(SCHEMA)
            _migrate(conn)

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

    def list(
        self,
        limit: int = 50,
        source: str | None = None,
        q: str | None = None,
        since: str | None = None,
        until: str | None = None,
        verification: str | None = None,
    ) -> list[dict]:
        """Newest events first, optionally filtered.

        ``q`` is a case-insensitive substring match on the body and headers. ``since`` and
        ``until`` are ISO dates or datetimes (UTC unless an offset is given); a date-only
        ``until`` includes that whole day. Raises ``ValueError`` for a malformed bound.
        """
        conditions: list[str] = []
        params: list = []
        if source:
            conditions.append("source = ?")
            params.append(source)
        if verification:
            conditions.append("verification = ?")
            params.append(verification)
        if q:
            pattern = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            conditions.append("(body LIKE ? ESCAPE '\\' OR headers LIKE ? ESCAPE '\\')")
            params += [pattern, pattern]
        if since:
            conditions.append("received_at >= ?")
            params.append(time_bound(since))
        if until:
            conditions.append("received_at < ?")
            params.append(time_bound(until, end=True))
        query = "SELECT * FROM events"
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
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
        attempt: int = 1,
    ) -> int:
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO forwards "
                "(event_id, rule, target_url, forwarded_at, status_code, elapsed_ms, error, attempt) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (event_id, rule, target_url, _now(), status_code, elapsed_ms, error, attempt),
            )
            return int(cur.lastrowid)

    def list_forwards(self, event_id: int) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM forwards WHERE event_id = ? ORDER BY id", (event_id,)
            ).fetchall()
        return [dict(r) for r in rows]

    def latest_forwards(self) -> list[dict]:
        """The most recent attempt for each (event, rule) pair, newest first."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM forwards WHERE id IN "
                "(SELECT MAX(id) FROM forwards GROUP BY event_id, rule) ORDER BY id DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    def forwards_by_event(self, event_ids: list[int]) -> dict[int, list[dict]]:
        """Forward attempts for several events in one query, keyed by event id."""
        grouped: dict[int, list[dict]] = {event_id: [] for event_id in event_ids}
        if not event_ids:
            return grouped
        placeholders = ", ".join("?" * len(event_ids))
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM forwards WHERE event_id IN ({placeholders}) ORDER BY id", event_ids
            ).fetchall()
        for row in rows:
            grouped[row["event_id"]].append(dict(row))
        return grouped


def _migrate(conn: sqlite3.Connection) -> None:
    """Bring databases created by older versions up to the current schema."""
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(forwards)")}
    if "attempt" not in columns:
        conn.execute("ALTER TABLE forwards ADD COLUMN attempt INTEGER NOT NULL DEFAULT 1")


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def time_bound(value: str, end: bool = False) -> str:
    """Normalise an ISO date/datetime to the UTC format used for ``received_at``.

    With ``end=True`` the result is an exclusive upper bound: a date-only value moves to
    the start of the next day so the whole day is included.
    """
    value = value.strip()
    if len(value) == 10:
        day = date.fromisoformat(value)
        if end:
            day += timedelta(days=1)
        moment = datetime(day.year, day.month, day.day, tzinfo=UTC)
    else:
        moment = datetime.fromisoformat(value)
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=UTC)
        if end:
            # received_at has second precision, so "until 10:00:00" should include 10:00:00.
            moment += timedelta(seconds=1)
    return moment.astimezone(UTC).isoformat(timespec="seconds")


def _to_dict(row: sqlite3.Row) -> dict:
    event = dict(row)
    event["headers"] = json.loads(event["headers"])
    return event
