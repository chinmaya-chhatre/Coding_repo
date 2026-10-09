import sqlite3

import pytest

from hookscope.store import EventStore


@pytest.fixture
def store(tmp_path):
    return EventStore(str(tmp_path / "retention.db"))


def _add(store: EventStore, received_at: str) -> int:
    event_id = store.add(source="generic", headers={}, body="{}", verification="valid", reason="")
    with sqlite3.connect(store.path) as conn:
        conn.execute("UPDATE events SET received_at = ? WHERE id = ?", (received_at, event_id))
    return event_id


def _ids(store: EventStore) -> list[int]:
    return [e["id"] for e in store.list(limit=100)]


def test_purge_by_age_removes_events_and_their_forwards(store):
    old = _add(store, "2026-09-01T12:00:00+00:00")
    new = _add(store, "2026-10-01T12:00:00+00:00")
    store.add_forward(old, "audit", "http://a.test/", 200, 3)
    store.add_forward(new, "audit", "http://a.test/", 200, 3)

    removed = store.purge(older_than="2026-09-15")

    assert removed == 1
    assert _ids(store) == [new]
    assert store.list_forwards(old) == []
    assert len(store.list_forwards(new)) == 1


def test_purge_keep_last_keeps_newest(store):
    ids = [_add(store, f"2026-10-0{day}T12:00:00+00:00") for day in range(1, 6)]
    assert store.purge(keep_last=2) == 3
    assert _ids(store) == [ids[4], ids[3]]


def test_purge_rules_combine_with_or(store):
    old = _add(store, "2026-01-01T00:00:00+00:00")
    recent = [_add(store, f"2026-10-0{day}T00:00:00+00:00") for day in range(1, 5)]
    # The age rule alone would drop only `old`; keep_last=2 alone would drop `old` and two
    # recent ones. Either rule is enough to remove an event.
    assert store.purge(older_than="2026-06-01", keep_last=10) == 1
    assert old not in _ids(store)
    assert store.purge(older_than="2026-06-01", keep_last=2) == 2
    assert _ids(store) == [recent[3], recent[2]]


def test_purge_without_rules_is_a_noop(store):
    _add(store, "2026-01-01T00:00:00+00:00")
    assert store.purge() == 0
    assert len(_ids(store)) == 1


def test_purge_rejects_negative_keep_last_and_bad_dates(store):
    with pytest.raises(ValueError):
        store.purge(keep_last=-1)
    with pytest.raises(ValueError):
        store.purge(older_than="last week")
