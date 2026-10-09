import sqlite3
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from hookscope.main import create_app
from hookscope.retention import Purger, RetentionPolicy
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



class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def test_policy_from_env():
    policy = RetentionPolicy.from_env({"HOOKSCOPE_RETENTION_DAYS": "7", "HOOKSCOPE_MAX_EVENTS": "500"})
    assert policy == RetentionPolicy(max_age_days=7.0, max_events=500)
    assert RetentionPolicy.from_env({}).enabled is False
    assert RetentionPolicy.from_env({"HOOKSCOPE_PURGE_INTERVAL_SECONDS": "0"}).interval_seconds == 0


@pytest.mark.parametrize(
    "env",
    [
        {"HOOKSCOPE_RETENTION_DAYS": "a week"},
        {"HOOKSCOPE_RETENTION_DAYS": "0"},
        {"HOOKSCOPE_MAX_EVENTS": "0"},
        {"HOOKSCOPE_MAX_EVENTS": "1.5"},
        {"HOOKSCOPE_PURGE_INTERVAL_SECONDS": "-1"},
    ],
)
def test_policy_rejects_bad_settings(env):
    with pytest.raises(ValueError, match="HOOKSCOPE_RETENTION_DAYS"):
        RetentionPolicy.from_env(env)


def test_cutoff_is_max_age_before_now():
    now = datetime(2026, 10, 9, 12, 0, tzinfo=UTC)
    assert RetentionPolicy(max_age_days=1.5).cutoff(now) == "2026-10-08T00:00:00+00:00"
    assert RetentionPolicy(max_events=5).cutoff(now) is None


def test_purger_is_throttled(store):
    clock = FakeClock()
    purger = Purger(store, RetentionPolicy(max_events=1, interval_seconds=60), clock)
    _add(store, "2026-10-01T00:00:00+00:00")
    _add(store, "2026-10-02T00:00:00+00:00")
    assert purger.maybe_run() == 1

    _add(store, "2026-10-03T00:00:00+00:00")
    clock.now += 30
    assert purger.maybe_run() == 0  # too soon
    clock.now += 31
    assert purger.maybe_run() == 1
    assert len(_ids(store)) == 1


def test_disabled_policy_never_deletes(store):
    _add(store, "2000-01-01T00:00:00+00:00")
    assert Purger(store, RetentionPolicy(), FakeClock()).maybe_run() == 0
    assert len(_ids(store)) == 1


def test_receiving_a_webhook_applies_retention(store):
    expired = _add(store, "2000-01-01T00:00:00+00:00")
    client = TestClient(create_app(store=store, secrets={}, retention=RetentionPolicy(max_age_days=30)))

    resp = client.post("/hooks/generic", content=b'{"fresh": true}')

    assert resp.status_code == 202
    ids = _ids(store)
    assert expired not in ids
    assert ids == [resp.json()["id"]]


def test_max_events_keeps_the_event_just_received(store):
    for day in range(1, 4):
        _add(store, f"2026-10-0{day}T00:00:00+00:00")
    client = TestClient(create_app(store=store, secrets={}, retention=RetentionPolicy(max_events=1)))
    new_id = client.post("/hooks/generic", content=b"{}").json()["id"]
    assert _ids(store) == [new_id]


def test_purge_endpoint_with_explicit_rules(store):
    _add(store, "2020-01-01T00:00:00+00:00")
    keep = _add(store, "2026-10-01T00:00:00+00:00")
    client = TestClient(create_app(store=store, secrets={}, retention=RetentionPolicy()))

    resp = client.post("/api/purge", json={"older_than": "2025-01-01"})

    assert resp.status_code == 200
    assert resp.json() == {"removed": 1, "remaining": 1}
    assert _ids(store) == [keep]


def test_purge_endpoint_applies_configured_policy_immediately(store):
    for day in range(1, 5):
        _add(store, f"2026-10-0{day}T00:00:00+00:00")
    policy = RetentionPolicy(max_events=1, interval_seconds=3600)
    client = TestClient(create_app(store=store, secrets={}, retention=policy))
    # Ignores the purge interval: a manual purge always runs.
    assert client.post("/api/purge").json() == {"removed": 3, "remaining": 1}


def test_purge_endpoint_errors(store):
    client = TestClient(create_app(store=store, secrets={}, retention=RetentionPolicy()))
    assert client.post("/api/purge").status_code == 400
    assert client.post("/api/purge", json={}).status_code == 400
    assert client.post("/api/purge", json={"older_than": "someday"}).status_code == 422
    assert client.post("/api/purge", json={"keep_last": -1}).status_code == 422
