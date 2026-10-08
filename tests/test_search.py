import sqlite3

import pytest
from fastapi.testclient import TestClient

from hookscope.main import create_app
from hookscope.store import EventStore, time_bound


@pytest.fixture
def store(tmp_path):
    return EventStore(str(tmp_path / "search.db"))


def _add(store: EventStore, received_at: str, body: str = "{}", source: str = "generic", **kwargs) -> int:
    event_id = store.add(
        source=source,
        headers=kwargs.get("headers", {}),
        body=body,
        verification=kwargs.get("verification", "valid"),
        reason="",
    )
    # Pin the timestamp so date filters are deterministic.
    with sqlite3.connect(store.path) as conn:
        conn.execute("UPDATE events SET received_at = ? WHERE id = ?", (received_at, event_id))
    return event_id


def _ids(events: list[dict]) -> list[int]:
    return [e["id"] for e in events]


def test_search_matches_body_and_headers_case_insensitively(store):
    a = _add(store, "2026-10-01T10:00:00+00:00", body='{"customer": "ACME Corp"}')
    b = _add(store, "2026-10-01T11:00:00+00:00", headers={"x-github-event": "push"})
    _add(store, "2026-10-01T12:00:00+00:00", body='{"customer": "Globex"}')
    assert _ids(store.list(q="acme")) == [a]
    assert _ids(store.list(q="PUSH")) == [b]


def test_search_treats_wildcards_literally(store):
    pct = _add(store, "2026-10-01T10:00:00+00:00", body='{"discount": "50%"}')
    _add(store, "2026-10-01T11:00:00+00:00", body='{"discount": "50 dollars"}')
    under = _add(store, "2026-10-01T12:00:00+00:00", body='{"key": "a_b"}')
    _add(store, "2026-10-01T13:00:00+00:00", body='{"key": "axb"}')
    assert _ids(store.list(q="50%")) == [pct]
    assert _ids(store.list(q="a_b")) == [under]


def test_date_range_is_inclusive_of_whole_until_day(store):
    _add(store, "2026-09-30T23:59:59+00:00")
    first = _add(store, "2026-10-01T00:00:00+00:00")
    last = _add(store, "2026-10-02T23:59:59+00:00")
    _add(store, "2026-10-03T00:00:00+00:00")
    assert _ids(store.list(since="2026-10-01", until="2026-10-02")) == [last, first]


def test_datetime_bounds_and_offsets(store):
    _add(store, "2026-10-01T09:59:59+00:00")
    at_ten = _add(store, "2026-10-01T10:00:00+00:00")
    _add(store, "2026-10-01T10:00:01+00:00")
    assert _ids(store.list(since="2026-10-01T10:00:00", until="2026-10-01T10:00:00")) == [at_ten]
    # 06:00 in New York (UTC-4 in October) is 10:00 UTC.
    assert _ids(store.list(since="2026-10-01T06:00:00-04:00", until="2026-10-01T06:00:00-04:00")) == [at_ten]


def test_filters_combine_with_source_and_verification(store):
    _add(store, "2026-10-01T10:00:00+00:00", body='{"id": 1}', source="stripe", verification="invalid")
    keep = _add(store, "2026-10-01T11:00:00+00:00", body='{"id": 1}', source="stripe")
    _add(store, "2026-10-01T12:00:00+00:00", body='{"id": 1}', source="github")
    assert _ids(store.list(source="stripe", verification="valid", q='"id": 1')) == [keep]


@pytest.mark.parametrize(
    ("value", "end", "expected"),
    [
        ("2026-10-01", False, "2026-10-01T00:00:00+00:00"),
        ("2026-10-01", True, "2026-10-02T00:00:00+00:00"),
        ("2026-10-01T10:30:00Z", False, "2026-10-01T10:30:00+00:00"),
        ("2026-10-01T10:30:00+02:00", True, "2026-10-01T08:30:01+00:00"),
    ],
)
def test_time_bound(value, end, expected):
    assert time_bound(value, end=end) == expected


def test_api_filters_and_rejects_bad_dates(store):
    client = TestClient(create_app(store=store, secrets={}))
    hit = _add(store, "2026-10-05T12:00:00+00:00", body='{"order": "A-1001"}')
    _add(store, "2026-10-06T12:00:00+00:00", body='{"order": "A-1002"}')

    resp = client.get("/api/events", params={"q": "A-100", "until": "2026-10-05"})
    assert resp.status_code == 200
    assert _ids(resp.json()) == [hit]

    bad = client.get("/api/events", params={"since": "last tuesday"})
    assert bad.status_code == 422


def test_dashboard_filters_events_and_keeps_form_values(store):
    client = TestClient(create_app(store=store, secrets={}))
    _add(store, "2026-10-05T12:00:00+00:00", body='{"order": "A-1001"}', source="stripe")
    _add(store, "2026-10-06T12:00:00+00:00", body='{"order": "B-2002"}', source="stripe")

    html = client.get("/", params={"q": "A-1001", "until": "2026-10-05", "source": "stripe"}).text

    assert "A-1001" in html and "B-2002" not in html
    assert 'value="A-1001"' in html and 'value="2026-10-05"' in html
    # Source links keep the active filters so switching tabs does not drop them.
    assert "q=A-1001" in html and "source=github" in html


def test_dashboard_empty_fields_mean_no_filter(store):
    client = TestClient(create_app(store=store, secrets={}))
    _add(store, "2026-10-05T12:00:00+00:00", body='{"order": "A-1001"}')
    html = client.get("/", params={"q": "", "since": "", "until": "", "verification": ""}).text
    assert "A-1001" in html
    assert "clear</a>" not in html


def test_dashboard_reports_bad_dates_and_no_matches(store):
    client = TestClient(create_app(store=store, secrets={}))
    _add(store, "2026-10-05T12:00:00+00:00")
    assert "Dates must look like" in client.get("/", params={"since": "05/10/2026"}).text
    assert "No events match these filters" in client.get("/", params={"q": "nothing-here"}).text
