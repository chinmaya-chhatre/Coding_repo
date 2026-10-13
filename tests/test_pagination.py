import pytest
from fastapi.testclient import TestClient

from hookscope.main import create_app
from hookscope.store import EventStore


@pytest.fixture
def store(tmp_path):
    return EventStore(str(tmp_path / "pages.db"))


@pytest.fixture
def client(store):
    return TestClient(create_app(store=store, secrets={}))


def _fill(store: EventStore, count: int, source: str = "generic") -> list[int]:
    return [
        store.add(source=source, headers={}, body=str(i), verification="valid", reason="")
        for i in range(count)
    ]


def _walk(client, **params) -> tuple[list[int], int]:
    """Follow X-Next-Cursor to the end; return all ids seen and the number of pages."""
    ids: list[int] = []
    pages = 0
    before = None
    while True:
        query = {**params, **({"before_id": before} if before else {})}
        response = client.get("/api/events", params=query)
        assert response.status_code == 200
        ids += [e["id"] for e in response.json()]
        pages += 1
        before = response.headers.get("x-next-cursor")
        if before is None:
            return ids, pages
        assert pages < 100


def test_store_before_id_returns_only_older_events(store):
    ids = _fill(store, 5)
    assert [e["id"] for e in store.list(before_id=ids[3])] == [ids[2], ids[1], ids[0]]
    assert store.list(before_id=ids[0]) == []


def test_pages_cover_every_event_once_in_order(client, store):
    ids = _fill(store, 25)
    seen, pages = _walk(client, limit=10)
    assert seen == sorted(ids, reverse=True)
    assert pages == 3


def test_no_cursor_when_everything_fits(client, store):
    _fill(store, 10)
    exact = client.get("/api/events", params={"limit": 10})
    assert len(exact.json()) == 10
    assert "x-next-cursor" not in exact.headers  # exactly one full page is not a reason to page again
    assert "x-next-cursor" not in client.get("/api/events").headers


def test_cursor_points_at_the_last_event_of_the_page(client, store):
    ids = _fill(store, 6)
    response = client.get("/api/events", params={"limit": 4})
    assert [e["id"] for e in response.json()] == ids[:1:-1]
    assert response.headers["x-next-cursor"] == str(ids[2])


def test_paging_is_stable_while_new_events_arrive(client, store):
    old = _fill(store, 6)
    first = client.get("/api/events", params={"limit": 3})
    cursor = first.headers["x-next-cursor"]
    _fill(store, 4)  # arrives between page requests
    second = client.get("/api/events", params={"limit": 3, "before_id": cursor})
    assert [e["id"] for e in first.json() + second.json()] == sorted(old, reverse=True)


def test_cursor_respects_filters(client, store):
    for i in range(6):
        _fill(store, 1, source="github" if i % 2 else "stripe")
    seen, pages = _walk(client, source="github", limit=2)
    assert len(seen) == 3
    assert pages == 2
    assert all(e["source"] == "github" for e in client.get("/api/events", params={"source": "github"}).json())


def test_limit_is_still_capped_and_cursor_follows_the_cap(client, store):
    _fill(store, 501)
    response = client.get("/api/events", params={"limit": 9999})
    assert len(response.json()) == 500
    assert response.headers["x-next-cursor"] == str(response.json()[-1]["id"])


def test_cursor_header_is_documented(client):
    spec = client.get("/openapi.json").json()
    headers = spec["paths"]["/api/events"]["get"]["responses"]["200"]["headers"]
    assert "X-Next-Cursor" in headers
