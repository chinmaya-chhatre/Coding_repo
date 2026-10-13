import re

import pytest
from fastapi.testclient import TestClient

from hookscope import main
from hookscope.main import create_app
from hookscope.store import EventStore


@pytest.fixture(autouse=True)
def small_pages(monkeypatch):
    monkeypatch.setattr(main, "DASHBOARD_PAGE_SIZE", 5)


@pytest.fixture
def store(tmp_path):
    return EventStore(str(tmp_path / "dash.db"))


@pytest.fixture
def client(store):
    return TestClient(create_app(store=store, secrets={}))


def _fill(store: EventStore, count: int, source: str = "generic") -> list[int]:
    return [
        store.add(source=source, headers={}, body="{}", verification="valid", reason="")
        for _ in range(count)
    ]


def _shown(html: str) -> list[int]:
    return [int(n) for n in re.findall(r"<strong>#(\d+)</strong>", html)]


def _older_link(html: str) -> str | None:
    match = re.search(r'<a rel="next" href="([^"]+)"', html)
    return match.group(1).replace("&amp;", "&") if match else None


def test_one_page_has_no_pager(client, store):
    _fill(store, 5)
    html = client.get("/").text
    assert len(_shown(html)) == 5
    assert "Older events" not in html
    assert "Newest events" not in html


def test_older_link_walks_back_through_every_event(client, store):
    ids = _fill(store, 12)
    seen: list[int] = []
    url: str | None = "/"
    pages = 0
    while url:
        html = client.get(url).text
        seen += _shown(html)
        url = _older_link(html)
        pages += 1
    assert seen == sorted(ids, reverse=True)
    assert pages == 3


def test_later_pages_link_back_to_the_newest(client, store):
    _fill(store, 8)
    second = client.get(_older_link(client.get("/").text))
    assert "Newest events" in second.text
    assert '<a href="/?">' in second.text
    assert "Older events" not in second.text  # only 3 events left


def test_paging_keeps_filters(client, store):
    github = _fill(store, 7, source="github")
    _fill(store, 4, source="stripe")
    link = _older_link(client.get("/", params={"source": "github", "verification": "valid"}).text)
    assert "source=github" in link and "verification=valid" in link and "before_id=" in link
    page = client.get(link).text
    assert _shown(page) == [github[1], github[0]]  # only the two oldest github events remain
    newest = re.search(r'<a href="([^"]+)">&larr; Newest events', page).group(1).replace("&amp;", "&")
    assert "source=github" in newest and "before_id" not in newest

