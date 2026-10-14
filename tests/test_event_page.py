import re

import pytest
from fastapi.testclient import TestClient

from hookscope.main import create_app
from hookscope.rules import ForwardRule
from hookscope.store import EventStore


@pytest.fixture
def store(tmp_path):
    return EventStore(str(tmp_path / "page.db"))


@pytest.fixture
def client(store):
    return TestClient(create_app(store=store, secrets={}))


def _add(store, body='{"hello": "world"}', source="generic"):
    return store.add(source=source, headers={"x-test": "yes"}, body=body, verification="valid", reason="")


def test_event_page_shows_the_event_expanded(client, store):
    event_id = _add(store)
    response = client.get(f"/events/{event_id}")
    assert response.status_code == 200
    html = response.text
    assert f"<strong>#{event_id}</strong>" in html
    assert "<details open>" in html
    assert "&#34;hello&#34;: &#34;world&#34;" in html  # pretty-printed body
    assert "x-test: yes" in html
    assert "<title>Event #" in html


def test_event_page_has_replay_and_preview_forms_and_the_scripts_they_need(client, store):
    html = client.get(f"/events/{_add(store)}").text
    assert 'form class="replay"' in html
    assert 'form class="preview"' in html
    assert 'id="transform-rules"' in html
    assert "/api/events/" in html  # the page script that drives replay


def test_event_page_links_back_to_the_dashboard(client, store):
    html = client.get(f"/events/{_add(store)}").text
    assert 'href="/">&larr; All events' in html


def test_unknown_event_is_a_404_page_not_json(client):
    response = client.get("/events/999")
    assert response.status_code == 404
    assert response.headers["content-type"].startswith("text/html")
    assert "No event with that id" in response.text


def test_non_numeric_id_is_rejected(client):
    assert client.get("/events/abc").status_code == 422


def test_dashboard_events_link_to_their_permalink(client, store):
    event_id = _add(store)
    html = client.get("/").text
    assert f'<a href="/events/{event_id}">Permalink</a>' in html
    assert "<details open>" not in html  # dashboard rows stay collapsed


def test_event_page_lists_forward_attempts(tmp_path):
    import httpx

    store = EventStore(str(tmp_path / "fwd.db"))
    rule = ForwardRule("ci", "https://target.test/hook", source="generic")
    transport = httpx.MockTransport(lambda request: httpx.Response(200))
    http = httpx.Client(transport=transport)
    app = create_app(store=store, secrets={}, rules=[rule], http_client=http, sleep=lambda s: None)
    client = TestClient(app)
    receipt = client.post("/hooks/generic", content=b'{"a": 1}').json()
    html = client.get(f"/events/{receipt['id']}").text
    assert "https://target.test/hook" in html
    assert "HTTP 200" in html
    assert re.search(r"forwarded 1", html)


def test_event_page_is_in_the_docs_and_behind_the_password(tmp_path):
    store = EventStore(str(tmp_path / "auth.db"))
    secured = TestClient(create_app(store=store, secrets={}, admin_password="pw"))
    event_id = _add(store)
    assert secured.get(f"/events/{event_id}").status_code == 401
    assert secured.get(f"/events/{event_id}", headers={"Authorization": "Bearer pw"}).status_code == 200
    spec = secured.get("/openapi.json", headers={"Authorization": "Bearer pw"}).json()
    assert spec["paths"]["/events/{event_id}"]["get"]["tags"] == ["dashboard"]
