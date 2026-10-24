import re

import pytest
from fastapi.testclient import TestClient

from hookscope.main import create_app
from hookscope.samples import build_sample
from hookscope.store import EventStore

SECRET = "sample-secret"


@pytest.fixture
def store(tmp_path):
    return EventStore(str(tmp_path / "panel.db"))


@pytest.fixture
def client(store):
    secrets = {"github": SECRET, "stripe": SECRET}
    return TestClient(create_app(store=store, secrets=secrets, admin_password=None))


def panel(html: str) -> str | None:
    match = re.search(r'<section class="diagnosis".*?</section>', html, re.S)
    return match.group(0) if match else None


def rejected_event(client) -> int:
    return client.post("/hooks/github", content=b"{}").json()["id"]  # no signature at all


def test_a_rejected_event_explains_itself_on_its_page(client):
    event_id = rejected_event(client)
    html = client.get(f"/events/{event_id}").text
    box = panel(html)
    assert box and "Why did this fail?" in box
    assert "no X-Hub-Signature-256 header" in box
    assert "<strong>Fix:</strong>" in box and "X-Hub-Signature-256" in box
    assert "<code>missing_signature</code>" in box


def test_the_dashboard_list_shows_the_panel_and_the_cause(client):
    rejected_event(client)
    html = client.get("/").text
    assert panel(html) and '<span class="muted cause">missing_signature</span>' in html


def test_a_valid_event_has_no_panel(client):
    sample = build_sample("github", SECRET, url="https://h.example/hooks/github")
    assert client.post("/hooks/github", content=sample.body, headers=sample.headers).status_code == 202
    html = client.get("/events/1").text
    assert panel(html) is None and "Why did this fail?" not in html and 'class="muted cause"' not in html


def test_an_old_rejected_event_without_a_diagnosis_shows_no_panel(client, store):
    event_id = store.add("github", {}, "{}", "invalid", "signature mismatch")  # from before diagnoses
    html = client.get(f"/events/{event_id}").text
    assert "invalid" in html and panel(html) is None


def test_diagnosis_text_is_escaped(client, store):
    nasty = {"cause": "x<b>", "message": "<script>alert(1)</script>", "fix": '"><img src=x onerror=alert(2)>'}
    event_id = store.add("github", {}, "{}", "invalid", "r", diagnosis=nasty)
    html = client.get(f"/events/{event_id}").text
    assert "<script>alert(1)" not in html and "<img src=x" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in panel(html)


def test_the_panel_sits_before_the_raw_body(client):
    html = client.get(f"/events/{rejected_event(client)}").text
    assert html.index("Why did this fail?") < html.index("<pre>")


def test_several_rejected_events_each_get_their_own_panel(client):
    rejected_event(client)
    client.post("/hooks/stripe", content=b"{}")
    html = client.get("/").text
    assert len(re.findall(r'<section class="diagnosis"', html)) == 2
    assert 'aria-label="Why event 1 failed"' in html and 'aria-label="Why event 2 failed"' in html


def test_the_filter_for_rejected_events_still_works_with_panels(client):
    rejected_event(client)
    html = client.get("/?verification=unsigned").text
    assert panel(html) is not None
