import hashlib
import hmac

import pytest
from fastapi.testclient import TestClient

from hookscope.main import create_app
from hookscope.store import EventStore

SECRET = "s3cret"


@pytest.fixture
def client(tmp_path):
    store = EventStore(str(tmp_path / "test.db"))
    return TestClient(create_app(store=store, secrets={"github": SECRET}))


def _github_headers(body: bytes) -> dict:
    sig = hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()
    return {"X-Hub-Signature-256": f"sha256={sig}", "Content-Type": "application/json"}


def test_healthz(client):
    assert client.get("/healthz").json()["status"] == "ok"


def test_valid_webhook_is_accepted_and_stored(client):
    body = b'{"action": "opened"}'
    resp = client.post("/hooks/github", content=body, headers=_github_headers(body))
    assert resp.status_code == 202
    event = client.get(f"/api/events/{resp.json()['id']}").json()
    assert event["verification"] == "valid"
    assert event["body"] == body.decode()


def test_invalid_webhook_is_rejected_but_stored(client):
    resp = client.post("/hooks/github", content=b"{}", headers={"X-Hub-Signature-256": "sha256=bad"})
    assert resp.status_code == 401
    assert client.get("/api/events").json()[0]["verification"] == "invalid"


def test_source_without_secret_is_accepted(client):
    resp = client.post("/hooks/generic", content=b"{}")
    assert resp.status_code == 202
    assert resp.json()["verification"] == "no_secret"


def test_unknown_source(client):
    assert client.post("/hooks/nope", content=b"{}").status_code == 404


def test_filter_by_source(client):
    client.post("/hooks/generic", content=b"{}")
    body = b"{}"
    client.post("/hooks/github", content=body, headers=_github_headers(body))
    events = client.get("/api/events", params={"source": "generic"}).json()
    assert [e["source"] for e in events] == ["generic"]


def test_dashboard_renders(client):
    client.post("/hooks/generic", content=b'{"a": 1}')
    resp = client.get("/")
    assert resp.status_code == 200
    assert "generic" in resp.text
