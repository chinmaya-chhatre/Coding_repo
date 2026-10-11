import base64

import httpx
import pytest
from fastapi.testclient import TestClient

from hookscope.auth import is_authorized, is_public, password_from_env
from hookscope.main import create_app
from hookscope.retention import RetentionPolicy
from hookscope.rules import ForwardRule
from hookscope.store import EventStore
from tests.test_replay import Recorder

PASSWORD = "correct horse battery"


def _basic(user: str, password: str) -> dict:
    return {"Authorization": "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()}


@pytest.fixture
def client(tmp_path):
    store = EventStore(str(tmp_path / "auth.db"))
    return TestClient(create_app(store=store, secrets={}, admin_password=PASSWORD))


PROTECTED = [
    ("GET", "/"),
    ("GET", "/metrics"),
    ("GET", "/api/events"),
    ("GET", "/api/events/1"),
    ("POST", "/api/events/1/replay"),
    ("POST", "/api/purge"),
    ("POST", "/api/events/1/transform-preview"),
]


@pytest.mark.parametrize(("method", "path"), PROTECTED)
def test_protected_endpoints_require_credentials(client, method, path):
    resp = client.request(method, path, json={})
    assert resp.status_code == 401
    assert resp.headers["www-authenticate"].startswith("Basic realm=")


def test_webhooks_and_health_stay_public(client):
    assert client.get("/healthz").status_code == 200
    resp = client.post("/hooks/generic", content=b"{}")
    assert resp.status_code == 202


def test_basic_credentials_ignore_the_username(client):
    for user in ("admin", "", "anyone"):
        assert client.get("/api/events", headers=_basic(user, PASSWORD)).status_code == 200
    assert client.get("/").status_code == 401
    assert client.get("/", headers=_basic("admin", PASSWORD)).status_code == 200
    assert client.get("/metrics", headers=_basic("admin", PASSWORD)).status_code == 200


def test_bearer_token_works_for_scripts(client):
    assert client.get("/api/events", headers={"Authorization": f"Bearer {PASSWORD}"}).status_code == 200
    assert client.get("/api/events", headers={"Authorization": "bearer wrong"}).status_code == 401


def test_wrong_or_malformed_credentials_are_rejected(client):
    bad = [
        _basic("admin", "wrong"),
        _basic("admin", PASSWORD + "x"),
        {"Authorization": "Basic !!!not-base64!!!"},
        {"Authorization": "Basic " + base64.b64encode(PASSWORD.encode()).decode()},  # no "user:"
        {"Authorization": "Digest abc"},
        {"Authorization": "Basic"},
    ]
    for headers in bad:
        assert client.get("/api/events", headers=headers).status_code == 401, headers


def test_password_may_contain_colons(tmp_path):
    store = EventStore(str(tmp_path / "colon.db"))
    app = create_app(store=store, secrets={}, admin_password="a:b:c")
    assert TestClient(app).get("/api/events", headers=_basic("u", "a:b:c")).status_code == 200


def test_open_by_default(tmp_path):
    store = EventStore(str(tmp_path / "open.db"))
    assert TestClient(create_app(store=store, secrets={})).get("/api/events").status_code == 200


def test_password_is_read_from_the_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("HOOKSCOPE_ADMIN_PASSWORD", "from-env-secret")
    app = create_app(store=EventStore(str(tmp_path / "env.db")), secrets={})
    client = TestClient(app)
    assert client.get("/api/events").status_code == 401
    assert client.get("/api/events", headers=_basic("u", "from-env-secret")).status_code == 200


def test_blank_password_means_disabled(tmp_path, monkeypatch):
    monkeypatch.setenv("HOOKSCOPE_ADMIN_PASSWORD", "   ")
    app = create_app(store=EventStore(str(tmp_path / "blank.db")), secrets={})
    assert TestClient(app).get("/api/events").status_code == 200
    assert password_from_env({"HOOKSCOPE_ADMIN_PASSWORD": ""}) is None


def test_public_path_matching_is_exact():
    assert is_public("/healthz") and is_public("/hooks/stripe")
    # Lookalikes must not slip through.
    for path in ("/healthz/", "/healthzz", "/hooks", "/hooksx/stripe", "/api/hooks/stripe", "//hooks/x"):
        assert not is_public(path), path


def test_is_authorized_unit():
    assert is_authorized(None, "pw") is False
    assert is_authorized("Bearer pw", "pw") is True
    assert is_authorized("Bearer  pw  ", "pw") is True


def test_forwarding_and_purging_still_run_behind_the_password(tmp_path):
    # Webhooks pass through the auth middleware, and their forwards and the retention purge run
    # as background tasks after the response; neither may be lost when a password is set.
    recorder = Recorder()
    store = EventStore(str(tmp_path / "bg.db"))
    for _ in range(3):
        store.add("generic", {}, "{}", "valid", "")
    app = create_app(
        store=store,
        secrets={},
        admin_password=PASSWORD,
        http_client=httpx.Client(transport=httpx.MockTransport(recorder)),
        rules=[ForwardRule("other", "http://other.test/")],
        retention=RetentionPolicy(max_events=1, interval_seconds=0),
    )

    resp = TestClient(app).post("/hooks/generic", content=b"{}")

    assert resp.status_code == 202
    assert len(recorder.requests) == 1
    assert store.count() == 1
