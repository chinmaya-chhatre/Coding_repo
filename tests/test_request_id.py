import sqlite3

import httpx
import pytest
from fastapi.testclient import TestClient

from hookscope import request_id
from hookscope.main import create_app
from hookscope.rules import ForwardRule
from hookscope.store import EventStore


@pytest.fixture
def store(tmp_path):
    return EventStore(str(tmp_path / "rid.db"))


@pytest.fixture
def client(store):
    return TestClient(create_app(store=store, secrets={}))


# ------------------------------------------------------------------ accept or generate


@pytest.mark.parametrize("supplied", ["abc123", "req-2026.10.16:7", "a/b=c+d", "A" * 128, "  padded  "])
def test_usable_ids_are_kept(supplied):
    assert request_id.accept_or_generate(supplied) == supplied.strip()


@pytest.mark.parametrize(
    "supplied",
    [None, "", "   ", "A" * 129, "has space", "new\nline", "semi;colon", "<script>", "-leading", "é"],
)
def test_unusable_ids_are_replaced(supplied):
    generated = request_id.accept_or_generate(supplied)
    assert generated != supplied
    assert len(generated) == 32 and generated.isalnum()


def test_generated_ids_are_unique():
    assert len({request_id.generate() for _ in range(100)}) == 100


# ------------------------------------------------------------------------- the app


def test_every_response_carries_an_id(client):
    assert len(client.get("/healthz").headers["x-request-id"]) == 32
    assert client.get("/api/events/999").headers["x-request-id"]  # errors too
    assert client.get("/").headers["x-request-id"]


def test_a_supplied_id_is_echoed(client):
    response = client.get("/healthz", headers={"X-Request-ID": "trace-42"})
    assert response.headers["x-request-id"] == "trace-42"


def test_a_malformed_id_is_replaced_not_rejected(client):
    response = client.get("/healthz", headers={"X-Request-ID": "bad id!"})
    assert response.status_code == 200
    assert response.headers["x-request-id"] != "bad id!"


def test_the_id_is_stored_on_the_event_and_shown(client, store):
    receipt = client.post("/hooks/generic", content=b"{}", headers={"X-Request-ID": "trace-42"})
    assert receipt.headers["x-request-id"] == "trace-42"
    event = store.get(receipt.json()["id"])
    assert event["request_id"] == "trace-42"
    assert client.get(f"/api/events/{event['id']}").json()["request_id"] == "trace-42"
    assert "Request ID <code>trace-42</code>" in client.get(f"/events/{event['id']}").text


def test_a_generated_id_is_stored_too(client, store):
    receipt = client.post("/hooks/generic", content=b"{}")
    assert store.get(receipt.json()["id"])["request_id"] == receipt.headers["x-request-id"]


def test_rejected_deliveries_get_an_id_as_well(client, store):
    client.post("/hooks/github", content=b"{}")  # no secret configured, accepted
    app = create_app(store=store, secrets={"github": "s"})
    rejected = TestClient(app).post(
        "/hooks/github", content=b"{}", headers={"X-Hub-Signature-256": "sha256=0"}
    )
    assert rejected.status_code == 401
    assert store.get(rejected.json()["id"])["request_id"] == rejected.headers["x-request-id"]


def test_the_password_wall_still_returns_an_id(tmp_path):
    store = EventStore(str(tmp_path / "pw.db"))
    secured = TestClient(create_app(store=store, secrets={}, admin_password="pw"))
    response = secured.get("/api/events", headers={"X-Request-ID": "trace-7"})
    assert response.status_code == 401
    assert response.headers["x-request-id"] == "trace-7"


def test_the_openapi_event_schema_has_the_field(client):
    schema = client.get("/openapi.json").json()["components"]["schemas"]["EventOut"]
    assert "request_id" in schema["properties"]


# ---------------------------------------------------------------------------- storage


def test_old_databases_gain_the_column(tmp_path):
    path = str(tmp_path / "old.db")
    with sqlite3.connect(path) as conn:
        conn.execute(
            "CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, source TEXT NOT NULL, "
            "received_at TEXT NOT NULL, headers TEXT NOT NULL, body TEXT NOT NULL, "
            "verification TEXT NOT NULL, reason TEXT NOT NULL DEFAULT '')"
        )
        conn.execute(
            "INSERT INTO events (source, received_at, headers, body, verification) "
            "VALUES ('generic', '2026-01-01T00:00:00+00:00', '{}', 'x', 'valid')"
        )
    store = EventStore(path)
    assert store.get(1)["request_id"] is None
    new_id = store.add(
        source="generic", headers={}, body="y", verification="valid", reason="", request_id="r-1"
    )
    assert store.get(new_id)["request_id"] == "r-1"


# -------------------------------------------------------------------------- forwarding


def _forwarding_app(store, seen):
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(dict(request.headers))
        return httpx.Response(200)

    rule = ForwardRule("ci", "https://target.test/hook")
    http = httpx.Client(transport=httpx.MockTransport(handler))
    return TestClient(
        create_app(store=store, secrets={}, rules=[rule], http_client=http, sleep=lambda s: None)
    )


def test_the_id_is_passed_to_the_forward_target(store):
    seen: list[dict] = []
    _forwarding_app(store, seen).post("/hooks/generic", content=b"{}", headers={"X-Request-ID": "trace-42"})
    assert seen[0]["x-request-id"] == "trace-42"


def test_a_generated_id_is_passed_on_too(store):
    seen: list[dict] = []
    receipt = _forwarding_app(store, seen).post("/hooks/generic", content=b"{}")
    assert seen[0]["x-request-id"] == receipt.headers["x-request-id"]


def test_the_senders_header_is_not_duplicated(store):
    seen: list[dict] = []
    _forwarding_app(store, seen).post("/hooks/generic", content=b"{}", headers={"x-request-id": "sender-1"})
    assert seen[0]["x-request-id"] == "sender-1"
