"""Bodies that are not valid UTF-8 must be re-sent byte for byte."""

import base64
import hashlib
import hmac
import sqlite3

import httpx
from fastapi.testclient import TestClient

from hookscope.main import create_app
from hookscope.rules import ForwardRule
from hookscope.signatures import verify_generic
from hookscope.store import EventStore, body_bytes
from tests.test_replay import Recorder

SECRET = "s3cret"
# "café" in Latin-1, as some legacy systems post it; \xe9 alone is invalid UTF-8.
LATIN1_BODY = b"name=caf\xe9&amount=5"


def test_replay_resends_non_utf8_body_unchanged(tmp_path):
    recorder = Recorder(status_code=204, text="")
    client = TestClient(
        create_app(
            store=EventStore(str(tmp_path / "raw.db")),
            secrets={"generic": SECRET},
            http_client=httpx.Client(transport=httpx.MockTransport(recorder)),
        )
    )
    sig = hmac.new(SECRET.encode(), LATIN1_BODY, hashlib.sha256).hexdigest()
    event_id = client.post("/hooks/generic", content=LATIN1_BODY, headers={"X-Signature": sig}).json()["id"]

    client.post(f"/api/events/{event_id}/replay", json={"target_url": "http://target.test/"})

    sent = recorder.requests[0]
    assert sent.content == LATIN1_BODY
    assert verify_generic(sent.content, dict(sent.headers), SECRET).status == "valid"


def _client(tmp_path, recorder: Recorder, rules=None) -> tuple[TestClient, EventStore]:
    store = EventStore(str(tmp_path / "raw.db"))
    app = create_app(
        store=store,
        secrets={},
        http_client=httpx.Client(transport=httpx.MockTransport(recorder)),
        rules=rules or [],
    )
    return TestClient(app), store


def test_forward_resends_non_utf8_body_unchanged(tmp_path):
    recorder = Recorder(status_code=200)
    client, _ = _client(tmp_path, recorder, rules=[ForwardRule("legacy", "http://legacy.test/")])
    client.post("/hooks/generic", content=LATIN1_BODY)
    assert recorder.requests[0].content == LATIN1_BODY


def test_transformed_forward_sends_the_new_document_not_the_raw_bytes(tmp_path):
    recorder = Recorder(status_code=200)
    rule = ForwardRule("t", "http://t.test/", transform={"kind": "@event_type"})
    client, _ = _client(tmp_path, recorder, rules=[rule])
    client.post("/hooks/generic", content=b"\xff\xfe not json")
    assert recorder.requests[0].content == b'{"kind": null}'


def test_api_exposes_exact_bytes_only_for_non_utf8_bodies(tmp_path):
    client, _ = _client(tmp_path, Recorder())
    binary_id = client.post("/hooks/generic", content=LATIN1_BODY).json()["id"]
    text_id = client.post("/hooks/generic", content='{"name": "café"}'.encode()).json()["id"]

    binary = client.get(f"/api/events/{binary_id}").json()
    text = client.get(f"/api/events/{text_id}").json()

    assert base64.b64decode(binary["body_base64"]) == LATIN1_BODY
    assert "�" in binary["body"]  # the readable text stays lossy, the base64 is exact
    assert text["body_base64"] is None and text["body"] == '{"name": "café"}'


def test_older_databases_gain_the_column(tmp_path):
    path = str(tmp_path / "old.db")
    with sqlite3.connect(path) as conn:
        conn.execute(
            "CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, source TEXT NOT NULL, "
            "received_at TEXT NOT NULL, headers TEXT NOT NULL, body TEXT NOT NULL, "
            "verification TEXT NOT NULL, reason TEXT NOT NULL DEFAULT '')"
        )
        conn.execute(
            "INSERT INTO events (source, received_at, headers, body, verification) "
            "VALUES ('generic', '2026-10-01T00:00:00+00:00', '{}', 'old', 'valid')"
        )
    store = EventStore(path)
    old = store.get(1)
    assert old["body_base64"] is None and body_bytes(old) == b"old"
    new_id = store.add("generic", {}, "x", "valid", "", raw_body=b"\x80")
    assert body_bytes(store.get(new_id)) == b"\x80"
