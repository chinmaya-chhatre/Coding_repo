import hashlib
import hmac
import sqlite3

import httpx
import pytest
from fastapi.testclient import TestClient

from hookscope.main import create_app
from hookscope.replay import replay_headers
from hookscope.rules import ForwardRule
from hookscope.store import REDACTED, EventStore, redact_headers
from tests.test_replay import Recorder

SENDER_HEADERS = {
    "Authorization": "Bearer SECRET-TOKEN",
    "Cookie": "session=abc",
    "X-Custom": "keep-me",
}


def _client(tmp_path, recorder=None, rules=None, secrets=None):
    store = EventStore(str(tmp_path / "redact.db"))
    http_client = httpx.Client(transport=httpx.MockTransport(recorder or Recorder()))
    app = create_app(store=store, secrets=secrets or {}, http_client=http_client, rules=rules or [])
    return TestClient(app), store


def test_redact_headers_is_case_insensitive_and_keeps_the_rest():
    redacted = redact_headers(
        {
            "AUTHORIZATION": "x",
            "proxy-authorization": "y",
            "Cookie": "z",
            "Set-Cookie": "w",
            "X-Signature": "sig",
        }
    )
    assert redacted == {
        "AUTHORIZATION": REDACTED,
        "proxy-authorization": REDACTED,
        "Cookie": REDACTED,
        "Set-Cookie": REDACTED,
        "X-Signature": "sig",
    }


def test_credentials_are_not_stored_or_shown(tmp_path):
    client, store = _client(tmp_path)
    event_id = client.post("/hooks/generic", content=b"{}", headers=SENDER_HEADERS).json()["id"]

    headers = client.get(f"/api/events/{event_id}").json()["headers"]

    assert headers["authorization"] == REDACTED and headers["cookie"] == REDACTED
    assert headers["x-custom"] == "keep-me"
    with sqlite3.connect(store.path) as conn:
        raw_row = conn.execute("SELECT headers FROM events").fetchone()[0]
    assert "SECRET-TOKEN" not in raw_row and "session=abc" not in raw_row


def test_signature_verification_is_unaffected(tmp_path):
    client, _ = _client(tmp_path, secrets={"generic": "s3cret"})
    body = b'{"ok": true}'
    sig = hmac.new(b"s3cret", body, hashlib.sha256).hexdigest()
    resp = client.post("/hooks/generic", content=body, headers={"X-Signature": sig, **SENDER_HEADERS})
    assert resp.json()["verification"] == "valid"


@pytest.mark.parametrize("stored", [REDACTED, "Bearer LEGACY-TOKEN"])
def test_replay_never_sends_credential_headers(tmp_path, stored):
    # The second case is an event stored by an older version, before redaction existed.
    recorder = Recorder()
    client, store = _client(tmp_path, recorder)
    event_id = client.post("/hooks/generic", content=b"{}", headers={"X-Custom": "keep-me"}).json()["id"]
    with sqlite3.connect(store.path) as conn:
        conn.execute(
            "UPDATE events SET headers = json_set(headers, '$.authorization', ?, '$.cookie', ?)",
            (stored, stored),
        )

    client.post(f"/api/events/{event_id}/replay", json={"target_url": "http://other.test/"})

    sent = recorder.requests[0].headers
    assert "authorization" not in sent and "cookie" not in sent
    assert sent["x-custom"] == "keep-me"


def test_forwards_to_other_hosts_do_not_carry_credentials(tmp_path):
    recorder = Recorder()
    client, _ = _client(tmp_path, recorder, rules=[ForwardRule("other", "http://other-company.test/")])
    client.post("/hooks/generic", content=b"{}", headers=SENDER_HEADERS)
    sent = recorder.requests[0].headers
    assert "authorization" not in sent and "cookie" not in sent
    assert sent["x-custom"] == "keep-me"


def test_replay_headers_helper_drops_credentials_from_legacy_events():
    headers = replay_headers({"id": 1, "headers": {"Authorization": "Bearer t", "x-ok": "1"}})
    assert "Authorization" not in headers and headers["x-ok"] == "1"
