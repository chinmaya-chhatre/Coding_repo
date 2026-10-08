import base64
import hashlib
import hmac
import json
import time

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


def test_dashboard_has_replay_form_per_event(client):
    first = client.post("/hooks/generic", content=b"{}").json()["id"]
    second = client.post("/hooks/generic", content=b"{}").json()["id"]
    html = client.get("/").text
    assert f'data-event-id="{first}"' in html
    assert f'data-event-id="{second}"' in html
    assert "/replay" in html


def test_shopify_webhook_is_verified(tmp_path):
    store = EventStore(str(tmp_path / "shopify.db"))
    client = TestClient(create_app(store=store, secrets={"shopify": SECRET}))
    body = b'{"id": 1, "total_price": "49.00"}'
    sig = base64.b64encode(hmac.new(SECRET.encode(), body, hashlib.sha256).digest()).decode()

    ok = client.post("/hooks/shopify", content=body, headers={"X-Shopify-Hmac-Sha256": sig})
    bad = client.post("/hooks/shopify", content=body, headers={"X-Shopify-Hmac-Sha256": "AAAA"})

    assert ok.status_code == 202 and ok.json()["verification"] == "valid"
    assert bad.status_code == 401 and bad.json()["verification"] == "invalid"


def _slack_client(tmp_path) -> TestClient:
    store = EventStore(str(tmp_path / "slack.db"))
    return TestClient(create_app(store=store, secrets={"slack": SECRET}))


def _slack_post(client: TestClient, payload: dict, secret: str = SECRET):
    body = json.dumps(payload).encode()
    ts = str(int(time.time()))
    sig = hmac.new(secret.encode(), b"v0:" + ts.encode() + b":" + body, hashlib.sha256).hexdigest()
    headers = {"X-Slack-Request-Timestamp": ts, "X-Slack-Signature": f"v0={sig}"}
    return client.post("/hooks/slack", content=body, headers=headers)


def test_slack_url_verification_echoes_challenge(tmp_path):
    client = _slack_client(tmp_path)
    resp = _slack_post(client, {"type": "url_verification", "challenge": "3eZbrw1aBm2rZgRNFdxV"})
    assert resp.status_code == 200
    assert resp.json() == {"challenge": "3eZbrw1aBm2rZgRNFdxV"}
    assert client.get("/api/events").json()[0]["verification"] == "valid"


def test_slack_url_verification_with_bad_signature_is_rejected(tmp_path):
    client = _slack_client(tmp_path)
    resp = _slack_post(client, {"type": "url_verification", "challenge": "abc"}, secret="wrong")
    assert resp.status_code == 401
    assert "challenge" not in resp.json()


def test_slack_event_callback_is_accepted(tmp_path):
    client = _slack_client(tmp_path)
    resp = _slack_post(client, {"type": "event_callback", "event": {"type": "app_mention"}})
    assert resp.status_code == 202
    assert resp.json()["verification"] == "valid"


def test_twilio_webhook_is_verified_against_request_url(tmp_path):
    store = EventStore(str(tmp_path / "twilio.db"))
    client = TestClient(create_app(store=store, secrets={"twilio": SECRET}))
    body = b"From=%2B15551230000&Body=STATUS&MessageSid=SM123"
    # TestClient requests go to http://testserver, so that is the URL Twilio would have signed.
    signed = "http://testserver/hooks/twilio" + "".join(
        k + v for k, v in sorted([("From", "+15551230000"), ("Body", "STATUS"), ("MessageSid", "SM123")])
    )
    sig = base64.b64encode(hmac.new(SECRET.encode(), signed.encode(), hashlib.sha1).digest()).decode()
    form = {"Content-Type": "application/x-www-form-urlencoded"}

    ok = client.post("/hooks/twilio", content=body, headers={**form, "X-Twilio-Signature": sig})
    bad = client.post("/hooks/twilio?x=1", content=body, headers={**form, "X-Twilio-Signature": sig})

    assert ok.status_code == 202 and ok.json()["verification"] == "valid"
    assert bad.status_code == 401


def test_svix_webhook_is_verified(tmp_path):
    key = b"0123456789abcdef0123456789abcdef"
    secret = "whsec_" + base64.b64encode(key).decode()
    store = EventStore(str(tmp_path / "svix.db"))
    client = TestClient(create_app(store=store, secrets={"svix": secret}))
    body = b'{"type": "invoice.paid", "data": {"id": "inv_1"}}'
    ts = str(int(time.time()))
    digest = hmac.new(key, b"msg_1." + ts.encode() + b"." + body, hashlib.sha256).digest()
    sig = base64.b64encode(digest).decode()
    headers = {"svix-id": "msg_1", "svix-timestamp": ts, "svix-signature": f"v1,{sig}"}

    ok = client.post("/hooks/svix", content=body, headers=headers)
    bad = client.post("/hooks/svix", content=body + b" ", headers=headers)

    assert ok.status_code == 202 and ok.json()["verification"] == "valid"
    assert bad.status_code == 401
