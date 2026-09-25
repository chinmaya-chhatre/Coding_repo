import hashlib
import hmac

import httpx
import pytest
from fastapi.testclient import TestClient

from hookscope.main import create_app
from hookscope.replay import REPLAY_HEADER, replay_headers
from hookscope.signatures import verify_github
from hookscope.store import EventStore

SECRET = "s3cret"
BODY = b'{"action": "opened"}'


class Recorder:
    """httpx transport that records requests and returns a canned response."""

    def __init__(self, status_code: int = 200, text: str = "ok", error: Exception | None = None):
        self.requests: list[httpx.Request] = []
        self.status_code = status_code
        self.text = text
        self.error = error

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.error:
            raise self.error
        return httpx.Response(self.status_code, text=self.text)


def _make_client(tmp_path, recorder: Recorder) -> TestClient:
    store = EventStore(str(tmp_path / "test.db"))
    http_client = httpx.Client(transport=httpx.MockTransport(recorder))
    return TestClient(create_app(store=store, secrets={"github": SECRET}, http_client=http_client))


def _capture_github_event(client: TestClient) -> int:
    sig = hmac.new(SECRET.encode(), BODY, hashlib.sha256).hexdigest()
    headers = {"X-Hub-Signature-256": f"sha256={sig}", "X-GitHub-Event": "pull_request"}
    return client.post("/hooks/github", content=BODY, headers=headers).json()["id"]


def test_replay_forwards_body_and_signature(tmp_path):
    recorder = Recorder(status_code=204, text="")
    client = _make_client(tmp_path, recorder)
    event_id = _capture_github_event(client)

    resp = client.post(f"/api/events/{event_id}/replay", json={"target_url": "http://localhost:9000/hook"})

    assert resp.status_code == 200
    assert resp.json()["status_code"] == 204
    assert resp.json()["ok"] is True
    sent = recorder.requests[0]
    assert str(sent.url) == "http://localhost:9000/hook"
    assert sent.content == BODY
    assert sent.headers[REPLAY_HEADER] == str(event_id)
    assert sent.headers["x-github-event"] == "pull_request"
    # The replayed request must still pass the original provider's signature check.
    assert verify_github(sent.content, dict(sent.headers), SECRET).status == "valid"


def test_replay_reports_target_error_status(tmp_path):
    client = _make_client(tmp_path, Recorder(status_code=500, text="boom"))
    event_id = _capture_github_event(client)

    body = client.post(f"/api/events/{event_id}/replay", json={"target_url": "http://example.test/"}).json()

    assert body["status_code"] == 500
    assert body["ok"] is False
    assert body["response_body"] == "boom"


def test_replay_unreachable_target_returns_502(tmp_path):
    client = _make_client(tmp_path, Recorder(error=httpx.ConnectError("connection refused")))
    event_id = _capture_github_event(client)

    resp = client.post(f"/api/events/{event_id}/replay", json={"target_url": "http://example.test/"})

    assert resp.status_code == 502
    assert "ConnectError" in resp.json()["error"]


@pytest.mark.parametrize("url", ["ftp://example.test/", "not-a-url", "http://"])
def test_replay_rejects_invalid_target(tmp_path, url):
    recorder = Recorder()
    client = _make_client(tmp_path, recorder)
    event_id = _capture_github_event(client)

    resp = client.post(f"/api/events/{event_id}/replay", json={"target_url": url})

    assert resp.status_code == 422
    assert recorder.requests == []


def test_replay_unknown_event(tmp_path):
    client = _make_client(tmp_path, Recorder())
    resp = client.post("/api/events/999/replay", json={"target_url": "http://example.test/"})
    assert resp.status_code == 404


def test_replay_headers_drop_hop_by_hop():
    event = {"id": 3, "headers": {"host": "a", "content-length": "5", "x-signature": "abc"}}
    assert replay_headers(event) == {"x-signature": "abc", REPLAY_HEADER: "3"}
