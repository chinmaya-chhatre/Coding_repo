import base64
import shlex
import subprocess

import pytest
from fastapi.testclient import TestClient

from hookscope.curl import build_curl, redacted_headers
from hookscope.main import create_app
from hookscope.store import EventStore

GITHUB_SECRET = "It's a Secret to Everybody"
GITHUB_SIGNATURE = "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17"


@pytest.fixture
def store(tmp_path):
    return EventStore(str(tmp_path / "curl.db"))


@pytest.fixture
def client(store):
    return TestClient(create_app(store=store, secrets={"github": GITHUB_SECRET}))


def parse(command: str) -> dict:
    """Read a built command back the way a shell would: URL, headers and the data argument."""
    tokens = shlex.split(command.replace("\\\n", " "), comments=True)
    assert tokens[:3] == ["curl", "-sS", "-X"] or "curl" in tokens
    start = tokens.index("curl")
    args = tokens[start + 1 :]
    headers = {}
    url = body = None
    i = 0
    while i < len(args):
        if args[i] == "-H":
            name, _, value = args[i + 1].partition(": ")
            headers[name] = value
            i += 2
        elif args[i] == "--data-binary":
            body = args[i + 1]
            i += 2
        elif args[i] in ("-sS", "-X", "POST"):
            i += 1
        else:
            url = args[i]
            i += 1
    return {"url": url, "headers": headers, "body": body}


def receive(client, body=b"Hello, World!", signature=GITHUB_SIGNATURE, headers=None):
    return client.post(
        "/hooks/github",
        content=body,
        headers={"X-Hub-Signature-256": signature, "Content-Type": "text/plain", **(headers or {})},
    )


def test_rebuilt_command_carries_headers_body_and_target(client, store):
    event_id = receive(client, headers={"X-GitHub-Event": "push"}).json()["id"]
    command = build_curl(store.get(event_id), "http://hooks.test:8000/")
    parsed = parse(command)
    assert parsed["url"] == "http://hooks.test:8000/hooks/github"
    assert parsed["body"] == "Hello, World!"
    assert parsed["headers"]["x-hub-signature-256"] == GITHUB_SIGNATURE
    assert parsed["headers"]["x-github-event"] == "push"
    assert command.startswith("# Rebuilt from HookScope event #")


def test_replaying_the_command_verifies_again(client, store):
    event_id = receive(client).json()["id"]
    parsed = parse(build_curl(store.get(event_id), "http://testserver"))
    assert "host" not in {name.lower() for name in parsed["headers"]}
    again = client.post("/hooks/github", content=parsed["body"].encode(), headers=parsed["headers"])
    assert again.status_code == 202 and again.json()["verification"] == "valid"


def test_transport_and_credential_headers_are_left_out(client, store):
    event_id = receive(client, headers={"Authorization": "Bearer hunter2", "Cookie": "sid=1"}).json()["id"]
    event = store.get(event_id)
    command = build_curl(event, "http://x")
    names = {name.lower() for name in parse(command)["headers"]}
    assert not names & {"host", "content-length", "connection", "accept-encoding", "authorization", "cookie"}
    assert "hunter2" not in command and "sid=1" not in command
    assert redacted_headers(event) == ["authorization", "cookie"]
    assert "Not included, because credentials are never stored: authorization, cookie." in command


def test_body_with_quotes_newlines_and_unicode_survives_quoting(client, store):
    body = 'it\'s "quoted"\nline two ✓ $HOME `x`'
    event_id = receive(client, body=body.encode(), signature="sha256=bad").json()["id"]
    assert parse(build_curl(store.get(event_id), "http://x"))["body"] == body


def test_non_utf8_body_is_sent_as_exact_bytes(client, store):
    raw = b"\xff\xfe\x00binary\x80"
    event_id = receive(client, body=raw, signature="sha256=bad").json()["id"]
    event = store.get(event_id)
    assert event["body_base64"] == base64.b64encode(raw).decode()
    command = build_curl(event, "http://x")
    assert "base64 -d | curl" in command and "--data-binary @-" in command
    produced = subprocess.run(
        ["bash", "-c", command.split("| curl")[0]], capture_output=True, check=True
    ).stdout
    assert produced == raw


def test_notes_for_providers_with_time_or_url_dependent_signatures(store):
    for source, note in (
        ("stripe", "carries a timestamp"),
        ("slack", "carries a timestamp"),
        ("svix", "carries a timestamp"),
        ("twilio", "signs the full public URL"),
    ):
        event_id = store.add(source=source, headers={}, body="{}", verification="valid", reason="")
        assert note in build_curl(store.get(event_id), "http://x")
    event_id = store.add(source="github", headers={}, body="{}", verification="valid", reason="")
    assert "timestamp" not in build_curl(store.get(event_id), "http://x")


def test_empty_body(store):
    event_id = store.add(source="generic", headers={"x": "y"}, body="", verification="valid", reason="")
    assert parse(build_curl(store.get(event_id), "http://x"))["body"] == ""


# ------------------------------------------------------------------------- API and page


def test_api_returns_the_command_for_this_server(client):
    event_id = receive(client).json()["id"]
    response = client.get(f"/api/events/{event_id}/curl")
    assert response.status_code == 200
    body = response.json()
    assert "http://testserver/hooks/github" in body["command"]
    assert body["omitted_headers"] == []


def test_api_404_and_docs(client):
    assert client.get("/api/events/999/curl").status_code == 404
    spec = client.get("/openapi.json").json()
    operation = spec["paths"]["/api/events/{event_id}/curl"]["get"]
    assert operation["tags"] == ["events"] and operation["summary"]


def test_api_is_behind_the_password(tmp_path):
    store = EventStore(str(tmp_path / "a.db"))
    event_id = store.add(source="generic", headers={}, body="x", verification="valid", reason="")
    secured = TestClient(create_app(store=store, secrets={}, admin_password="pw"))
    assert secured.get(f"/api/events/{event_id}/curl").status_code == 401
    assert (
        secured.get(f"/api/events/{event_id}/curl", headers={"Authorization": "Bearer pw"}).status_code == 200
    )


def test_pages_have_the_copy_button(client, store):
    event_id = receive(client).json()["id"]
    for page in ("/", f"/events/{event_id}"):
        html = client.get(page).text
        assert 'class="copy-curl"' in html and f'data-event-id="{event_id}"' in html
