import hashlib
import hmac
import json

import httpx
import pytest
from fastapi.testclient import TestClient

from hookscope.main import create_app
from hookscope.replay import REPLAY_HEADER
from hookscope.rules import (
    FORWARD_HEADER,
    ForwardRule,
    InvalidRuleError,
    event_type,
    load_rules,
    parse_rules,
)
from hookscope.signatures import verify_github
from hookscope.store import EventStore
from tests.test_replay import Recorder

SECRET = "s3cret"


def _make_client(tmp_path, recorder: Recorder, rules: list[ForwardRule]) -> TestClient:
    store = EventStore(str(tmp_path / "test.db"))
    http_client = httpx.Client(transport=httpx.MockTransport(recorder))
    app = create_app(store=store, secrets={"github": SECRET}, http_client=http_client, rules=rules)
    return TestClient(app)


def _post_github(client: TestClient, event: str, body: bytes = b'{"ref": "main"}', secret: str = SECRET):
    sig = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    headers = {"X-Hub-Signature-256": f"sha256={sig}", "X-GitHub-Event": event}
    return client.post("/hooks/github", content=body, headers=headers)


def test_matching_event_is_forwarded_with_signature(tmp_path):
    recorder = Recorder(status_code=200)
    rule = ForwardRule("ci", "http://ci.test/hook", source="github", event_types=("push",))
    client = _make_client(tmp_path, recorder, [rule])

    resp = _post_github(client, "push")

    assert resp.status_code == 202
    assert resp.json()["forwarded_to"] == ["ci"]
    sent = recorder.requests[0]
    assert str(sent.url) == "http://ci.test/hook"
    assert sent.headers[FORWARD_HEADER] == "ci"
    assert REPLAY_HEADER not in sent.headers
    assert verify_github(sent.content, dict(sent.headers), SECRET).status == "valid"

    forwards = client.get(f"/api/events/{resp.json()['id']}/forwards").json()
    assert [(f["rule"], f["status_code"], f["error"]) for f in forwards] == [("ci", 200, "")]


def test_non_matching_event_type_is_not_forwarded(tmp_path):
    recorder = Recorder()
    rule = ForwardRule("ci", "http://ci.test/hook", source="github", event_types=("push",))
    client = _make_client(tmp_path, recorder, [rule])

    resp = _post_github(client, "issues")

    assert resp.json()["forwarded_to"] == []
    assert recorder.requests == []


def test_rejected_event_is_never_forwarded(tmp_path):
    recorder = Recorder()
    client = _make_client(tmp_path, recorder, [ForwardRule("all", "http://any.test/")])

    resp = _post_github(client, "push", secret="wrong")

    assert resp.status_code == 401
    assert resp.json()["forwarded_to"] == []
    assert recorder.requests == []


def test_fan_out_to_several_targets(tmp_path):
    recorder = Recorder()
    rules = [
        ForwardRule("billing", "http://billing.test/", source="generic", event_types=("invoice.paid",)),
        ForwardRule("audit", "http://audit.test/"),
        ForwardRule("github-only", "http://gh.test/", source="github"),
    ]
    client = _make_client(tmp_path, recorder, rules)

    resp = client.post("/hooks/generic", content=b'{"type": "invoice.paid"}')

    assert resp.json()["forwarded_to"] == ["billing", "audit"]
    assert [str(r.url) for r in recorder.requests] == ["http://billing.test/", "http://audit.test/"]


def test_unreachable_target_is_recorded(tmp_path):
    recorder = Recorder(error=httpx.ConnectError("connection refused"))
    client = _make_client(tmp_path, recorder, [ForwardRule("down", "http://down.test/")])

    resp = client.post("/hooks/generic", content=b"{}")

    assert resp.status_code == 202
    [forward] = client.get(f"/api/events/{resp.json()['id']}/forwards").json()
    assert forward["status_code"] is None
    assert "ConnectError" in forward["error"]


def test_forwards_for_unknown_event(tmp_path):
    client = _make_client(tmp_path, Recorder(), [])
    assert client.get("/api/events/999/forwards").status_code == 404


def test_rules_endpoint_lists_configured_rules(tmp_path):
    rule = ForwardRule("ci", "http://ci.test/", source="github", event_types=("push",))
    client = _make_client(tmp_path, Recorder(), [rule])
    assert client.get("/api/rules").json() == [
        {
            "name": "ci",
            "target_url": "http://ci.test/",
            "source": "github",
            "event_types": ["push"],
            "format": "raw",
        }
    ]


@pytest.mark.parametrize(
    ("event", "expected"),
    [
        ({"source": "github", "headers": {"x-github-event": "push"}, "body": "{}"}, "push"),
        ({"source": "github", "headers": {}, "body": '{"type": "x"}'}, None),
        ({"source": "stripe", "headers": {}, "body": '{"type": "invoice.paid"}'}, "invoice.paid"),
        ({"source": "generic", "headers": {}, "body": "not json"}, None),
        ({"source": "generic", "headers": {}, "body": "[1, 2]"}, None),
        ({"source": "generic", "headers": {}, "body": '{"type": 5}'}, None),
    ],
)
def test_event_type(event, expected):
    assert event_type(event) == expected


def test_parse_rules_accepts_object_and_defaults():
    rules = parse_rules(
        {"rules": [{"target_url": "http://a.test/", "event_types": "push"}, {"name": "b", "target_url": "https://b.test/"}]}
    )
    assert rules == [
        ForwardRule("rule-0", "http://a.test/", None, ("push",)),
        ForwardRule("b", "https://b.test/"),
    ]


@pytest.mark.parametrize(
    ("data", "message"),
    [
        ("nope", "must be a list"),
        (["x"], "must be an object"),
        ([{"name": "a"}], "target_url is required"),
        ([{"name": "a", "target_url": "ftp://x/"}], "absolute http"),
        ([{"name": "a", "target_url": "http://x/", "source": "gitlab"}], "unknown source"),
        ([{"name": "a", "target_url": "http://x/", "event_types": [1]}], "list of strings"),
        ([{"name": "a", "target_url": "http://x/"}, {"name": "a", "target_url": "http://y/"}], "duplicate"),
        ([{"name": "a", "target_url": "http://x/", "format": "teams"}], "format must be one of"),
    ],
)
def test_parse_rules_rejects_bad_definitions(data, message):
    with pytest.raises(InvalidRuleError, match=message):
        parse_rules(data)


def test_load_rules_from_file(tmp_path):
    path = tmp_path / "rules.json"
    path.write_text(json.dumps({"rules": [{"name": "a", "target_url": "http://a.test/"}]}))
    assert load_rules(str(path)) == [ForwardRule("a", "http://a.test/")]
    assert load_rules(None) == []


def test_load_rules_reports_bad_file(tmp_path):
    path = tmp_path / "rules.json"
    path.write_text("{not json")
    with pytest.raises(InvalidRuleError, match="not valid JSON"):
        load_rules(str(path))
    with pytest.raises(InvalidRuleError, match="cannot read"):
        load_rules(str(tmp_path / "missing.json"))


def test_dashboard_shows_forward_attempts(tmp_path):
    recorder = Recorder(status_code=500)
    client = _make_client(tmp_path, recorder, [ForwardRule("ci", "http://ci.test/hook")])

    event_id = client.post("/hooks/generic", content=b"{}").json()["id"]
    html = client.get("/").text

    assert f'aria-label="Forwards for event {event_id}"' in html
    assert "http://ci.test/hook" in html
    assert "HTTP 500" in html
    assert "forwarded 1, 1 failed" in html


def test_dashboard_shows_unreachable_forward_error(tmp_path):
    recorder = Recorder(error=httpx.ConnectError("connection refused"))
    client = _make_client(tmp_path, recorder, [ForwardRule("down", "http://down.test/")])

    client.post("/hooks/generic", content=b"{}")
    html = client.get("/").text

    assert "ConnectError" in html
    assert "forwarded 1, 1 failed" in html


def test_dashboard_omits_forwards_section_without_attempts(tmp_path):
    client = _make_client(tmp_path, Recorder(), [])

    client.post("/hooks/generic", content=b"{}")
    html = client.get("/").text

    assert "Forwards for event" not in html
    assert "forwarded " not in html


def test_forwards_by_event_groups_attempts(tmp_path):
    store = EventStore(str(tmp_path / "test.db"))
    first = store.add("generic", {}, "{}", "no_secret", "")
    second = store.add("generic", {}, "{}", "no_secret", "")
    store.add_forward(first, "a", "http://a.test/", 200, 5)
    store.add_forward(second, "b", "http://b.test/", None, 7, "timeout")
    store.add_forward(first, "c", "http://c.test/", 204, 3)

    grouped = store.forwards_by_event([first, second, 999])

    assert [f["rule"] for f in grouped[first]] == ["a", "c"]
    assert [f["error"] for f in grouped[second]] == ["timeout"]
    assert grouped[999] == []
    assert store.forwards_by_event([]) == {}
