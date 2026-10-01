import json

import httpx
import pytest
from fastapi.testclient import TestClient

from hookscope.main import create_app
from hookscope.rules import FORWARD_HEADER, ForwardRule, parse_rules
from hookscope.store import EventStore
from hookscope.transform import (
    WILDCARD,
    InvalidTransformError,
    apply_transform,
    compile_path,
    resolve,
    validate_mapping,
)
from tests.test_replay import Recorder

PAYLOAD = {
    "repository": {"full_name": "octo/hello", "topics": ["a", "b"]},
    "sender": {"login": "octocat"},
    "commits": [{"id": "c1", "message": "first"}, {"id": "c2", "message": "second"}],
    "weird key": {"x": 1},
}


def _event(body: str, source: str = "github") -> dict:
    return {
        "id": 7,
        "source": source,
        "headers": {},
        "body": body,
        "verification": "valid",
        "received_at": "2026-09-30T12:00:00+00:00",
    }


@pytest.mark.parametrize(
    ("expr", "segments"),
    [
        ("$", ()),
        ("$.repository.full_name", ("repository", "full_name")),
        ("$.commits[0].id", ("commits", 0, "id")),
        ("$.commits[-1]", ("commits", -1)),
        ("$['weird key'].x", ("weird key", "x")),
        ('$["a.b"]', ("a.b",)),
        ("$.commits[*].id", ("commits", WILDCARD, "id")),
        ("$.repository.*", ("repository", WILDCARD)),
    ],
)
def test_compile_path(expr, segments):
    assert compile_path(expr) == segments


@pytest.mark.parametrize(
    ("expr", "message"),
    [
        ("repository", "must start with"),
        ("$.", "expected a key name"),
        ("$.commits[0", "unclosed"),
        ("$.commits[?(@.id)]", "unsupported selector"),
        ("$..id", "expected a key name"),
        ("$repo", "unexpected 'r'"),
    ],
)
def test_compile_path_rejects_bad_expressions(expr, message):
    with pytest.raises(InvalidTransformError, match=message):
        compile_path(expr)


@pytest.mark.parametrize(
    ("expr", "expected"),
    [
        ("$.repository.full_name", "octo/hello"),
        ("$.commits[1].message", "second"),
        ("$.commits[-1].id", "c2"),
        ("$['weird key'].x", 1),
        ("$.commits[*].id", ["c1", "c2"]),
        ("$.repository.topics[*]", ["a", "b"]),
        ("$.sender.*", ["octocat"]),
        ("$.missing.deeper", None),
        ("$.commits[5]", None),
        ("$.sender.login[0]", None),
        ("$.missing[*]", []),
    ],
)
def test_resolve(expr, expected):
    assert resolve(PAYLOAD, compile_path(expr)) == expected


def test_resolve_root_returns_whole_payload():
    assert resolve(PAYLOAD, compile_path("$")) is PAYLOAD


def test_apply_transform_builds_nested_document_with_metadata():
    mapping = {
        "repo": "$.repository.full_name",
        "author": "$.sender.login",
        "commit_ids": "$.commits[*].id",
        "missing": "$.nope",
        "meta": {"source": "@source", "type": "@event_type", "id": "@event_id", "status": "@verification"},
    }

    result = apply_transform(mapping, _event(json.dumps(PAYLOAD)), "push")

    assert result == {
        "repo": "octo/hello",
        "author": "octocat",
        "commit_ids": ["c1", "c2"],
        "missing": None,
        "meta": {"source": "github", "type": "push", "id": 7, "status": "valid"},
    }


def test_apply_transform_on_non_json_body_yields_nulls_but_keeps_metadata():
    result = apply_transform({"repo": "$.repository", "at": "@received_at"}, _event("not json"), None)
    assert result == {"repo": None, "at": "2026-09-30T12:00:00+00:00"}


@pytest.mark.parametrize(
    ("mapping", "message"),
    [
        ([], "non-empty object"),
        ({}, "non-empty object"),
        ({"k": 5}, "path string or an object"),
        ({"k": "$.a[x]"}, "unsupported selector"),
        ({"k": {"inner": {}}}, "non-empty object"),
        ({"a": {"b": {"c": {"d": {"e": {"f": "$"}}}}}}, "nested more than"),
    ],
)
def test_validate_mapping_rejects_bad_transforms(mapping, message):
    with pytest.raises(InvalidTransformError, match=message):
        validate_mapping(mapping)


def test_parse_rules_keeps_transform():
    [rule] = parse_rules([{"name": "t", "target_url": "http://t.test/", "transform": {"id": "$.id"}}])
    assert rule.transform == {"id": "$.id"}
    assert rule.to_dict()["transform"] == {"id": "$.id"}


def test_transformed_event_is_forwarded_without_provider_headers(tmp_path):
    recorder = Recorder(status_code=200)
    rule = ForwardRule(
        "internal", "http://internal.test/", source="generic",
        transform={"order": "$.data.id", "kind": "@event_type"},
    )  # fmt: skip
    store = EventStore(str(tmp_path / "test.db"))
    http_client = httpx.Client(transport=httpx.MockTransport(recorder))
    client = TestClient(create_app(store=store, secrets={}, http_client=http_client, rules=[rule]))

    body = json.dumps({"type": "order.created", "data": {"id": "o_1"}})
    resp = client.post("/hooks/generic", content=body, headers={"X-Signature": "abc", "X-Custom": "1"})

    assert resp.json()["forwarded_to"] == ["internal"]
    [sent] = recorder.requests
    assert json.loads(sent.content) == {"order": "o_1", "kind": "order.created"}
    assert sent.headers["content-type"] == "application/json"
    assert sent.headers[FORWARD_HEADER] == "internal"
    assert "x-signature" not in sent.headers
    assert "x-custom" not in sent.headers


@pytest.fixture
def preview_client(tmp_path):
    rules = [
        ForwardRule("orders", "http://orders.test/", source="generic", event_types=("order.created",),
                    transform={"order": "$.data.id", "kind": "@event_type", "id": "@event_id"}),
        ForwardRule("plain", "http://plain.test/"),
    ]  # fmt: skip
    store = EventStore(str(tmp_path / "test.db"))
    return TestClient(create_app(store=store, secrets={}, rules=rules))


def _stored(client, body: dict) -> int:
    return client.post("/hooks/generic", content=json.dumps(body)).json()["id"]


def test_preview_rule_transform_against_stored_event(preview_client):
    event_id = _stored(preview_client, {"type": "order.created", "data": {"id": "o_1"}})
    resp = preview_client.post(f"/api/events/{event_id}/transform-preview", json={"rule": "orders"})
    assert resp.status_code == 200
    assert resp.json() == {
        "event_id": event_id,
        "event_type": "order.created",
        "rule": "orders",
        "matches": True,
        "output": {"order": "o_1", "kind": "order.created", "id": event_id},
    }


def test_preview_reports_when_rule_would_not_forward_event(preview_client):
    event_id = _stored(preview_client, {"type": "order.cancelled", "data": {"id": "o_2"}})
    body = preview_client.post(f"/api/events/{event_id}/transform-preview", json={"rule": "orders"}).json()
    assert body["matches"] is False
    assert body["output"]["order"] == "o_2"


def test_preview_ad_hoc_transform(preview_client):
    event_id = _stored(preview_client, {"type": "x", "items": [{"sku": "a"}, {"sku": "b"}]})
    resp = preview_client.post(
        f"/api/events/{event_id}/transform-preview",
        json={"transform": {"skus": "$.items[*].sku", "meta": {"src": "@source"}}},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["rule"] is None and body["matches"] is None
    assert body["output"] == {"skus": ["a", "b"], "meta": {"src": "generic"}}


@pytest.mark.parametrize(
    "payload, status, message",
    [
        ({}, 422, "exactly one"),
        ({"rule": "orders", "transform": {"a": "$.a"}}, 422, "exactly one"),
        ({"rule": "missing"}, 404, "unknown rule 'missing'"),
        ({"rule": "plain"}, 422, "has no transform"),
        ({"transform": {"a": "a.b"}}, 422, "must start with '$'"),
        ({"transform": {"a": "@nope"}}, 422, "unknown reference"),
        ({"transform": {}}, 422, "non-empty"),
    ],
)
def test_preview_rejects_bad_requests(preview_client, payload, status, message):
    event_id = _stored(preview_client, {"type": "x"})
    resp = preview_client.post(f"/api/events/{event_id}/transform-preview", json=payload)
    assert resp.status_code == status
    assert message in resp.json()["detail"]


def test_preview_unknown_event(preview_client):
    resp = preview_client.post("/api/events/999/transform-preview", json={"rule": "orders"})
    assert resp.status_code == 404
