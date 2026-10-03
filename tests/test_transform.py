import json

import httpx
import pytest
from fastapi.testclient import TestClient

from hookscope.main import create_app
from hookscope.rules import FORWARD_HEADER, ForwardRule, parse_rules
from hookscope.store import EventStore
from hookscope.transform import (
    DESCENT,
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
        ("$..id", (DESCENT, "id")),
        ("$.commits..message", ("commits", DESCENT, "message")),
        ("$..*", (DESCENT, WILDCARD)),
        ("$..[0]", (DESCENT, 0)),
        ("$..['weird key']", (DESCENT, "weird key")),
        ("$..[*]", (DESCENT, WILDCARD)),
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
        ("$..", "expected a key name at position 3"),
        ("$...id", "expected a key name"),
        ("$..[?(@.id)]", "unsupported selector"),
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
        ("$..id", ["c1", "c2"]),
        ("$..message", ["first", "second"]),
        ("$.commits..id", ["c1", "c2"]),
        ("$..x", [1]),
        ("$..[0]", ["a", {"id": "c1", "message": "first"}]),
        ("$..nope", []),
        ("$.sender..login", ["octocat"]),
    ],
)
def test_resolve(expr, expected):
    assert resolve(PAYLOAD, compile_path(expr)) == expected


def test_recursive_descent_matches_at_every_depth_in_document_order():
    payload = {"id": 1, "child": {"id": 2, "items": [{"id": 3}, {"other": {"id": 4}}]}, "id2": {"id": 5}}
    assert resolve(payload, compile_path("$..id")) == [1, 2, 3, 4, 5]


def test_recursive_descent_wildcard_returns_every_nested_value_once():
    payload = {"a": {"b": [1, 2]}, "c": 3}
    # Children of each node, visiting outer nodes before inner ones (the root itself is excluded).
    assert resolve(payload, compile_path("$..*")) == [{"b": [1, 2]}, 3, [1, 2], 1, 2]


def test_recursive_descent_on_scalar_or_non_json_body():
    assert resolve("text", compile_path("$..id")) == []
    assert resolve(None, compile_path("$..*")) == []


def test_recursive_descent_handles_deeply_nested_payloads():
    payload: dict = {"id": "leaf"}
    for _ in range(3000):
        payload = {"wrap": payload}
    assert resolve(payload, compile_path("$..id")) == ["leaf"]


def test_resolve_root_returns_whole_payload():
    assert resolve(PAYLOAD, compile_path("$")) is PAYLOAD


def test_apply_transform_builds_nested_document_with_metadata():
    mapping = {
        "repo": "$.repository.full_name",
        "author": "$.sender.login",
        "commit_ids": "$.commits[*].id",
        "all_ids": "$..id",
        "missing": "$.nope",
        "meta": {"source": "@source", "type": "@event_type", "id": "@event_id", "status": "@verification"},
    }

    result = apply_transform(mapping, _event(json.dumps(PAYLOAD)), "push")

    assert result == {
        "repo": "octo/hello",
        "author": "octocat",
        "commit_ids": ["c1", "c2"],
        "all_ids": ["c1", "c2"],
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
        ({"k": "$.a.."}, "expected a key name"),
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


def _rule_transforms(html: str) -> dict:
    start = html.index('<script type="application/json" id="transform-rules">')
    start = html.index(">", start) + 1
    return json.loads(html[start : html.index("</script>", start)])


def test_dashboard_has_transform_preview_form_per_event(preview_client):
    first = _stored(preview_client, {"type": "x"})
    second = _stored(preview_client, {"type": "y"})
    html = preview_client.get("/").text
    assert html.count('<form class="preview"') == 2
    assert f'<form class="preview" data-event-id="{first}"' in html
    assert f'<form class="preview" data-event-id="{second}"' in html
    assert "/transform-preview" in html


def test_dashboard_offers_only_rules_with_a_transform(preview_client):
    _stored(preview_client, {"type": "x"})
    html = preview_client.get("/").text
    assert '<option value="orders">Rule: orders</option>' in html
    assert 'value="plain"' not in html
    orders = {"order": "$.data.id", "kind": "@event_type", "id": "@event_id"}
    assert _rule_transforms(html) == {"orders": orders}
    # Rule order is kept so an edited copy of the mapping builds the same document.
    assert list(_rule_transforms(html)["orders"]) == ["order", "kind", "id"]


def test_dashboard_preview_without_transform_rules_offers_custom_mapping_only(tmp_path):
    client = TestClient(create_app(store=EventStore(str(tmp_path / "t.db")), secrets={}, rules=[]))
    _stored(client, {"type": "x"})
    html = client.get("/").text
    assert '<option value="">Custom mapping</option>' in html
    assert "Rule: " not in html
    assert _rule_transforms(html) == {}


def test_dashboard_escapes_rule_transforms_embedded_in_script(tmp_path):
    rules = [ForwardRule("evil</script>", "http://x.test/", transform={"</script><b>": "$.a"})]
    client = TestClient(create_app(store=EventStore(str(tmp_path / "t.db")), secrets={}, rules=rules))
    _stored(client, {"a": 1})
    html = client.get("/").text
    assert "</script><b>" not in html
    assert _rule_transforms(html) == {"evil</script>": {"</script><b>": "$.a"}}
    assert '<option value="evil&lt;/script&gt;">' in html
