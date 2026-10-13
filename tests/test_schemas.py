from typing import get_args

import httpx
import pytest
from fastapi.testclient import TestClient

from hookscope import metrics
from hookscope.main import create_app
from hookscope.rules import ForwardRule
from hookscope.schemas import (
    DeadLetterOut,
    EventOut,
    ForwardOut,
    HealthOut,
    PurgeOut,
    ReceiveOut,
    ReplayOut,
    ResendOut,
    RuleOut,
    TransformPreviewOut,
    Verification,
)
from hookscope.store import EventStore


def _transport(request: httpx.Request) -> httpx.Response:
    if request.url.host == "down.test":
        raise httpx.ConnectError("refused")
    return httpx.Response(500 if request.url.host == "bad.test" else 200, text="ok")


@pytest.fixture
def client(tmp_path):
    rules = [
        ForwardRule("good", "http://ok.test/", source="generic"),
        ForwardRule("bad", "http://bad.test/", source="generic"),
        ForwardRule("tx", "http://ok.test/tx", source="generic", transform={"kind": "@event_type"}),
    ]
    app = create_app(
        store=EventStore(str(tmp_path / "schemas.db")),
        secrets={"github": "s3cret"},
        rules=rules,
        http_client=httpx.Client(transport=httpx.MockTransport(_transport)),
        admin_password=None,
    )
    test_client = TestClient(app)
    test_client.post("/hooks/generic", content=b'{"type": "x"}')
    test_client.post("/hooks/github", content=b"{}", headers={"X-Hub-Signature-256": "sha256=bad"})
    test_client.post("/hooks/generic", content=b"caf\xe9")
    return test_client


def _round_trips(model, payload: dict) -> None:
    """The model describes every field of the payload, and nothing the payload lacks."""
    assert model.model_validate(payload).model_dump() == payload


def test_event_endpoints_match_their_models(client):
    events = client.get("/api/events").json()
    assert len(events) == 3
    for event in events:
        _round_trips(EventOut, event)
    _round_trips(EventOut, client.get("/api/events/1").json())
    # The non-UTF-8 body carries its exact bytes; the others have null there.
    assert {e["body_base64"] is None for e in events} == {True, False}


def test_forward_dead_letter_and_rule_endpoints_match_their_models(client):
    forwards = client.get("/api/events/1/forwards").json()
    assert {f["rule"] for f in forwards} == {"good", "bad", "tx"}
    for forward in forwards:
        _round_trips(ForwardOut, forward)
    dead = client.get("/api/dead-letters").json()
    # Two generic events each failed for good against the "bad" rule's target.
    assert {d["rule"] for d in dead} == {"bad"} and {d["event_id"] for d in dead} == {1, 3}
    for letter in dead:
        _round_trips(DeadLetterOut, letter)
    rules = client.get("/api/rules").json()
    assert len(rules) == 3
    for rule in rules:
        _round_trips(RuleOut, rule)


def test_responses_built_by_hand_match_their_models(client):
    # These routes return JSONResponse directly, so FastAPI cannot filter them through a model;
    # this is what keeps the documented schema honest.
    received = client.post("/hooks/generic", content=b"{}").json()
    _round_trips(ReceiveOut, received)
    rejected = client.post("/hooks/github", content=b"{}", headers={"X-Hub-Signature-256": "sha256=bad"})
    assert rejected.status_code == 401
    _round_trips(ReceiveOut, rejected.json())
    for target in ("http://ok.test/", "http://bad.test/", "http://down.test/"):
        replay = client.post("/api/events/1/replay", json={"target_url": target})
        assert replay.status_code in (200, 502)
        _round_trips(ReplayOut, replay.json())
    for rule in ("good", "bad"):
        _round_trips(ResendOut, client.post(f"/api/events/1/forwards/{rule}/resend").json())
    _round_trips(HealthOut, client.get("/healthz").json())


def test_preview_and_purge_match_their_models(client):
    preview = client.post("/api/events/1/transform-preview", json={"rule": "tx"}).json()
    _round_trips(TransformPreviewOut, preview)
    _round_trips(TransformPreviewOut, client.post(
        "/api/events/1/transform-preview", json={"transform": {"x": "$.type"}}
    ).json())
    _round_trips(PurgeOut, client.post("/api/purge", json={"keep_last": 1}).json())


def test_openapi_describes_every_json_operation(client):
    spec = client.get("/openapi.json").json()
    json_paths = [p for p in spec["paths"] if p.startswith(("/api/", "/hooks/")) or p == "/healthz"]
    assert len(json_paths) >= 10
    for path in json_paths:
        for method, operation in spec["paths"][path].items():
            successes = {c: r for c, r in operation["responses"].items() if c.startswith("2")}
            assert successes, f"{method.upper()} {path} documents no 2xx response"
            for code, response in successes.items():
                schema = response.get("content", {}).get("application/json", {}).get("schema")
                assert schema, f"{method.upper()} {path} {code} has no JSON schema"


def test_openapi_documents_error_bodies(client):
    paths = client.get("/openapi.json").json()["paths"]

    def ref(path, method, code):
        return paths[path][method]["responses"][code]["content"]["application/json"]["schema"]["$ref"]

    assert ref("/api/events/{event_id}", "get", "404").endswith("/ErrorOut")
    assert ref("/api/events/{event_id}/replay", "post", "422").endswith("/ErrorOut")
    assert ref("/api/purge", "post", "400").endswith("/ErrorOut")
    assert ref("/hooks/{source}", "post", "413").endswith("/ErrorOut")
    # A rejected delivery is a 401 with the normal receipt, not an error body.
    assert ref("/hooks/{source}", "post", "401").endswith("/ReceiveOut")


def test_verification_values_are_defined_once():
    expected = {"valid", "invalid", "unsigned", "no_secret"}
    assert set(get_args(Verification)) == expected
    assert set(metrics.VERIFICATION_STATUSES) == expected


def test_event_schema_marks_the_verification_enum_and_nullable_bytes(client):
    schema = client.get("/openapi.json").json()["components"]["schemas"]["EventOut"]
    assert schema["properties"]["verification"]["enum"] == list(get_args(Verification))
    assert set(schema["required"]) >= {"id", "source", "body", "body_base64", "verification"}


def test_openapi_has_title_description_and_tag_descriptions(client):
    spec = client.get("/openapi.json").json()
    assert spec["info"]["title"] == "HookScope"
    assert "HOOKSCOPE_ADMIN_PASSWORD" in spec["info"]["description"]
    described = {tag["name"] for tag in spec["tags"] if tag.get("description")}
    assert {"webhooks", "events", "forwarding", "system", "dashboard"} <= described


def test_every_operation_has_a_tag_and_summary(client):
    spec = client.get("/openapi.json").json()
    declared = {tag["name"] for tag in spec["tags"]}
    for path, methods in spec["paths"].items():
        for method, operation in methods.items():
            where = f"{method.upper()} {path}"
            assert operation.get("summary"), f"{where} has no summary"
            tags = set(operation.get("tags", []))
            assert tags and tags <= declared, f"{where} has no declared tag"


def test_request_bodies_carry_examples(client):
    schemas = client.get("/openapi.json").json()["components"]["schemas"]
    for model, field in [
        ("ReplayRequest", "target_url"),
        ("PurgeRequest", "older_than"),
        ("TransformPreviewRequest", "transform"),
    ]:
        assert schemas[model]["properties"][field]["examples"], f"{model}.{field} has no example"
