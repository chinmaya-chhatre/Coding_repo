from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from hookscope.errors import DEFAULT_CODES, ApiError, error_body
from hookscope.main import create_app
from hookscope.store import EventStore

ROOT = Path(__file__).parent.parent


@pytest.fixture
def store(tmp_path):
    return EventStore(str(tmp_path / "errors.db"))


@pytest.fixture
def client(store):
    store.add(source="generic", headers={}, body="{}", verification="valid", reason="")
    return TestClient(create_app(store=store, secrets={}))


def assert_standard(response, status, code):
    assert response.status_code == status, response.text
    body = response.json()
    assert list(body) == ["error"], f"only an 'error' key is allowed at the top level, got {list(body)}"
    error = body["error"]
    assert error["code"] == code
    assert isinstance(error["message"], str) and error["message"]
    assert error["request_id"] == response.headers["x-request-id"]
    return error


# Every way the API can refuse a request, with the code a program should switch on.
CASES = [
    ("GET", "/api/events/999", None, 404, "event_not_found"),
    ("GET", "/api/events/999/forwards", None, 404, "event_not_found"),
    ("GET", "/api/events/999/curl", None, 404, "event_not_found"),
    ("GET", "/api/events?since=yesterday", None, 422, "invalid_date"),
    ("GET", "/api/events?limit=lots", None, 422, "validation_error"),
    ("POST", "/hooks/nonsense", b"{}", 404, "unknown_source"),
    ("POST", "/api/events/1/replay", {"target_url": "ftp://nope"}, 422, "invalid_target"),
    ("POST", "/api/events/1/replay", {}, 422, "validation_error"),
    ("POST", "/api/events/999/replay", {"target_url": "http://x.test"}, 404, "event_not_found"),
    ("POST", "/api/events/1/forwards/ghost/resend", None, 404, "rule_not_found"),
    ("POST", "/api/purge", None, 400, "no_retention_policy"),
    ("POST", "/api/purge", {"older_than": "not a date"}, 422, "invalid_purge"),
    ("POST", "/api/events/1/transform-preview", {}, 422, "invalid_transform_request"),
    ("POST", "/api/events/1/transform-preview", {"rule": "ghost"}, 404, "rule_not_found"),
    ("POST", "/api/events/1/transform-preview", {"transform": {"x": "nope"}}, 422, "invalid_transform"),
    ("GET", "/api/no-such-endpoint", None, 404, "not_found"),
    ("DELETE", "/api/events", None, 405, "method_not_allowed"),
]


@pytest.mark.parametrize(("method", "path", "payload", "status", "code"), CASES)
def test_every_refusal_uses_the_standard_body(client, method, path, payload, status, code):
    if isinstance(payload, bytes):
        response = client.request(method, path, content=payload)
    else:
        response = client.request(method, path, json=payload)
    assert_standard(response, status, code)


def test_validation_errors_list_each_invalid_field(client):
    error = assert_standard(client.get("/api/events?limit=lots&before_id=soon"), 422, "validation_error")
    assert {d["field"] for d in error["details"]} == {"query.limit", "query.before_id"}
    assert all({"field", "message", "type"} <= set(d) for d in error["details"])
    assert "query.limit" in error["message"]


def test_a_missing_body_field_is_located(client):
    error = assert_standard(client.post("/api/events/1/replay", json={}), 422, "validation_error")
    assert error["details"][0]["field"] == "body.target_url"


def test_an_oversized_body_is_a_413_with_the_standard_body(tmp_path):
    store = EventStore(str(tmp_path / "big.db"))
    client = TestClient(create_app(store=store, secrets={}, max_body_bytes=10))
    error = assert_standard(client.post("/hooks/generic", content=b"x" * 50), 413, "payload_too_large")
    assert "10 byte" in error["message"]


def test_the_password_wall_uses_it_and_keeps_its_challenge(tmp_path):
    store = EventStore(str(tmp_path / "pw.db"))
    secured = TestClient(create_app(store=store, secrets={}, admin_password="pw"))
    response = secured.get("/api/events", headers={"X-Request-ID": "trace-1"})
    error = assert_standard(response, 401, "authentication_required")
    assert error["request_id"] == "trace-1"
    assert response.headers["www-authenticate"].startswith("Basic")


def test_wrong_method_keeps_the_allow_header(client):
    response = client.delete("/api/events")
    assert_standard(response, 405, "method_not_allowed")
    assert "GET" in response.headers["allow"]


def test_an_unexpected_failure_is_a_500_that_leaks_nothing(store):
    app = create_app(store=store, secrets={})

    @app.get("/boom")
    def boom():
        raise RuntimeError("secret internals: /etc/passwd")

    response = TestClient(app, raise_server_exceptions=False).get("/boom", headers={"X-Request-ID": "t-9"})
    assert response.status_code == 500
    body = response.json()
    assert body["error"]["code"] == "internal_error" and body["error"]["request_id"] == "t-9"
    assert "internals" not in response.text and "passwd" not in response.text


def test_a_route_can_raise_its_own_error_with_details_and_headers(store):
    app = create_app(store=store, secrets={})

    @app.get("/teapot")
    def teapot():
        raise ApiError(
            418,
            "teapot",
            "short and stout",
            details=[{"field": "spout", "message": "tip me"}],
            headers={"X-A": "1"},
        )

    response = TestClient(app).get("/teapot")
    assert response.status_code == 418 and response.headers["x-a"] == "1"
    assert response.json()["error"]["details"] == [{"field": "spout", "message": "tip me"}]


def test_error_body_omits_empty_fields():
    assert error_body("x", "y") == {"error": {"code": "x", "message": "y"}}
    assert error_body("x", "y", "r1", [{"field": "f"}]) == {
        "error": {"code": "x", "message": "y", "request_id": "r1", "details": [{"field": "f"}]}
    }


def test_default_codes_cover_the_statuses_the_api_uses():
    assert {400, 401, 404, 405, 413, 422, 500} <= set(DEFAULT_CODES)
    assert all(code == code.lower() and " " not in code for code in DEFAULT_CODES.values())


# ------------------------------------------------------------------- what is not an error


def test_delivery_results_keep_their_own_shape_on_502(store):
    """A replay to an unreachable target is a delivery result, not an API error: its `error` is text."""
    client = TestClient(create_app(store=store, secrets={}))
    event_id = client.post("/hooks/generic", content=b"{}").json()["id"]
    response = client.post(f"/api/events/{event_id}/replay", json={"target_url": "http://127.0.0.1:1/x"})
    assert response.status_code == 502
    assert isinstance(response.json()["error"], str) and response.json()["status_code"] is None


def test_rejected_webhook_deliveries_keep_the_receipt_body(store):
    """A bad signature is still a stored delivery with a receipt, not an API error."""
    secured = TestClient(create_app(store=store, secrets={"github": "s"}))
    response = secured.post("/hooks/github", content=b"{}", headers={"X-Hub-Signature-256": "sha256=0"})
    assert response.status_code == 401
    assert response.json()["verification"] == "invalid" and "error" not in response.json()


# ------------------------------------------------------------------- consistency of the source


def test_routes_never_raise_the_framework_exception_directly():
    assert "HTTPException" not in (ROOT / "hookscope" / "main.py").read_text()


def test_the_dashboard_reads_the_new_error_shape():
    page = (ROOT / "hookscope" / "templates" / "layout.html").read_text()
    assert "data.detail" not in page and "data.error.message" in page


def test_openapi_documents_the_error_object(client):
    schemas = client.get("/openapi.json").json()["components"]["schemas"]
    assert set(schemas["ErrorOut"]["properties"]) == {"error"}
    assert {"code", "message", "request_id", "details"} == set(schemas["ErrorBody"]["properties"])
    assert {"field", "message", "type"} == set(schemas["ErrorDetail"]["properties"])
