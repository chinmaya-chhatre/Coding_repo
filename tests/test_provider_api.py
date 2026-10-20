import json
import logging

import httpx
import pytest
from fastapi.testclient import TestClient

from hookscope.main import create_app
from hookscope.providers import PROVIDERS
from hookscope.rules import ForwardRule
from hookscope.schemas import ProviderOut
from hookscope.store import EventStore


@pytest.fixture
def client(tmp_path):
    app = create_app(
        store=EventStore(str(tmp_path / "p.db")), secrets={"github": "s3cret"}, admin_password=None
    )
    return TestClient(app)


def test_lists_every_provider_in_the_documented_shape(client):
    response = client.get("/api/providers")
    assert response.status_code == 200
    providers = response.json()
    assert [p["name"] for p in providers] == list(PROVIDERS)
    for provider in providers:
        assert ProviderOut.model_validate(provider).model_dump() == provider


def test_says_which_secrets_are_configured_and_where_to_set_the_others(client):
    by_name = {p["name"]: p for p in client.get("/api/providers").json()}
    assert by_name["github"]["secret_configured"] is True
    assert by_name["stripe"]["secret_configured"] is False
    assert by_name["stripe"]["secret_env"] == "HOOKSCOPE_SECRET_STRIPE"
    assert by_name["stripe"]["path"] == "/hooks/stripe"


def test_describes_how_each_provider_is_handled(client):
    by_name = {p["name"]: p for p in client.get("/api/providers").json()}
    assert by_name["twilio"]["url_signed"] is True and by_name["github"]["url_signed"] is False
    assert by_name["stripe"]["timestamp_header"] == "Stripe-Signature"
    assert by_name["github"]["event_type_from"] == "header x-github-event"
    assert by_name["github"]["delivery_id_from"] == "header x-github-delivery"
    assert by_name["generic"]["delivery_id_from"] is None


def test_never_reveals_a_secret_value(client):
    assert "s3cret" not in client.get("/api/providers").text


def test_is_in_the_openapi_document(client):
    paths = client.get("/openapi.json").json()["paths"]
    assert paths["/api/providers"]["get"]["summary"] == "List supported providers"


def test_the_delivery_id_reaches_the_log(client, caplog):
    with caplog.at_level(logging.INFO, logger="hookscope"):
        client.post(
            "/hooks/github", content=b"{}", headers={"X-GitHub-Delivery": "guid-1", "X-GitHub-Event": "ping"}
        )
        client.post("/hooks/stripe", content=json.dumps({"id": "evt_9"}).encode())
    received = {r.source: r for r in caplog.records if r.getMessage() == "event received"}
    assert received["github"].delivery_id == "guid-1"
    assert received["stripe"].delivery_id == "evt_9"


# ------------------------------------------------------------------------------ send a test


SECRETS = {name: "sample-secret" for name in PROVIDERS} | {"svix": "whsec_ZGV2LXNlY3JldC1kZXYtc2VjcmV0"}


@pytest.fixture
def lab(tmp_path):
    seen: list[httpx.Request] = []

    def target(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, text="ok")

    app = create_app(
        store=EventStore(str(tmp_path / "lab.db")),
        secrets=SECRETS,
        rules=[ForwardRule("everything", "http://sink.test/", source="stripe")],
        http_client=httpx.Client(transport=httpx.MockTransport(target)),
        admin_password=None,
    )
    client = TestClient(app)
    client.seen = seen
    return client


@pytest.mark.parametrize("name", sorted(PROVIDERS))
def test_a_test_event_is_verified_stored_and_valid(lab, name):
    response = lab.post(f"/api/providers/{name}/test")
    assert response.status_code == 202, response.text
    assert response.json()["verification"] == "valid"
    event = lab.get(f"/api/events/{response.json()['id']}").json()
    assert event["source"] == name and event["verification"] == "valid"


def test_a_test_event_follows_the_forwarding_rules(lab):
    response = lab.post("/api/providers/stripe/test")
    assert response.json()["forwarded_to"] == ["everything"]
    assert len(lab.seen) == 1
    assert lab.post("/api/providers/github/test").json()["forwarded_to"] == []


def test_the_response_does_not_contain_the_signature_or_secret(lab):
    text = lab.post("/api/providers/github/test").text
    assert "sha256=" not in text and "sample-secret" not in text


def test_the_stored_event_keeps_lower_case_headers_like_a_real_one(lab):
    event_id = lab.post("/api/providers/github/test").json()["id"]
    headers = lab.get(f"/api/events/{event_id}").json()["headers"]
    assert "x-github-event" in headers and "X-GitHub-Event" not in headers


def test_a_test_needs_a_configured_secret(client):
    response = client.post("/api/providers/stripe/test")
    assert response.status_code == 409
    error = response.json()["error"]
    assert error["code"] == "secret_not_configured" and "HOOKSCOPE_SECRET_STRIPE" in error["message"]
    assert client.get("/api/events").json() == []  # nothing was stored


def test_an_unusable_svix_secret_is_explained(tmp_path):
    app = create_app(
        store=EventStore(str(tmp_path / "s.db")), secrets={"svix": "dev-secret"}, admin_password=None
    )
    response = TestClient(app).post("/api/providers/svix/test")
    assert response.status_code == 409 and response.json()["error"]["code"] == "sample_unavailable"
    assert "whsec_" in response.json()["error"]["message"]


def test_an_unknown_provider_is_a_404(client):
    response = client.post("/api/providers/nope/test")
    assert response.status_code == 404 and response.json()["error"]["code"] == "unknown_source"


def test_the_endpoint_is_documented(client):
    operation = client.get("/openapi.json").json()["paths"]["/api/providers/{name}/test"]["post"]
    assert operation["summary"] == "Send a signed test event"
    assert {"202", "404", "409"} <= set(operation["responses"])
