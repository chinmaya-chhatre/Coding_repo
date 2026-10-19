import json
import logging

import pytest
from fastapi.testclient import TestClient

from hookscope.main import create_app
from hookscope.providers import PROVIDERS
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
