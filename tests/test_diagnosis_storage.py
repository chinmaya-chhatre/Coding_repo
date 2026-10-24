import json
import logging
import sqlite3

import pytest
from fastapi.testclient import TestClient

from hookscope.main import create_app
from hookscope.samples import build_sample
from hookscope.schemas import EventOut, ReceiveOut
from hookscope.store import EventStore

SECRET = "sample-secret"
DIAGNOSIS = {"cause": "c", "message": "m", "fix": "f"}


@pytest.fixture
def store(tmp_path):
    return EventStore(str(tmp_path / "d.db"))


@pytest.fixture
def client(store):
    secrets = {"github": SECRET, "stripe": SECRET}
    return TestClient(create_app(store=store, secrets=secrets, admin_password=None))


def post(client, source="github", body=b"{}", headers=None):
    return client.post(f"/hooks/{source}", content=body, headers=headers or {})


# ------------------------------------------------------------------------------ the store


def test_a_diagnosis_is_stored_and_read_back(store):
    event_id = store.add("github", {}, "{}", "invalid", "signature mismatch", diagnosis=DIAGNOSIS)
    assert store.get(event_id)["diagnosis"] == DIAGNOSIS
    assert store.list(limit=10)[0]["diagnosis"] == DIAGNOSIS


def test_an_event_without_one_reads_back_as_none(store):
    event_id = store.add("github", {}, "{}", "valid", "")
    assert store.get(event_id)["diagnosis"] is None


@pytest.mark.parametrize("raw", ["not json", "[1, 2]", "", "123"])
def test_an_unreadable_stored_diagnosis_is_treated_as_none(store, raw):
    event_id = store.add("github", {}, "{}", "invalid", "x")
    with sqlite3.connect(store.path) as conn:
        conn.execute("UPDATE events SET diagnosis = ? WHERE id = ?", (raw, event_id))
    assert store.get(event_id)["diagnosis"] is None


def test_a_database_from_before_diagnoses_is_migrated(tmp_path):
    path = str(tmp_path / "old.db")
    with sqlite3.connect(path) as conn:
        conn.execute(
            "CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, source TEXT NOT NULL,"
            " received_at TEXT NOT NULL, headers TEXT NOT NULL, body TEXT NOT NULL,"
            " verification TEXT NOT NULL, reason TEXT NOT NULL DEFAULT '', body_base64 TEXT, request_id TEXT)"
        )
        conn.execute(
            "INSERT INTO events (source, received_at, headers, body, verification, reason)"
            " VALUES ('github', 'then', '{}', '{}', 'invalid', 'old row')"
        )
    store = EventStore(path)
    assert store.get(1)["diagnosis"] is None  # the old row is still there, with nothing explained
    new_id = store.add("github", {}, "{}", "invalid", "new", diagnosis=DIAGNOSIS)
    assert store.get(new_id)["diagnosis"] == DIAGNOSIS and store.count() == 2


# ------------------------------------------------------------------------------ the pipeline


def test_a_rejected_delivery_is_diagnosed_and_the_answer_says_why(client):
    response = post(client, headers={"X-Hub-Signature-256": "sha256=" + "0" * 64})
    assert response.status_code == 401
    answer = response.json()
    assert answer["diagnosis"]["cause"] == "unexplained"
    assert "HOOKSCOPE_SECRET_GITHUB" in answer["diagnosis"]["fix"]
    ReceiveOut.model_validate(answer)


def test_the_diagnosis_is_on_the_stored_event(client):
    event_id = post(client).json()["id"]  # no signature at all
    event = client.get(f"/api/events/{event_id}").json()
    assert event["diagnosis"]["cause"] == "missing_signature"
    assert "X-Hub-Signature-256" in event["diagnosis"]["message"]
    assert EventOut.model_validate(event).model_dump() == event


def test_a_request_to_the_wrong_endpoint_is_named_as_such(client):
    sample = build_sample("github", SECRET, url="https://h.example/hooks/github")
    answer = client.post("/hooks/stripe", content=sample.body, headers=sample.headers).json()
    assert answer["diagnosis"]["cause"] == "wrong_provider"
    assert "came from github" in answer["diagnosis"]["message"]


def test_a_valid_delivery_has_no_diagnosis_anywhere(client):
    sample = build_sample("github", SECRET, url="https://h.example/hooks/github")
    answer = client.post("/hooks/github", content=sample.body, headers=sample.headers).json()
    assert answer["verification"] == "valid" and answer["diagnosis"] is None
    assert client.get(f"/api/events/{answer['id']}").json()["diagnosis"] is None


def test_a_source_with_no_secret_is_not_diagnosed(client):
    answer = post(client, source="shopify").json()  # no secret configured: not the sender's fault
    assert answer["verification"] == "no_secret" and answer["diagnosis"] is None


def test_the_event_list_carries_diagnoses_too(client):
    post(client)
    assert [e["diagnosis"]["cause"] for e in client.get("/api/events").json()] == ["missing_signature"]


def test_the_send_a_test_endpoint_is_never_diagnosed(client):
    answer = client.post("/api/providers/github/test").json()
    assert answer["verification"] == "valid" and answer["diagnosis"] is None


def test_the_log_line_names_the_cause(client, caplog):
    with caplog.at_level(logging.WARNING, logger="hookscope"):
        post(client)
    record = next(r for r in caplog.records if r.getMessage() == "event received")
    assert record.cause == "missing_signature"


def test_a_diagnosis_never_contains_the_secret(client, store):
    post(client, headers={"X-Hub-Signature-256": "sha256=" + "0" * 64})
    assert SECRET not in json.dumps(store.list(limit=10))


def test_a_broken_detector_does_not_stop_the_event_being_stored(client, store, monkeypatch):
    from hookscope import diagnostics

    def broken(delivery):
        raise RuntimeError("boom")

    monkeypatch.setattr(diagnostics, "DETECTORS", [broken])
    response = post(client)
    assert response.status_code == 401 and response.json()["diagnosis"] is None
    assert store.count() == 1


def test_the_openapi_document_describes_the_diagnosis(client):
    schemas = client.get("/openapi.json").json()["components"]["schemas"]
    assert set(schemas["DiagnosisOut"]["properties"]) == {"cause", "message", "fix"}
    for model in ("EventOut", "ReceiveOut"):
        assert "diagnosis" in schemas[model]["properties"]
