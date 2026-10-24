import re
import sqlite3

import pytest
from fastapi.testclient import TestClient

from hookscope.main import create_app
from hookscope.samples import build_sample
from hookscope.store import UNDIAGNOSED, EventStore

SECRET = "sample-secret"
URL = "https://hooks.example.com/hooks/github"


@pytest.fixture
def store(tmp_path):
    return EventStore(str(tmp_path / "failures.db"))


@pytest.fixture
def client(store):
    secrets = {"github": SECRET, "stripe": SECRET, "generic": SECRET}
    return TestClient(create_app(store=store, secrets=secrets, admin_password=None))


def failures(text: str) -> dict[tuple[str, str], int]:
    pattern = r'^hookscope_signature_failures_total\{source="([^"]*)",cause="([^"]*)"\} (\d+)$'
    return {(m[1], m[2]): int(m[3]) for m in re.finditer(pattern, text, re.M)}


def test_the_family_is_declared_with_help_and_type(client):
    text = client.get("/metrics").text
    assert "# TYPE hookscope_signature_failures_total counter" in text
    assert "# HELP hookscope_signature_failures_total" in text
    assert failures(text) == {}  # nothing has failed yet, so no series yet


def test_failures_are_counted_by_source_and_cause(client):
    for _ in range(3):
        client.post("/hooks/github", content=b"{}")  # no signature
    client.post("/hooks/github", content=b"{}", headers={"X-Hub-Signature-256": "sha256=" + "0" * 64})
    client.post("/hooks/stripe", content=b"{}")
    assert failures(client.get("/metrics").text) == {
        ("github", "missing_signature"): 3,
        ("github", "unexplained"): 1,
        ("stripe", "missing_signature"): 1,
    }


def test_the_cause_comes_from_the_diagnosis(client):
    sample = build_sample("github", SECRET, url=URL)
    client.post("/hooks/stripe", content=sample.body, headers=sample.headers)  # GitHub's, wrong endpoint
    assert failures(client.get("/metrics").text) == {("stripe", "wrong_provider"): 1}


def test_good_deliveries_and_missing_secrets_are_not_failures(client):
    sample = build_sample("github", SECRET, url=URL)
    client.post("/hooks/github", content=sample.body, headers=sample.headers)  # valid
    client.post("/hooks/shopify", content=b"{}")  # no secret configured
    assert failures(client.get("/metrics").text) == {}


def test_events_from_before_diagnoses_count_as_undiagnosed(client, store):
    store.add("github", {}, "{}", "invalid", "signature mismatch")
    store.add("github", {}, "{}", "unsigned", "missing header")
    assert failures(client.get("/metrics").text) == {("github", UNDIAGNOSED): 2}


def test_an_unreadable_stored_diagnosis_counts_as_undiagnosed(client, store):
    event_id = store.add("github", {}, "{}", "invalid", "x")
    with sqlite3.connect(store.path) as conn:
        conn.execute("UPDATE events SET diagnosis = 'not json' WHERE id = ?", (event_id,))
    assert failures(client.get("/metrics").text) == {("github", UNDIAGNOSED): 1}


def test_the_causes_add_up_to_the_rejected_deliveries(client):
    client.post("/hooks/github", content=b"{}")
    client.post("/hooks/stripe", content=b"{}")
    client.post("/hooks/generic", content=b"{}", headers={"X-Signature": "00" * 32})
    text = client.get("/metrics").text
    pattern = r'^hookscope_deliveries_total\{source="[^"]*",verification="(?:invalid|unsigned)"\} (\d+)$'
    rejected = sum(int(m[1]) for m in re.finditer(pattern, text, re.M))
    assert rejected == 3 == sum(failures(text).values())


def test_a_cause_with_odd_characters_is_escaped(client, store):
    store.add("github", {}, "{}", "invalid", "x", diagnosis={"cause": 'a"b\nc', "message": "m", "fix": "f"})
    assert 'cause="a\\"b\\nc"' in client.get("/metrics").text


def test_the_counts_fall_when_events_are_purged(client):
    client.post("/hooks/github", content=b"{}")
    client.post("/hooks/github", content=b"{}")
    assert failures(client.get("/metrics").text) == {("github", "missing_signature"): 2}
    client.post("/api/purge", json={"keep_last": 1})
    assert failures(client.get("/metrics").text) == {("github", "missing_signature"): 1}
