import sqlite3
import time

import pytest
from fastapi.testclient import TestClient

from hookscope import __version__
from hookscope.auth import is_public
from hookscope.main import create_app
from hookscope.schemas import ReadyOut
from hookscope.store import EventStore


@pytest.fixture
def store(tmp_path):
    return EventStore(str(tmp_path / "ready.db"))


@pytest.fixture
def client(store):
    return TestClient(create_app(store=store, secrets={}))


def test_ready_when_the_database_accepts_writes(client):
    response = client.get("/readyz")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ready" and body["version"] == __version__
    assert body["checks"]["database"]["ok"] is True
    assert body["checks"]["database"]["latency_ms"] >= 0
    assert "error" not in body["checks"]["database"]
    ReadyOut.model_validate(body)


def test_probing_adds_no_rows_and_leaves_no_lock(client, store):
    for _ in range(20):
        assert client.get("/readyz").status_code == 200
    assert store.count() == 0
    assert client.post("/hooks/generic", content=b"{}").status_code == 202  # writes still work afterwards


def test_not_ready_when_the_database_is_locked_by_a_stuck_writer(store):
    app = create_app(store=store, secrets={})
    store_check = store.check_writable
    store.check_writable = lambda timeout=1.0: store_check(timeout=0.2)  # keep the test quick
    blocker = sqlite3.connect(store.path, isolation_level=None)
    blocker.execute("BEGIN IMMEDIATE")  # holds the write lock, like a hung writer would
    try:
        started = time.monotonic()
        response = TestClient(app).get("/readyz")
        assert time.monotonic() - started < 3
    finally:
        blocker.execute("ROLLBACK")
        blocker.close()
    assert response.status_code == 503
    body = response.json()
    assert body["status"] == "not_ready"
    assert body["checks"]["database"]["ok"] is False
    assert "locked" in body["checks"]["database"]["error"]
    ReadyOut.model_validate(body)
    # healthz stays cheap and green: the process is alive, it just should not get traffic.
    assert TestClient(app).get("/healthz").status_code == 200


def test_recovers_when_the_lock_is_released(store):
    app = create_app(store=store, secrets={})
    store_check = store.check_writable
    store.check_writable = lambda timeout=1.0: store_check(timeout=0.2)
    blocker = sqlite3.connect(store.path, isolation_level=None)
    blocker.execute("BEGIN IMMEDIATE")
    client = TestClient(app)
    assert client.get("/readyz").status_code == 503
    blocker.execute("ROLLBACK")
    blocker.close()
    assert client.get("/readyz").status_code == 200


def test_not_ready_when_the_database_cannot_be_opened(tmp_path):
    store = EventStore(str(tmp_path / "gone.db"))
    store.path = str(tmp_path / "missing-directory" / "gone.db")
    response = TestClient(create_app(store=store, secrets={})).get("/readyz")
    assert response.status_code == 503
    assert "unable to open database file" in response.json()["checks"]["database"]["error"]


def test_any_failure_type_is_reported_not_raised(store, monkeypatch):
    def explode(timeout=1.0):
        raise RuntimeError("disk on fire")

    monkeypatch.setattr(store, "check_writable", explode)
    response = TestClient(create_app(store=store, secrets={})).get("/readyz")
    assert response.status_code == 503
    assert response.json()["checks"]["database"]["error"] == "RuntimeError: disk on fire"


def test_readyz_is_public_even_behind_the_password(tmp_path):
    store = EventStore(str(tmp_path / "pw.db"))
    secured = TestClient(create_app(store=store, secrets={}, admin_password="pw"))
    assert secured.get("/readyz").status_code == 200
    assert secured.get("/api/events").status_code == 401
    assert is_public("/readyz") and not is_public("/readyz/")


def test_readyz_is_in_the_openapi_document_with_both_outcomes(client):
    operation = client.get("/openapi.json").json()["paths"]["/readyz"]["get"]
    assert operation["tags"] == ["system"] and operation["summary"] == "Readiness check"
    assert {"200", "503"} <= set(operation["responses"])


def test_responses_carry_a_request_id(client):
    assert client.get("/readyz", headers={"X-Request-ID": "probe-1"}).headers["x-request-id"] == "probe-1"
