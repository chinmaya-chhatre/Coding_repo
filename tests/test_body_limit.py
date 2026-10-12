import pytest
from fastapi.testclient import TestClient

from hookscope.config import DEFAULT_MAX_BODY_BYTES, max_body_bytes_from_env
from hookscope.main import create_app
from hookscope.store import EventStore

LIMIT = 1000


@pytest.fixture
def store(tmp_path):
    return EventStore(str(tmp_path / "limit.db"))


@pytest.fixture
def client(store):
    return TestClient(create_app(store=store, secrets={}, max_body_bytes=LIMIT))


def test_body_at_the_limit_is_accepted(client, store):
    resp = client.post("/hooks/generic", content=b"x" * LIMIT)
    assert resp.status_code == 202
    assert len(store.get(resp.json()["id"])["body"]) == LIMIT


def test_body_over_the_limit_is_rejected_and_not_stored(client, store):
    resp = client.post("/hooks/generic", content=b"x" * (LIMIT + 1))
    assert resp.status_code == 413
    assert str(LIMIT) in resp.json()["detail"]
    assert store.count() == 0


def test_chunked_body_without_content_length_is_still_limited(client, store):
    def chunks():
        for _ in range(5):
            yield b"y" * 300  # 1500 bytes in total, sent without a Content-Length header

    resp = client.post("/hooks/generic", content=chunks())
    assert resp.status_code == 413
    assert store.count() == 0


def test_declared_content_length_is_refused_before_reading(client, store):
    resp = client.post("/hooks/generic", content=b"z", headers={"Content-Length": str(LIMIT * 100)})
    # h11 rejects a body shorter than its declared length; either way nothing is stored.
    assert resp.status_code in (400, 413)
    assert store.count() == 0


def test_limit_applies_to_every_provider_and_is_checked_before_signatures(store):
    client = TestClient(create_app(store=store, secrets={"github": "s3cret"}, max_body_bytes=LIMIT))
    headers = {"X-Hub-Signature-256": "sha256=bad"}
    resp = client.post("/hooks/github", content=b"x" * (LIMIT + 1), headers=headers)
    assert resp.status_code == 413  # not 401: nothing is hashed or stored for an oversized body
    assert store.count() == 0


def test_normal_deliveries_are_unaffected_by_the_default(store):
    client = TestClient(create_app(store=store, secrets={}))
    assert client.post("/hooks/generic", content=b"x" * 100_000).status_code == 202


def test_limit_from_environment():
    assert max_body_bytes_from_env({}) == DEFAULT_MAX_BODY_BYTES
    assert max_body_bytes_from_env({"HOOKSCOPE_MAX_BODY_BYTES": " 2048 "}) == 2048
    for bad in ("0", "-5", "lots", "1.5"):
        with pytest.raises(ValueError, match="HOOKSCOPE_MAX_BODY_BYTES"):
            max_body_bytes_from_env({"HOOKSCOPE_MAX_BODY_BYTES": bad})


def test_app_reads_the_limit_from_the_environment(store, monkeypatch):
    monkeypatch.setenv("HOOKSCOPE_MAX_BODY_BYTES", "64")
    client = TestClient(create_app(store=store, secrets={}))
    assert client.post("/hooks/generic", content=b"x" * 65).status_code == 413
    assert client.post("/hooks/generic", content=b"x" * 64).status_code == 202
