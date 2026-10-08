import hashlib
import hmac

import pytest
from fastapi.testclient import TestClient

from hookscope.main import create_app
from hookscope.metrics import render
from hookscope.rules import ForwardRule, RetryPolicy
from hookscope.store import EventStore

SECRET = "s3cret"


@pytest.fixture
def store(tmp_path):
    return EventStore(str(tmp_path / "metrics.db"))


def _sample(text: str, name: str, **labels: str) -> int | None:
    """Value of the sample with exactly these labels, or None if absent."""
    label_text = ",".join(f'{k}="{v}"' for k, v in labels.items())
    prefix = f"{name}{{{label_text}}} " if labels else f"{name} "
    for line in text.splitlines():
        if line.startswith(prefix):
            return int(line[len(prefix):])
    return None


def test_metrics_endpoint_counts_deliveries_by_source_and_verification(store):
    client = TestClient(create_app(store=store, secrets={"github": SECRET}))
    body = b'{"ref": "main"}'
    sig = hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()
    client.post("/hooks/github", content=body, headers={"X-Hub-Signature-256": f"sha256={sig}"})
    client.post("/hooks/github", content=body, headers={"X-Hub-Signature-256": "sha256=bad"})
    client.post("/hooks/generic", content=b"{}")

    resp = client.get("/metrics")

    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/plain; version=0.0.4")
    text = resp.text
    assert "# TYPE hookscope_deliveries_total counter" in text
    assert _sample(text, "hookscope_deliveries_total", source="github", verification="valid") == 1
    assert _sample(text, "hookscope_deliveries_total", source="github", verification="invalid") == 1
    assert _sample(text, "hookscope_deliveries_total", source="generic", verification="no_secret") == 1
    # Known pairs are exported at zero so rate() works before the first delivery.
    assert _sample(text, "hookscope_deliveries_total", source="stripe", verification="valid") == 0
    assert _sample(text, "hookscope_dead_letters") == 0
    assert text.endswith("\n")


def test_forward_attempts_split_by_outcome(store):
    event_id = store.add(source="generic", headers={}, body="{}", verification="valid", reason="")
    store.add_forward(event_id, "billing", "http://b.test/", 200, 5)
    store.add_forward(event_id, "billing", "http://b.test/", 503, 5, attempt=2)
    store.add_forward(event_id, "audit", "http://a.test/", None, 5, error="ConnectError")

    text = render(store, sources=["generic"], dead_letters=1)

    assert _sample(text, "hookscope_forward_attempts_total", rule="billing", outcome="success") == 1
    assert _sample(text, "hookscope_forward_attempts_total", rule="billing", outcome="failure") == 1
    assert _sample(text, "hookscope_forward_attempts_total", rule="audit", outcome="failure") == 1
    assert _sample(text, "hookscope_dead_letters") == 1


def test_dead_letters_gauge_reflects_exhausted_forwards(tmp_path):
    store = EventStore(str(tmp_path / "dead.db"))
    rule = ForwardRule("ops", "http://ops.test/", retry=RetryPolicy(attempts=1))
    client = TestClient(create_app(store=store, secrets={}, rules=[rule]))
    event_id = store.add(source="generic", headers={}, body="{}", verification="valid", reason="")
    store.add_forward(event_id, "ops", "http://ops.test/", 500, 5)
    assert _sample(client.get("/metrics").text, "hookscope_dead_letters") == 1


def test_label_values_are_escaped(store):
    event_id = store.add(source="generic", headers={}, body="{}", verification="valid", reason="")
    store.add_forward(event_id, 'say "hi"\\now', "http://x.test/", 200, 1)
    text = render(store, sources=[], dead_letters=0)
    assert 'rule="say \\"hi\\"\\\\now"' in text
