import httpx
from fastapi.testclient import TestClient

from hookscope.main import create_app
from hookscope.rules import ForwardRule, RetryPolicy, is_dead_letter
from hookscope.store import EventStore


def _client(tmp_path, statuses: dict[str, list[int]], rules: list[ForwardRule]):
    scripts = {f"http://{host}.test/": list(steps) for host, steps in statuses.items()}

    def handler(request: httpx.Request) -> httpx.Response:
        steps = scripts[str(request.url)]
        return httpx.Response(steps.pop(0) if len(steps) > 1 else steps[0])

    store = EventStore(str(tmp_path / "test.db"))
    http_client = httpx.Client(transport=httpx.MockTransport(handler))
    app = create_app(store=store, secrets={}, http_client=http_client, rules=rules, sleep=lambda s: None)
    return TestClient(app), store


def _fwd(status, attempt=1):
    return {"status_code": status, "attempt": attempt}


def test_is_dead_letter_rules():
    rule = ForwardRule("a", "http://a.test/", retry=RetryPolicy(attempts=3))
    assert not is_dead_letter(_fwd(200), rule)
    assert not is_dead_letter(_fwd(503, 2), rule)  # still has attempts left
    assert not is_dead_letter(_fwd(None, 1), rule)
    assert is_dead_letter(_fwd(503, 3), rule)  # exhausted
    assert is_dead_letter(_fwd(404, 1), rule)  # permanent error
    assert is_dead_letter(_fwd(503, 1), None)  # rule removed


def test_exhausted_and_permanent_failures_are_listed(tmp_path):
    rules = [
        ForwardRule("flaky", "http://flaky.test/", retry=RetryPolicy(2, backoff_seconds=0)),
        ForwardRule("gone", "http://gone.test/"),
        ForwardRule("fine", "http://fine.test/"),
    ]
    client, _ = _client(tmp_path, {"flaky": [500], "gone": [404], "fine": [200]}, rules)
    event_id = client.post("/hooks/generic", content=b"{}").json()["id"]

    dead = client.get("/api/dead-letters").json()

    assert {(d["event_id"], d["rule"], d["status_code"], d["attempt"]) for d in dead} == {
        (event_id, "flaky", 500, 2),
        (event_id, "gone", 404, 1),
    }
    assert all(d["resendable"] for d in dead)


def test_resend_success_removes_the_dead_letter(tmp_path):
    rule = ForwardRule("a", "http://a.test/")
    client, _ = _client(tmp_path, {"a": [503, 200]}, [rule])
    event_id = client.post("/hooks/generic", content=b"{}").json()["id"]
    assert len(client.get("/api/dead-letters").json()) == 1

    resp = client.post(f"/api/events/{event_id}/forwards/a/resend")

    assert resp.status_code == 200
    assert resp.json()["ok"] is True
    assert resp.json()["attempt"] == 2
    assert client.get("/api/dead-letters").json() == []
    stored = client.get(f"/api/events/{event_id}/forwards").json()
    attempts = [(f["attempt"], f["status_code"]) for f in stored]
    assert attempts == [(1, 503), (2, 200)]


def test_resend_failure_keeps_it_dead_and_counts_the_attempt(tmp_path):
    client, _ = _client(tmp_path, {"a": [500]}, [ForwardRule("a", "http://a.test/")])
    event_id = client.post("/hooks/generic", content=b"{}").json()["id"]

    resp = client.post(f"/api/events/{event_id}/forwards/a/resend")

    assert resp.status_code == 200
    assert resp.json()["ok"] is False
    dead = client.get("/api/dead-letters").json()
    assert [(d["rule"], d["attempt"]) for d in dead] == [("a", 2)]


def test_resend_unreachable_target_is_502(tmp_path):
    def handler(request):
        raise httpx.ConnectError("refused")

    store = EventStore(str(tmp_path / "test.db"))
    rule = ForwardRule("a", "http://a.test/")
    http_client = httpx.Client(transport=httpx.MockTransport(handler))
    client = TestClient(create_app(store=store, secrets={}, http_client=http_client, rules=[rule]))
    event_id = client.post("/hooks/generic", content=b"{}").json()["id"]

    resp = client.post(f"/api/events/{event_id}/forwards/a/resend")

    assert resp.status_code == 502
    assert resp.json()["attempt"] == 2


def test_resend_errors(tmp_path):
    client, store = _client(tmp_path, {"a": [500]}, [ForwardRule("a", "http://a.test/")])
    event_id = client.post("/hooks/generic", content=b"{}").json()["id"]
    unforwarded = store.add("generic", {}, "{}", "no_secret", "")

    assert client.post("/api/events/999/forwards/a/resend").status_code == 404
    assert client.post(f"/api/events/{event_id}/forwards/nope/resend").status_code == 404
    assert client.post(f"/api/events/{unforwarded}/forwards/a/resend").status_code == 404


def test_removed_rule_is_listed_but_not_resendable(tmp_path):
    client, store = _client(tmp_path, {}, [])
    event_id = store.add("generic", {}, "{}", "no_secret", "")
    store.add_forward(event_id, "old-rule", "http://old.test/", 500, 5)

    dead = client.get("/api/dead-letters").json()

    assert [(d["rule"], d["resendable"]) for d in dead] == [("old-rule", False)]
    assert client.post(f"/api/events/{event_id}/forwards/old-rule/resend").status_code == 404


def test_dashboard_shows_dead_letters(tmp_path):
    client, _ = _client(tmp_path, {"a": [500]}, [ForwardRule("a", "http://a.test/")])
    event_id = client.post("/hooks/generic", content=b"{}").json()["id"]

    html = client.get("/").text

    assert "Dead letters (1)" in html
    assert f'data-event-id="{event_id}" data-rule="a"' in html
    assert "Re-send" in html


def test_dashboard_hides_section_without_dead_letters(tmp_path):
    client, _ = _client(tmp_path, {"a": [200]}, [ForwardRule("a", "http://a.test/")])
    client.post("/hooks/generic", content=b"{}")

    assert "Dead letters" not in client.get("/").text
