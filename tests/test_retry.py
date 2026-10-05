import sqlite3
from datetime import UTC, datetime

import httpx
import pytest
from fastapi.testclient import TestClient

from hookscope.main import create_app
from hookscope.replay import ReplayResult, parse_retry_after
from hookscope.rules import (
    ForwardRule,
    InvalidRuleError,
    RetryPolicy,
    deliver,
    is_retryable,
    parse_rules,
)
from hookscope.store import EventStore


class Script:
    """httpx transport that answers each request to a URL with the next scripted response.

    A script entry is a status code, an exception to raise, or an ``httpx.Response``.
    The last entry repeats once the script runs out.
    """

    def __init__(self, **scripts: list):
        self.scripts = {f"http://{host}.test/": list(steps) for host, steps in scripts.items()}
        self.calls: list[str] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        self.calls.append(url)
        steps = self.scripts[url]
        step = steps.pop(0) if len(steps) > 1 else steps[0]
        if isinstance(step, Exception):
            raise step
        if isinstance(step, httpx.Response):
            return step
        return httpx.Response(step, text="")


class FakeClock:
    def __init__(self):
        self.now = 0.0
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


def _client(tmp_path, script: Script, rules: list[ForwardRule], clock: FakeClock) -> TestClient:
    store = EventStore(str(tmp_path / "test.db"))
    http_client = httpx.Client(transport=httpx.MockTransport(script))
    app = create_app(
        store=store, secrets={}, http_client=http_client, rules=rules, sleep=clock.sleep, clock=clock
    )
    return TestClient(app)


def _forwards(client: TestClient, event_id: int) -> list[tuple]:
    rows = client.get(f"/api/events/{event_id}/forwards").json()
    return [(f["rule"], f["attempt"], f["status_code"]) for f in rows]


def test_transient_failures_are_retried_with_exponential_backoff(tmp_path):
    script = Script(a=[503, httpx.ConnectError("refused"), 500, 200])
    clock = FakeClock()
    rule = ForwardRule("a", "http://a.test/", retry=RetryPolicy(attempts=5, backoff_seconds=2))
    client = _client(tmp_path, script, [rule], clock)

    event_id = client.post("/hooks/generic", content=b"{}").json()["id"]

    assert _forwards(client, event_id) == [("a", 1, 503), ("a", 2, None), ("a", 3, 500), ("a", 4, 200)]
    assert clock.sleeps == [2.0, 4.0, 8.0]


def test_retries_stop_after_the_last_attempt(tmp_path):
    script = Script(a=[502])
    clock = FakeClock()
    rule = ForwardRule("a", "http://a.test/", retry=RetryPolicy(attempts=3, backoff_seconds=1))
    client = _client(tmp_path, script, [rule], clock)

    event_id = client.post("/hooks/generic", content=b"{}").json()["id"]

    assert _forwards(client, event_id) == [("a", 1, 502), ("a", 2, 502), ("a", 3, 502)]
    assert clock.sleeps == [1.0, 2.0]


@pytest.mark.parametrize("status", [200, 302, 400, 404, 410])
def test_success_and_permanent_failures_are_not_retried(tmp_path, status):
    script = Script(a=[status])
    clock = FakeClock()
    client = _client(tmp_path, script, [ForwardRule("a", "http://a.test/", retry=RetryPolicy(4))], clock)

    event_id = client.post("/hooks/generic", content=b"{}").json()["id"]

    assert _forwards(client, event_id) == [("a", 1, status)]
    assert clock.sleeps == []


def test_without_retry_policy_a_failure_is_attempted_once(tmp_path):
    script = Script(a=[500])
    clock = FakeClock()
    client = _client(tmp_path, script, [ForwardRule("a", "http://a.test/")], clock)

    event_id = client.post("/hooks/generic", content=b"{}").json()["id"]

    assert _forwards(client, event_id) == [("a", 1, 500)]


def test_backoff_is_capped(tmp_path):
    script = Script(a=[500])
    clock = FakeClock()
    policy = RetryPolicy(attempts=6, backoff_seconds=10, max_backoff_seconds=30)
    client = _client(tmp_path, script, [ForwardRule("a", "http://a.test/", retry=policy)], clock)

    client.post("/hooks/generic", content=b"{}")

    assert clock.sleeps == [10.0, 20.0, 30.0, 30.0, 30.0]


def test_retry_after_lengthens_the_wait(tmp_path):
    script = Script(a=[httpx.Response(429, headers={"Retry-After": "7"}), 200])
    clock = FakeClock()
    rule = ForwardRule("a", "http://a.test/", retry=RetryPolicy(attempts=3, backoff_seconds=1))
    client = _client(tmp_path, script, [rule], clock)

    event_id = client.post("/hooks/generic", content=b"{}").json()["id"]

    assert _forwards(client, event_id) == [("a", 1, 429), ("a", 2, 200)]
    assert clock.sleeps == [7.0]


def test_retries_do_not_hold_up_other_rules(tmp_path):
    script = Script(slow=[500, 500, 200], fast=[200], other=[503, 200])
    clock = FakeClock()
    rules = [
        ForwardRule("slow", "http://slow.test/", retry=RetryPolicy(attempts=3, backoff_seconds=10)),
        ForwardRule("fast", "http://fast.test/"),
        ForwardRule("other", "http://other.test/", retry=RetryPolicy(attempts=2, backoff_seconds=3)),
    ]
    client = _client(tmp_path, script, rules, clock)

    client.post("/hooks/generic", content=b"{}")

    # First attempts go out back to back; retries follow in order of when they fall due.
    assert script.calls == [
        "http://slow.test/",
        "http://fast.test/",
        "http://other.test/",
        "http://other.test/",  # t=3
        "http://slow.test/",  # t=10
        "http://slow.test/",  # t=30
    ]
    assert clock.now == 30.0


def test_deliver_records_each_attempt_before_waiting():
    events = []
    script = Script(a=[500, 200])

    def record(rule, attempt, result):
        events.append(("record", attempt, result.status_code))

    clock = FakeClock()

    def sleep(seconds):
        events.append(("sleep", seconds))
        clock.sleep(seconds)

    client = httpx.Client(transport=httpx.MockTransport(script))
    event = {"id": 1, "source": "generic", "headers": {}, "body": "{}", "verification": "no_secret"}
    rule = ForwardRule("a", "http://a.test/", retry=RetryPolicy(attempts=2, backoff_seconds=5))

    deliver(event, [rule], client, record, sleep, clock)

    assert events == [("record", 1, 500), ("sleep", 5.0), ("record", 2, 200)]


@pytest.mark.parametrize(
    ("status", "expected"),
    [(None, True), (408, True), (425, True), (429, True), (500, True), (503, True),
     (200, False), (301, False), (400, False), (401, False), (404, False)],
)
def test_is_retryable(status, expected):
    assert is_retryable(ReplayResult("http://x/", status, 1)) is expected


def test_policy_delay():
    policy = RetryPolicy(attempts=5, backoff_seconds=0.5, max_backoff_seconds=3)
    assert [policy.delay(n) for n in (1, 2, 3, 4)] == [0.5, 1.0, 2.0, 3.0]
    assert policy.delay(1, retry_after=2.5) == 2.5
    assert policy.delay(1, retry_after=100) == 3


def test_parse_retry_after():
    now = datetime(2026, 10, 5, 12, 0, 0, tzinfo=UTC)
    assert parse_retry_after("120") == 120.0
    assert parse_retry_after("Mon, 05 Oct 2026 12:00:30 GMT", now=now) == 30.0
    assert parse_retry_after("Mon, 05 Oct 2026 11:00:00 GMT", now=now) == 0.0
    assert parse_retry_after("soon") is None
    assert parse_retry_after("-5") is None
    assert parse_retry_after(None) is None


def test_parse_rules_reads_retry_settings():
    [full, short, default] = parse_rules(
        [
            {"name": "full", "target_url": "http://a.test/",
             "retry": {"attempts": 4, "backoff_seconds": 0.5, "max_backoff_seconds": 10}},
            {"name": "short", "target_url": "http://a.test/", "retry": 3},
            {"name": "default", "target_url": "http://a.test/"},
        ]
    )
    assert full.retry == RetryPolicy(4, 0.5, 10.0)
    assert short.retry == RetryPolicy(3, 1.0, 60.0)
    assert default.retry == RetryPolicy()


@pytest.mark.parametrize(
    ("retry", "message"),
    [
        ("3", "number of attempts or an object"),
        (True, "number of attempts or an object"),
        (0, "from 1 to 10"),
        (11, "from 1 to 10"),
        ({"attempts": 2.5}, "from 1 to 10"),
        ({"backoff_seconds": -1}, "backoff_seconds must be a number"),
        ({"max_backoff_seconds": "60"}, "max_backoff_seconds must be a number"),
        ({"max_backoff_seconds": 7200}, "max_backoff_seconds must be a number"),
        ({"backoff_seconds": 10, "max_backoff_seconds": 5}, "less than backoff_seconds"),
        ({"attempts": 2, "delay": 1}, "unknown retry setting"),
    ],
)
def test_parse_rules_rejects_bad_retry(retry, message):
    with pytest.raises(InvalidRuleError, match=message):
        parse_rules([{"name": "a", "target_url": "http://a.test/", "retry": retry}])


def test_dashboard_shows_attempt_numbers(tmp_path):
    script = Script(a=[500, 200])
    rule = ForwardRule("a", "http://a.test/", retry=RetryPolicy(2))
    client = _client(tmp_path, script, [rule], FakeClock())

    client.post("/hooks/generic", content=b"{}")
    html = client.get("/").text

    assert "<th>Attempt</th>" in html
    assert "<td>2</td>" in html


def test_old_database_gains_attempt_column(tmp_path):
    path = str(tmp_path / "old.db")
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, source TEXT NOT NULL,
            received_at TEXT NOT NULL, headers TEXT NOT NULL, body TEXT NOT NULL,
            verification TEXT NOT NULL, reason TEXT NOT NULL DEFAULT '');
        CREATE TABLE forwards (id INTEGER PRIMARY KEY AUTOINCREMENT, event_id INTEGER NOT NULL,
            rule TEXT NOT NULL, target_url TEXT NOT NULL, forwarded_at TEXT NOT NULL,
            status_code INTEGER, elapsed_ms INTEGER NOT NULL, error TEXT NOT NULL DEFAULT '');
        INSERT INTO events (source, received_at, headers, body, verification) VALUES
            ('generic', '2026-01-01T00:00:00+00:00', '{}', '{}', 'no_secret');
        INSERT INTO forwards (event_id, rule, target_url, forwarded_at, status_code, elapsed_ms) VALUES
            (1, 'a', 'http://a.test/', '2026-01-01T00:00:00+00:00', 200, 3);
        """
    )
    conn.commit()
    conn.close()

    store = EventStore(path)
    store.add_forward(1, "a", "http://a.test/", 500, 4, attempt=2)

    assert [(f["rule"], f["attempt"]) for f in store.list_forwards(1)] == [("a", 1), ("a", 2)]
