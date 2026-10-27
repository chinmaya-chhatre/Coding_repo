import base64
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from urllib.parse import parse_qs, urlparse

import pytest

from hookscope import cli


def make_event(event_id, source="github", verification="valid", diagnosis=None, reason=""):
    return {
        "id": event_id,
        "source": source,
        "received_at": f"2026-10-27T13:00:{event_id % 60:02d}+00:00",
        "headers": {"x-github-event": "push"} if source == "github" else {},
        "body": json.dumps({"type": "invoice.paid"}) if source == "stripe" else "{}",
        "verification": verification,
        "reason": reason,
        "diagnosis": diagnosis,
    }


class FakeServer:
    """The ``GET /api/events`` contract: newest first, with ``limit``, ``before_id`` and the filters."""

    def __init__(self):
        self.events = []
        self.requests = []
        self.down = False

    def add(self, *events):
        self.events += events

    def __call__(self, url, headers):
        self.requests.append((url, headers))
        if self.down:
            return None, "connection refused"
        query = {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}
        matching = [
            e
            for e in reversed(self.events)
            if query.get("source", e["source"]) == e["source"]
            and query.get("verification", e["verification"]) == e["verification"]
            and e["id"] < int(query.get("before_id", 10**12))
        ]
        return 200, matching[: int(query["limit"])]


def run(argv, server, sleep=None, capsys=None):
    args = cli.build_parser().parse_args(["tail", *argv])
    return cli.tail(args, fetch=server, sleep=sleep or (lambda seconds: None))


@pytest.fixture(autouse=True)
def no_password(monkeypatch):
    monkeypatch.delenv("HOOKSCOPE_ADMIN_PASSWORD", raising=False)


def printed(capsys):
    return capsys.readouterr().out.splitlines()


def test_the_last_events_are_shown_oldest_first(capsys):
    server = FakeServer()
    server.add(*[make_event(n) for n in range(1, 31)])
    assert run(["--no-follow", "--last", "3"], server) == 0
    assert [line.split()[0] for line in printed(capsys)] == ["#28", "#29", "#30"]


def test_last_zero_shows_nothing_first(capsys):
    server = FakeServer()
    server.add(make_event(1))
    assert run(["--no-follow", "--last", "0"], server) == 0
    assert printed(capsys) == []


def test_the_filters_are_sent_to_the_api_and_apply(capsys):
    server = FakeServer()
    server.add(make_event(1, "github"), make_event(2, "stripe", "invalid"), make_event(3, "stripe"))
    run(["--no-follow", "--source", "stripe", "--verification", "invalid"], server)
    assert [line.split()[0] for line in printed(capsys)] == ["#2"]
    query = parse_qs(urlparse(server.requests[0][0]).query)
    assert query["source"] == ["stripe"] and query["verification"] == ["invalid"]


def test_json_output_is_one_event_per_line_as_the_api_returns_it(capsys):
    server = FakeServer()
    server.add(make_event(1), make_event(2, "stripe", "invalid", {"cause": "c", "message": "m", "fix": "f"}))
    run(["--no-follow", "--json"], server)
    events = [json.loads(line) for line in printed(capsys)]
    assert [e["id"] for e in events] == [1, 2] and events[1]["diagnosis"]["cause"] == "c"


def test_new_events_are_printed_once_as_they_arrive(capsys):
    server = FakeServer()
    server.add(make_event(1))
    rounds = iter([[make_event(2)], [], [make_event(3), make_event(4)], None])

    def sleep(seconds):
        batch = next(rounds)
        if batch is None:
            raise KeyboardInterrupt
        server.add(*batch)

    assert run(["--last", "1"], server, sleep) == 0  # Ctrl-C ends it quietly
    assert [line.split()[0] for line in printed(capsys)] == ["#1", "#2", "#3", "#4"]


def test_a_burst_bigger_than_a_page_is_not_lost_or_repeated(capsys):
    server = FakeServer()
    server.add(make_event(1))
    burst = [make_event(n) for n in range(2, 2 + cli.PAGE * 2 + 7)]
    calls = iter([burst, None])

    def sleep(seconds):
        batch = next(calls)
        if batch is None:
            raise KeyboardInterrupt
        server.add(*batch)

    run(["--last", "0"], server, sleep)
    ids = [int(line.split()[0][1:]) for line in printed(capsys)]
    assert ids == [e["id"] for e in burst]


def test_an_empty_server_is_followed_from_the_start(capsys):
    server = FakeServer()
    calls = iter([[make_event(1)], None])

    def sleep(seconds):
        batch = next(calls)
        if batch is None:
            raise KeyboardInterrupt
        server.add(*batch)

    run([], server, sleep)
    assert [line.split()[0] for line in printed(capsys)] == ["#1"]


def test_a_filter_applies_to_new_events_too(capsys):
    server = FakeServer()
    calls = iter([[make_event(1, "github"), make_event(2, "stripe")], None])

    def sleep(seconds):
        batch = next(calls)
        if batch is None:
            raise KeyboardInterrupt
        server.add(*batch)

    run(["--source", "stripe"], server, sleep)
    assert [line.split()[0] for line in printed(capsys)] == ["#2"]


# ------------------------------------------------------------------------------ failing


def test_an_unreachable_server_at_the_start_is_an_error(capsys):
    server = FakeServer()
    server.down = True
    assert run(["--no-follow"], server) == 1
    assert "could not reach http://127.0.0.1:8000" in capsys.readouterr().err


def test_a_server_that_goes_away_while_following_is_waited_for_and_reported_once(capsys):
    server = FakeServer()
    server.add(make_event(1))
    script = iter(["down", "down", "up", None])

    def sleep(seconds):
        step = next(script)
        if step is None:
            raise KeyboardInterrupt
        server.down = step == "down"
        if step == "up":
            server.add(make_event(2))

    assert run(["--last", "0"], server, sleep) == 0
    captured = capsys.readouterr()
    assert captured.err.count("retrying") == 1
    assert [line.split()[0] for line in captured.out.splitlines()] == ["#2"]


def test_a_wrong_password_stops_it_with_advice(capsys):
    def refuse(url, headers):
        return 401, "unauthorized"

    assert run(["--no-follow"], refuse) == 2
    assert "HOOKSCOPE_ADMIN_PASSWORD" in capsys.readouterr().err


def test_the_password_is_sent_as_basic_auth(monkeypatch):
    monkeypatch.setenv("HOOKSCOPE_ADMIN_PASSWORD", "hunter2")
    server = FakeServer()
    run(["--no-follow"], server)
    token = server.requests[0][1]["Authorization"].removeprefix("Basic ")
    assert base64.b64decode(token) == b"hookscope:hunter2"


def test_no_authorization_header_without_a_password():
    server = FakeServer()
    run(["--no-follow"], server)
    assert server.requests[0][1] == {}


def test_an_unexpected_answer_is_reported(capsys):
    assert run(["--no-follow"], lambda url, headers: (404, "no such endpoint")) == 2
    assert "unexpected answer 404" in capsys.readouterr().err


# ------------------------------------------------------------------------------ the line


def test_a_line_names_the_event_type_and_the_diagnosis():
    line = cli.format_event(
        make_event(7, "stripe", "invalid", {"cause": "stale_timestamp", "message": "It is old.", "fix": "x"})
    )
    assert line.startswith("#7") and "13:00:07" in line and "invoice.paid" in line
    assert "[stale_timestamp] It is old." in line


def test_a_valid_event_has_no_trailing_explanation():
    assert cli.format_event(make_event(1)).rstrip().endswith("push")


def test_an_old_rejected_event_falls_back_to_its_reason():
    line = cli.format_event(make_event(1, "github", "invalid", None, "signature mismatch"))
    assert line.endswith("signature mismatch")


def test_an_event_with_no_type_shows_a_dash():
    assert cli.format_event(make_event(1, "generic")).endswith(" -")


# ------------------------------------------------------------------------------ for real


def test_tail_reads_a_real_server(tmp_path):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    env = {**os.environ, "HOOKSCOPE_SECRET_GITHUB": "dev-secret", "HOOKSCOPE_DB": str(tmp_path / "t.db")}
    server = subprocess.Popen(
        [sys.executable, "-m", "hookscope", "serve", "--port", str(port)],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        url = f"http://127.0.0.1:{port}"
        for _ in range(100):
            try:
                urllib.request.urlopen(url + "/healthz")
                break
            except OSError:
                assert server.poll() is None
                time.sleep(0.1)
        for scenario in ("good", "bad-secret"):
            done = subprocess.run(
                [sys.executable, "-m", "hookscope", "send", "github", "--scenario", scenario, "--url", url],
                env=env,
                capture_output=True,
                timeout=60,
            )
            assert done.returncode == 0
        shown = subprocess.run(
            [sys.executable, "-m", "hookscope", "tail", "--no-follow", "--url", url],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        lines = shown.stdout.splitlines()
        assert shown.returncode == 0 and len(lines) == 2
        assert "valid" in lines[0] and "invalid" in lines[1] and "[unexplained]" in lines[1]
    finally:
        server.terminate()
        server.wait(timeout=10)
