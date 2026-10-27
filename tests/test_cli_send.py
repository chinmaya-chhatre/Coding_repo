import json
import subprocess
import sys
import time
import urllib.request

import pytest
from fastapi.testclient import TestClient

from hookscope import cli
from hookscope.main import create_app
from hookscope.providers import PROVIDERS
from hookscope.store import EventStore

TIMESTAMPED = sorted(name for name, p in PROVIDERS.items() if p.timestamp_from)
UNTIMED = sorted(set(PROVIDERS) - set(TIMESTAMPED))


@pytest.fixture(autouse=True)
def demo_environment(monkeypatch):
    for name in PROVIDERS:
        monkeypatch.delenv(f"HOOKSCOPE_SECRET_{name.upper()}", raising=False)


@pytest.fixture
def server(tmp_path, monkeypatch):
    """HookScope with every provider's demo secret, reached without a network: ``cli.post`` is rerouted."""
    secrets = {name: cli.demo_secret(name) for name in PROVIDERS}
    app = create_app(store=EventStore(str(tmp_path / "send.db")), secrets=secrets, admin_password=None)
    client = TestClient(app, base_url="http://hookscope.test")  # Twilio signs the URL, so it must match
    seen = []

    def post(url, body, headers, timeout=10.0):
        seen.append(url)
        response = client.post(url, content=body, headers=headers)
        return response.status_code, response.text

    monkeypatch.setattr(cli, "post", post)
    client.seen = seen
    return client


def send(*argv):
    return cli.main(["send", "--url", "http://hookscope.test", *argv])


def events(server):
    return server.get("/api/events?limit=500").json()[::-1]


@pytest.mark.parametrize("provider", sorted(PROVIDERS))
def test_a_good_delivery_is_accepted_and_valid(server, provider, capsys):
    assert send(provider) == 0
    [event] = events(server)
    assert (event["source"], event["verification"]) == (provider, "valid")
    assert "202" in capsys.readouterr().out


@pytest.mark.parametrize("provider", sorted(PROVIDERS))
@pytest.mark.parametrize("scenario", ["bad-secret", "tampered"])
def test_the_bad_scenarios_are_rejected_and_stored(server, provider, scenario, capsys):
    assert send(provider, "--scenario", scenario) == 0  # 401 is what this scenario should get
    [event] = events(server)
    assert event["verification"] == "invalid" and event["diagnosis"]["cause"]
    assert "401" in capsys.readouterr().out


@pytest.mark.parametrize("provider", TIMESTAMPED)
def test_a_stale_timestamp_is_diagnosed_as_old(server, provider):
    assert send(provider, "--scenario", "stale-timestamp") == 0
    [event] = events(server)
    assert event["reason"].startswith("timestamp outside tolerance")
    assert (
        event["diagnosis"]["cause"] == "stale_timestamp" and "3600 seconds" in event["diagnosis"]["message"]
    )


@pytest.mark.parametrize("provider", UNTIMED)
def test_a_stale_timestamp_for_a_provider_without_one_is_refused_before_sending(server, provider, capsys):
    assert send(provider, "--scenario", "stale-timestamp") == 2
    assert "no timestamp" in capsys.readouterr().err and events(server) == []


def test_all_runs_the_four_scenarios_and_skips_what_does_not_apply(server, capsys):
    assert send("github", "--scenario", "all") == 0
    out = capsys.readouterr().out
    for scenario in ("good", "bad-secret", "tampered"):
        assert scenario in out
    assert "stale-timestamp  skipped" in out
    assert [e["verification"] for e in events(server)] == ["valid", "invalid", "invalid"]


def test_all_for_a_timestamped_provider_sends_all_four(server):
    assert send("stripe", "--scenario", "all") == 0
    assert [e["verification"] for e in events(server)] == ["valid", "invalid", "invalid", "invalid"]


def test_the_secret_comes_from_the_flag_then_the_environment(server, monkeypatch):
    assert send("github", "--secret", "wrong-on-purpose") == 1  # expected 202, got 401
    monkeypatch.setenv("HOOKSCOPE_SECRET_GITHUB", cli.demo_secret("github"))
    assert send("github") == 0


def test_a_mismatch_with_the_expected_answer_is_a_failure(server, capsys):
    assert send("github", "--secret", "nope") == 1
    assert "good should have been 202" in capsys.readouterr().err


def test_an_unreachable_hookscope_is_reported(monkeypatch, capsys):
    monkeypatch.setattr(cli, "post", lambda *a, **k: (None, "connection refused"))
    assert send("github") == 1
    err = capsys.readouterr()
    assert "no answer" in err.out and "could not reach http://hookscope.test/hooks/github" in err.err


def test_twilio_signs_the_url_it_is_sent_to(server):
    assert send("twilio") == 0
    assert server.seen == ["http://hookscope.test/hooks/twilio"]
    [event] = events(server)
    assert event["verification"] == "valid"


def test_the_target_url_ignores_a_trailing_slash(server):
    assert cli.main(["send", "github", "--url", "http://hookscope.test/"]) == 0
    assert server.seen == ["http://hookscope.test/hooks/github"]


def test_tampering_changes_the_last_byte_only():
    assert cli.tamper(b'{"a": 1}') == b'{"a": 1X'
    assert cli.tamper(b"..X") == b"..Y"
    assert len(cli.tamper(b"abc")) == 3


def test_an_unknown_provider_or_scenario_is_refused(capsys):
    for argv in (["send", "nope"], ["send", "github", "--scenario", "nope"]):
        with pytest.raises(SystemExit) as stop:
            cli.build_parser().parse_args(argv)
        assert stop.value.code == 2


def test_the_old_script_is_gone():
    import pathlib

    assert not (pathlib.Path(cli.__file__).parent.parent / "scripts" / "send_test_webhook.py").exists()


def test_send_really_talks_to_a_running_server(tmp_path):
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    import os

    env = {**os.environ, "HOOKSCOPE_SECRET_STRIPE": "dev-secret", "HOOKSCOPE_DB": str(tmp_path / "real.db")}
    server = subprocess.Popen(
        [sys.executable, "-m", "hookscope", "serve", "--port", str(port)],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(100):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz")
                break
            except OSError:
                assert server.poll() is None
                time.sleep(0.1)
        done = subprocess.run(
            [sys.executable, "-m", "hookscope", "send", "stripe", "--scenario", "all"]
            + ["--url", f"http://127.0.0.1:{port}"],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert done.returncode == 0, done.stderr
        statuses = [line.split()[1] for line in done.stdout.splitlines()]
        assert statuses == ["202", "401", "401", "401"]
        events = json.load(urllib.request.urlopen(f"http://127.0.0.1:{port}/api/events"))
        assert len(events) == 4
    finally:
        server.terminate()
        server.wait(timeout=10)
