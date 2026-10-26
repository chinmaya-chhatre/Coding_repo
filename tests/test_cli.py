import json
import os
import socket
import subprocess
import sys
import time
import urllib.request

import pytest

from hookscope import cli

ENV_NAMES = [*cli.OVERRIDES.values(), "PORT"]


@pytest.fixture(autouse=True)
def clean_environment(monkeypatch):
    for name in ENV_NAMES:
        monkeypatch.delenv(name, raising=False)
    for name in list(os.environ):
        if name.startswith("HOOKSCOPE_SECRET_"):
            monkeypatch.delenv(name)


def parse(*argv):
    return cli.build_parser().parse_args(argv)


# ------------------------------------------------------------------------------ the parser


def test_a_command_is_required(capsys):
    with pytest.raises(SystemExit) as stop:
        parse()
    assert stop.value.code == 2 and "serve" in capsys.readouterr().err


def test_serve_defaults_leave_everything_to_the_environment():
    args = parse("serve")
    assert args.command == "serve" and args.host is None and args.port is None
    assert all(getattr(args, name) is None for name in cli.OVERRIDES) and not args.proxy_headers


def test_serve_flags_are_read():
    args = parse(
        "serve", "--host", "0.0.0.0", "--port", "9000", "--db", "x.db", "--rules", "r.json",
        "--log-format", "json", "--log-level", "debug", "--max-body-bytes", "100", "--proxy-headers",
    )  # fmt: skip
    assert (args.host, args.port, args.db, args.rules) == ("0.0.0.0", 9000, "x.db", "r.json")
    assert (args.log_format, args.log_level, args.max_body_bytes) == ("json", "DEBUG", 100)
    assert args.proxy_headers


@pytest.mark.parametrize("flags", [["--log-format", "xml"], ["--log-level", "loud"], ["--port", "http"]])
def test_bad_flag_values_are_refused(flags, capsys):
    with pytest.raises(SystemExit) as stop:
        parse("serve", *flags)
    assert stop.value.code == 2 and capsys.readouterr().err


def test_there_is_no_secret_flag():
    with pytest.raises(SystemExit):
        parse("serve", "--secret", "github=abc")


# ------------------------------------------------------------------------------ overrides


def test_only_the_flags_that_were_given_touch_the_environment():
    env = {"HOOKSCOPE_DB": "from-env.db", "UNRELATED": "1"}
    cli.apply_overrides(parse("serve", "--rules", "r.json"), env)
    assert env == {"HOOKSCOPE_DB": "from-env.db", "UNRELATED": "1", "HOOKSCOPE_RULES": "r.json"}


def test_a_flag_beats_the_environment_variable():
    env = {"HOOKSCOPE_DB": "from-env.db", "HOOKSCOPE_LOG_LEVEL": "ERROR"}
    cli.apply_overrides(parse("serve", "--db", "flag.db"), env)
    assert env["HOOKSCOPE_DB"] == "flag.db" and env["HOOKSCOPE_LOG_LEVEL"] == "ERROR"


# ------------------------------------------------------------------------------ --check


def test_check_prints_what_would_run_and_does_not_start(capsys, monkeypatch):
    monkeypatch.setenv("HOOKSCOPE_SECRET_GITHUB", "very-secret-value")
    assert cli.main(["serve", "--check", "--port", "9123", "--db", "/tmp/hs-check.db"]) == 0
    out = capsys.readouterr().out
    assert "http://127.0.0.1:9123" in out and "database: /tmp/hs-check.db" in out
    assert "secrets set for: github" in out and "very-secret-value" not in out


def test_check_names_the_providers_when_no_secret_is_set(capsys):
    assert cli.main(["serve", "--check"]) == 0
    assert "secrets set for: none (of generic, github" in capsys.readouterr().out


def test_every_bad_setting_is_reported_together_and_nothing_starts(capsys, monkeypatch):
    monkeypatch.setenv("HOOKSCOPE_MAX_BODY_BYTES", "lots")
    monkeypatch.setenv("HOOKSCOPE_DB_BUSY_TIMEOUT_MS", "soon")
    assert cli.main(["serve", "--check"]) == 2
    err = capsys.readouterr().err
    assert "invalid configuration" in err and "HOOKSCOPE_MAX_BODY_BYTES" in err and "BUSY_TIMEOUT" in err


def test_a_flag_can_fix_a_bad_environment_value(capsys, monkeypatch):
    monkeypatch.setenv("HOOKSCOPE_MAX_BODY_BYTES", "lots")
    assert cli.main(["serve", "--check", "--max-body-bytes", "1000"]) == 0


# ------------------------------------------------------------------------------ starting


class FakeUvicorn:
    def __init__(self):
        self.calls = []

    def run(self, *args, **kwargs):
        self.calls.append((args, kwargs))


@pytest.fixture
def uvicorn_calls(monkeypatch):
    fake = FakeUvicorn()
    monkeypatch.setitem(sys.modules, "uvicorn", fake)
    return fake.calls


def test_serve_starts_uvicorn_on_loopback_by_default(uvicorn_calls):
    assert cli.main(["serve"]) == 0
    [(args, kwargs)] = uvicorn_calls
    assert args == ("hookscope.main:app",)
    assert (kwargs["host"], kwargs["port"], kwargs["proxy_headers"]) == ("127.0.0.1", 8000, False)


def test_the_port_comes_from_the_flag_then_port_then_the_default(uvicorn_calls, monkeypatch):
    monkeypatch.setenv("PORT", "7001")
    cli.main(["serve"])
    cli.main(["serve", "--port", "7002"])
    assert [kwargs["port"] for _, kwargs in uvicorn_calls] == [7001, 7002]


def test_proxy_headers_trust_forwarded_headers(uvicorn_calls):
    cli.main(["serve", "--proxy-headers", "--host", "0.0.0.0"])
    [(_, kwargs)] = uvicorn_calls
    assert kwargs["proxy_headers"] is True and kwargs["forwarded_allow_ips"] == "*"
    assert kwargs["host"] == "0.0.0.0"


def test_the_flags_are_in_the_environment_when_uvicorn_starts(uvicorn_calls):
    seen = {}

    def run(*args, **kwargs):
        seen.update({name: os.environ.get(name) for name in cli.OVERRIDES.values()})

    sys.modules["uvicorn"].run = run
    cli.main(["serve", "--db", "flag.db", "--log-format", "json"])
    assert seen["HOOKSCOPE_DB"] == "flag.db" and seen["HOOKSCOPE_LOG_FORMAT"] == "json"
    os.environ.pop("HOOKSCOPE_DB", None)
    os.environ.pop("HOOKSCOPE_LOG_FORMAT", None)


# ------------------------------------------------------------------------------ for real


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_python_m_hookscope_serve_really_serves(tmp_path):
    port, db = free_port(), tmp_path / "cli.db"
    env = {**os.environ, "HOOKSCOPE_SECRET_GENERIC": "cli-secret"}
    process = subprocess.Popen(
        [sys.executable, "-m", "hookscope", "serve", "--port", str(port), "--db", str(db)],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        base = f"http://127.0.0.1:{port}"
        for _ in range(100):
            try:
                assert json.load(urllib.request.urlopen(base + "/healthz"))["status"] == "ok"
                break
            except OSError:
                assert process.poll() is None, "the server exited"
                time.sleep(0.1)
        else:
            pytest.fail("the server never came up")
        request = urllib.request.Request(base + "/hooks/generic", data=b"{}")
        try:
            urllib.request.urlopen(request)
        except urllib.error.HTTPError as error:
            assert error.code == 401  # unsigned, but received and stored
        assert db.exists()  # the --db flag decided where it was kept
    finally:
        process.terminate()
        process.wait(timeout=10)
