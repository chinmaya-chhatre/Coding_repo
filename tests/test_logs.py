import io
import json
import logging
import os
import pwd
import subprocess
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from hookscope import logs
from hookscope.config import ConfigError, Settings
from hookscope.main import create_app
from hookscope.rules import ForwardRule
from hookscope.store import EventStore

ROOT = Path(__file__).parent.parent


@pytest.fixture
def store(tmp_path):
    return EventStore(str(tmp_path / "logs.db"))


def app_for(store, **kwargs):
    return TestClient(create_app(store=store, secrets={}, **kwargs))


# ---------------------------------------------------------------------------- formatters


def format_record(formatter, message="hello", **extra):
    record = logging.LogRecord("hookscope.x", logging.INFO, __file__, 1, message, (), None)
    record.__dict__.update(extra)
    return formatter.format(record)


def test_json_lines_are_valid_json_with_the_standard_keys():
    line = format_record(logs.JsonFormatter(), "a message", event_id=7, source="github")
    entry = json.loads(line)
    assert entry["message"] == "a message" and entry["level"] == "INFO" and entry["logger"] == "hookscope.x"
    assert entry["event_id"] == 7 and entry["source"] == "github"
    assert entry["request_id"] is None
    assert entry["ts"].endswith("+00:00")
    assert "\n" not in line


def test_the_current_request_id_is_included():
    token = logs.current_request_id.set("trace-9")
    try:
        assert json.loads(format_record(logs.JsonFormatter()))["request_id"] == "trace-9"
        assert "[trace-9]" in format_record(logs.TextFormatter())
    finally:
        logs.current_request_id.reset(token)
    assert "[" not in format_record(logs.TextFormatter()).split("hookscope.x")[1].split("hello")[0]


def test_formatting_twice_gives_the_same_line():
    formatter = logs.TextFormatter()
    record = logging.LogRecord("hookscope", logging.INFO, __file__, 1, "request", (), None)
    record.status = 200
    assert formatter.format(record) == formatter.format(record)


def test_text_format_appends_fields_as_key_value_pairs():
    assert format_record(logs.TextFormatter(), "request", status=202, path="/hooks/x").endswith(
        "request status=202 path=/hooks/x"
    )


def test_exceptions_are_logged_as_a_field():
    try:
        raise ValueError("boom")
    except ValueError:
        import sys

        record = logging.LogRecord("hookscope", logging.ERROR, __file__, 1, "failed", (), sys.exc_info())
    assert "ValueError: boom" in json.loads(logs.JsonFormatter().format(record))["exception"]


def test_unserialisable_values_do_not_break_logging():
    assert json.loads(format_record(logs.JsonFormatter(), obj=object()))["obj"].startswith("<object")


def test_configure_is_idempotent():
    logger = logging.getLogger("hookscope")
    before = list(logger.handlers)
    try:
        logs.configure("json", "INFO")
        logs.configure("text", "INFO")
        ours = [h for h in logger.handlers if getattr(h, "_hookscope_handler", False)]
        assert len(ours) == 1 and isinstance(ours[0].formatter, logs.TextFormatter)
    finally:
        logger.handlers[:] = before


# -------------------------------------------------------------------------------- settings


def test_settings_defaults_and_values():
    assert (Settings.from_env({}).log_format, Settings.from_env({}).log_level) == ("text", "INFO")
    settings = Settings.from_env({"HOOKSCOPE_LOG_FORMAT": " JSON ", "HOOKSCOPE_LOG_LEVEL": "debug"})
    assert (settings.log_format, settings.log_level) == ("json", "DEBUG")


def test_invalid_log_settings_are_reported_with_the_other_errors():
    with pytest.raises(ConfigError) as error:
        Settings.from_env(
            {"HOOKSCOPE_LOG_FORMAT": "xml", "HOOKSCOPE_LOG_LEVEL": "loud", "HOOKSCOPE_MAX_BODY_BYTES": "0"}
        )
    assert len(error.value.errors) == 3
    assert any("HOOKSCOPE_LOG_FORMAT" in e for e in error.value.errors)
    assert any("HOOKSCOPE_LOG_LEVEL" in e for e in error.value.errors)


# ------------------------------------------------------------------------- in the running app


def run_app(monkeypatch, store, **kwargs):
    monkeypatch.setenv("HOOKSCOPE_LOG_FORMAT", "json")
    monkeypatch.setenv("HOOKSCOPE_LOG_LEVEL", "DEBUG")
    logger = logging.getLogger("hookscope")
    before = (list(logger.handlers), logger.level)
    client = app_for(store, **kwargs)
    stream = io.StringIO()
    logger.handlers[-1].setStream(stream)
    return client, lambda: [json.loads(line) for line in stream.getvalue().splitlines()], before


def restore(before):
    logger = logging.getLogger("hookscope")
    logger.handlers[:] = before[0]
    logger.setLevel(before[1])


def test_each_request_logs_one_access_line_with_its_request_id(monkeypatch, store):
    client, lines, before = run_app(monkeypatch, store)
    try:
        client.get("/api/events", headers={"X-Request-ID": "trace-1"})
        [entry] = [e for e in lines() if e["message"] == "request"]
        assert entry["request_id"] == "trace-1"
        assert (entry["method"], entry["path"], entry["status"]) == ("GET", "/api/events", 200)
        assert entry["duration_ms"] >= 0
    finally:
        restore(before)


def test_a_delivery_is_followed_by_one_id_through_its_log_lines(monkeypatch, store):
    seen = []
    http = httpx.Client(transport=httpx.MockTransport(lambda r: seen.append(r) or httpx.Response(500)))
    rule = ForwardRule("ci", "https://target.test/hook")
    client, lines, before = run_app(monkeypatch, store, rules=[rule], http_client=http, sleep=lambda s: None)
    try:
        receipt = client.post(
            "/hooks/generic", content=b'{"secret": "do-not-log"}', headers={"X-Request-ID": "t-42"}
        )
        entries = lines()
        assert {e["request_id"] for e in entries} == {"t-42"}, entries
        messages = [e["message"] for e in entries]
        assert messages.count("event received") == 1 and messages.count("request") == 1
        assert messages.count("forward attempt") >= 1  # retried after the 500s, same id on every line
        received = next(e for e in entries if e["message"] == "event received")
        assert received["event_id"] == receipt.json()["id"] and received["verification"] == "no_secret"
        assert all(e["level"] == "WARNING" for e in entries if e["message"] == "forward attempt")
        assert "do-not-log" not in json.dumps(entries)
    finally:
        restore(before)


def test_rejected_deliveries_are_warnings_with_the_reason(monkeypatch, store):
    client, lines, before = run_app(monkeypatch, store)
    try:
        secured = TestClient(create_app(store=store, secrets={"github": "s"}))
        logs.configure("json", "DEBUG")
        stream = io.StringIO()
        logging.getLogger("hookscope").handlers[-1].setStream(stream)
        secured.post("/hooks/github", content=b"{}", headers={"X-Hub-Signature-256": "sha256=0"})
        received = next(
            json.loads(line) for line in stream.getvalue().splitlines() if '"event received"' in line
        )
        assert received["level"] == "WARNING" and received["verification"] == "invalid"
        assert received["reason"] == "signature mismatch"
    finally:
        restore(before)


def test_health_checks_are_debug_level_so_they_stay_out_of_the_info_log(monkeypatch, store):
    client, lines, before = run_app(monkeypatch, store)
    try:
        client.get("/healthz")
        [entry] = [e for e in lines() if e["message"] == "request"]
        assert entry["level"] == "DEBUG" and entry["path"] == "/healthz"
    finally:
        restore(before)


# ---------------------------------------------------------------------------------- deploy


def _can_run_entrypoint_as_root() -> bool:
    """As root the script chowns the data directory to the `hookscope` user, which must exist."""
    if os.getuid() != 0:
        return True
    try:
        pwd.getpwnam("hookscope")
    except KeyError:
        return False
    return True


@pytest.mark.skipif(not _can_run_entrypoint_as_root(), reason="needs the hookscope user when run as root")
@pytest.mark.parametrize(("value", "dropped"), [("json", True), ("text", False), ("", False)])
def test_entrypoint_drops_uvicorns_access_log_only_for_json(value, dropped, tmp_path):
    # Run the real script with its final exec turned into an echo, so we see the command it would start.
    script = (ROOT / "deploy" / "entrypoint.sh").read_text()
    script = script.replace("exec setpriv", "echo setpriv").replace("exec $cmd", "echo $cmd")
    out = subprocess.run(
        ["sh", "-c", script],
        capture_output=True,
        text=True,
        check=True,
        env={
            "PATH": "/usr/bin:/bin",
            "HOOKSCOPE_DB": str(tmp_path / "h.db"),
            "HOOKSCOPE_LOG_FORMAT": value,
        },
    ).stdout
    assert "uvicorn hookscope.main:app" in out
    assert ("--no-access-log" in out) is dropped
