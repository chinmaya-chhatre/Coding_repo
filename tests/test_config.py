import subprocess
import sys
from pathlib import Path

import pytest

from hookscope.config import DEFAULT_DB_PATH, DEFAULT_MAX_BODY_BYTES, ConfigError, Settings
from hookscope.main import create_app
from hookscope.retention import RetentionPolicy
from hookscope.store import EventStore

ROOT = Path(__file__).resolve().parent.parent


def test_defaults_from_an_empty_environment():
    settings = Settings.from_env({})
    assert settings.db_path == DEFAULT_DB_PATH
    assert settings.rules_path is None
    assert settings.max_body_bytes == DEFAULT_MAX_BODY_BYTES
    assert settings.retention == RetentionPolicy()
    assert settings.secrets == {}
    assert settings.admin_password is None


def test_every_setting_is_read():
    settings = Settings.from_env(
        {
            "HOOKSCOPE_DB": "/data/events.db",
            "HOOKSCOPE_RULES": "/etc/hookscope/rules.json",
            "HOOKSCOPE_MAX_BODY_BYTES": "2048",
            "HOOKSCOPE_RETENTION_DAYS": "7",
            "HOOKSCOPE_MAX_EVENTS": "500",
            "HOOKSCOPE_PURGE_INTERVAL_SECONDS": "60",
            "HOOKSCOPE_ADMIN_PASSWORD": "hunter2-long",
            "HOOKSCOPE_SECRET_GITHUB": "gh-secret",
            "HOOKSCOPE_SECRET_STRIPE": "whsec_abc",
            "HOOKSCOPE_SECRET_TWILIO": "",
            "HOOKSCOPE_SECRET_UNKNOWN": "ignored",
        }
    )
    assert settings.db_path == "/data/events.db"
    assert settings.rules_path == "/etc/hookscope/rules.json"
    assert settings.max_body_bytes == 2048
    assert settings.retention == RetentionPolicy(max_age_days=7.0, max_events=500, interval_seconds=60.0)
    assert settings.admin_password == "hunter2-long"
    # Empty values and unknown sources are not secrets.
    assert settings.secrets == {"github": "gh-secret", "stripe": "whsec_abc"}


def test_blank_values_fall_back_to_defaults():
    blank = {"HOOKSCOPE_DB": "  ", "HOOKSCOPE_RULES": "", "HOOKSCOPE_ADMIN_PASSWORD": " "}
    settings = Settings.from_env(blank)
    assert settings.db_path == DEFAULT_DB_PATH and settings.rules_path is None
    assert settings.admin_password is None


def test_all_invalid_values_are_reported_together():
    with pytest.raises(ConfigError) as caught:
        Settings.from_env(
            {
                "HOOKSCOPE_MAX_BODY_BYTES": "lots",
                "HOOKSCOPE_RETENTION_DAYS": "a week",
                "HOOKSCOPE_MAX_EVENTS": "0",
            }
        )
    error = caught.value
    assert isinstance(error, ValueError)
    assert len(error.errors) == 2  # one for the body limit, one for the retention settings
    message = str(error)
    for name in ("HOOKSCOPE_MAX_BODY_BYTES", "HOOKSCOPE_RETENTION_DAYS", "HOOKSCOPE_MAX_EVENTS"):
        assert name in message
    assert message.startswith("invalid configuration:")


def test_secrets_are_not_in_repr():
    settings = Settings.from_env(
        {"HOOKSCOPE_ADMIN_PASSWORD": "super-secret-pw", "HOOKSCOPE_SECRET_GITHUB": "gh-secret-value"}
    )
    text = repr(settings)
    assert "super-secret-pw" not in text and "gh-secret-value" not in text
    assert "db_path" in text


def test_create_app_uses_settings_from_the_environment(tmp_path, monkeypatch):
    db = tmp_path / "from-env.db"
    monkeypatch.setenv("HOOKSCOPE_DB", str(db))
    create_app(secrets={})
    assert db.exists()


def test_explicit_arguments_win_over_the_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("HOOKSCOPE_DB", str(tmp_path / "ignored.db"))
    store = EventStore(str(tmp_path / "explicit.db"))
    create_app(store=store, secrets={}, rules=[])
    assert not (tmp_path / "ignored.db").exists()


def test_create_app_fails_on_invalid_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("HOOKSCOPE_MAX_BODY_BYTES", "-1")
    monkeypatch.setenv("HOOKSCOPE_MAX_EVENTS", "many")
    with pytest.raises(ConfigError, match="HOOKSCOPE_MAX_BODY_BYTES") as caught:
        create_app(store=EventStore(str(tmp_path / "bad.db")), secrets={})
    assert "HOOKSCOPE_MAX_EVENTS" in str(caught.value)


def test_importing_the_app_module_reports_every_problem():
    env = {
        "PATH": "/usr/bin:/bin",
        "HOOKSCOPE_DB": ":memory:",
        "HOOKSCOPE_MAX_BODY_BYTES": "zero",
        "HOOKSCOPE_RETENTION_DAYS": "never",
    }
    result = subprocess.run(
        [sys.executable, "-c", "import hookscope.main"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "invalid configuration" in result.stderr
    assert "HOOKSCOPE_MAX_BODY_BYTES" in result.stderr and "HOOKSCOPE_RETENTION_DAYS" in result.stderr
