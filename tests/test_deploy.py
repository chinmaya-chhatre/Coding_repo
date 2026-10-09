"""Keep the deployment files consistent with the app they deploy."""

import re
import tomllib
from pathlib import Path

from fastapi.testclient import TestClient

from hookscope.main import create_app
from hookscope.retention import RetentionPolicy
from hookscope.store import EventStore

ROOT = Path(__file__).resolve().parent.parent


def _fly() -> dict:
    return tomllib.loads((ROOT / "fly.toml").read_text())


def _dockerfile() -> str:
    return (ROOT / "Dockerfile").read_text()


def test_fly_port_matches_dockerfile():
    exposed = re.search(r"^EXPOSE (\d+)", _dockerfile(), re.M)
    default_port = re.search(r"PORT=(\d+)", _dockerfile())
    assert exposed and default_port
    assert _fly()["http_service"]["internal_port"] == int(exposed.group(1)) == int(default_port.group(1))


def test_fly_database_lives_on_the_mounted_volume():
    fly = _fly()
    mount = fly["mounts"][0]["destination"]
    assert Path(fly["env"]["HOOKSCOPE_DB"]).parent == Path(mount)
    assert f"HOOKSCOPE_DB={mount}/" in _dockerfile()


def test_fly_health_check_path_is_served(tmp_path):
    path = _fly()["http_service"]["checks"][0]["path"]
    client = TestClient(create_app(store=EventStore(str(tmp_path / "h.db")), secrets={}))
    assert client.get(path).status_code == 200


def test_fly_retention_settings_are_valid():
    policy = RetentionPolicy.from_env(_fly()["env"])
    assert policy.enabled


def test_dockerfile_trusts_proxy_headers_and_uses_port():
    cmd = _dockerfile().split("CMD", 1)[1]
    assert "--proxy-headers" in cmd and "${PORT}" in cmd
