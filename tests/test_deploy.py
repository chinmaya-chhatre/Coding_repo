"""Keep the deployment files consistent with the app they deploy."""

import re
import subprocess
import tomllib
from pathlib import Path

import yaml
from fastapi.testclient import TestClient

from hookscope.main import create_app
from hookscope.retention import RetentionPolicy
from hookscope.store import EventStore

ROOT = Path(__file__).resolve().parent.parent


def _fly() -> dict:
    return tomllib.loads((ROOT / "fly.toml").read_text())


def _dockerfile() -> str:
    return (ROOT / "Dockerfile").read_text()


def _entrypoint() -> str:
    return (ROOT / "deploy" / "entrypoint.sh").read_text()


def _render_service() -> dict:
    return yaml.safe_load((ROOT / "render.yaml").read_text())["services"][0]


def _render_env() -> dict[str, dict]:
    return {var["key"]: var for var in _render_service()["envVars"]}


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


def test_entrypoint_trusts_proxy_headers_and_uses_port():
    script = _entrypoint()
    assert "--proxy-headers" in script and "${PORT:-8000}" in script
    # Without -f, the unquoted "*" would glob-expand against files in the working dir.
    assert re.search(r"^set -e?f", script, re.M)
    assert "setpriv --reuid=hookscope" in script
    assert 'ENTRYPOINT ["hookscope-entrypoint"]' in _dockerfile()
    assert "COPY deploy/entrypoint.sh /usr/local/bin/hookscope-entrypoint" in _dockerfile()


def test_entrypoint_is_valid_shell():
    subprocess.run(["sh", "-n", str(ROOT / "deploy" / "entrypoint.sh")], check=True)


def test_render_disk_holds_the_database():
    service = _render_service()
    assert service["runtime"] == "docker"
    assert Path(_render_env()["HOOKSCOPE_DB"]["value"]).parent == Path(service["disk"]["mountPath"])


def test_render_health_check_is_served(tmp_path):
    client = TestClient(create_app(store=EventStore(str(tmp_path / "r.db")), secrets={}))
    assert client.get(_render_service()["healthCheckPath"]).status_code == 200


def test_render_secrets_are_not_committed_and_retention_is_valid():
    env = _render_env()
    for key, var in env.items():
        if key.startswith("HOOKSCOPE_SECRET_"):
            assert var.get("sync") is False and "value" not in var, key
    plain = {key: var["value"] for key, var in env.items() if "value" in var}
    assert RetentionPolicy.from_env(plain).enabled
