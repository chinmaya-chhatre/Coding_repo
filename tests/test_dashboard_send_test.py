import re

import pytest
from fastapi.testclient import TestClient

from hookscope.main import create_app
from hookscope.providers import PROVIDERS
from hookscope.store import EventStore


def dashboard(tmp_path, secrets):
    app = create_app(store=EventStore(str(tmp_path / "d.db")), secrets=secrets, admin_password=None)
    return TestClient(app).get("/")


def options(html: str) -> dict[str, str]:
    """Each provider option's value mapped to its other attributes (``disabled`` when it cannot be chosen)."""
    block = re.search(r'<select name="provider">(.*?)</select>', html, re.S).group(1)
    return {value: attrs.strip() for value, attrs in re.findall(r'<option value="([^"]+)"([^>]*)>', block)}


def test_the_panel_lists_every_provider(tmp_path):
    html = dashboard(tmp_path, {"github": "s"}).text
    assert 'class="sendtest"' in html and "Send a test event" in html
    assert list(options(html)) == sorted(PROVIDERS)


def test_providers_without_a_secret_cannot_be_chosen(tmp_path):
    html = dashboard(tmp_path, {"github": "s", "stripe": "s"}).text
    attrs = options(html)
    assert "disabled" not in attrs["github"] and "disabled" not in attrs["stripe"]
    assert all("disabled" in attrs[name] for name in PROVIDERS if name not in ("github", "stripe"))
    assert "twilio (secret not set)" in html


def test_without_any_secret_the_button_is_off_and_the_page_says_why(tmp_path):
    html = dashboard(tmp_path, {}).text
    form = re.search(r'<form class="sendtest-form">.*?</form>', html, re.S).group(0)
    assert re.search(r"<button type=\"submit\"\s+disabled", form)
    assert "HOOKSCOPE_SECRET_" in form


def test_the_script_calls_the_test_endpoint(tmp_path):
    html = dashboard(tmp_path, {"github": "s"}).text
    assert "/api/providers/${encodeURIComponent(select.value)}/test" in html


@pytest.mark.parametrize("name", ["github", "stripe", "slack"])
def test_what_the_button_does_works_end_to_end(tmp_path, name):
    app = create_app(store=EventStore(str(tmp_path / "e.db")), secrets={name: "s"}, admin_password=None)
    client = TestClient(app)
    assert client.post(f"/api/providers/{name}/test").status_code == 202
    page = client.get("/").text
    assert "<strong>#1</strong>" in page and "valid" in page
