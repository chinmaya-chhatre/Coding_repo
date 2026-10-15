"""The portfolio demo page (docs/demo/index.html) must stay in step with the real verifiers."""

import json
import re
from pathlib import Path
from urllib.parse import parse_qsl

import pytest

from hookscope import signatures

PAGE = Path(__file__).parent.parent / "docs" / "demo" / "index.html"
HTML = PAGE.read_text(encoding="utf-8")


def _providers() -> list[dict]:
    match = re.search(r'<script type="application/json" id="providers">(.*?)</script>', HTML, re.S)
    assert match, "providers data block missing"
    return json.loads(match.group(1))


PROVIDERS = _providers()


def test_demo_covers_every_provider_hookscope_verifies():
    assert {p["id"] for p in PROVIDERS} == set(signatures.VERIFIERS)


def test_every_provider_has_what_the_page_renders():
    for p in PROVIDERS:
        required = ("id", "label", "method", "path", "contentType", "secret")
        for key in (*required, "signatureHeaders", "how", "body"):
            assert p.get(key), f"{p['id']} is missing {key}"
        assert p["path"] == f"/hooks/{p['id']}"


@pytest.mark.parametrize("provider", PROVIDERS, ids=lambda p: p["id"])
def test_signature_headers_are_the_ones_the_verifier_reads(provider):
    source = Path(signatures.__file__).read_text()
    for header in provider["signatureHeaders"]:
        # Svix reads "<prefix>-signature" built from a prefix, so match its suffix form there.
        needle = header.split("-", 1)[1] if provider["id"] == "svix" else header
        assert needle in source, f"{header} is not read by the {provider['id']} verifier"


@pytest.mark.parametrize("provider", PROVIDERS, ids=lambda p: p["id"])
def test_sample_bodies_parse_as_their_content_type(provider):
    if provider["contentType"] == "application/json":
        assert isinstance(json.loads(provider["body"]), dict)
    else:
        assert provider["contentType"] == "application/x-www-form-urlencoded"
        assert parse_qsl(provider["body"], strict_parsing=True)


def test_twilio_sample_carries_the_url_that_gets_signed():
    twilio = next(p for p in PROVIDERS if p["id"] == "twilio")
    assert twilio["url"].startswith("https://")


def test_page_is_self_contained_apart_from_fonts():
    external = re.findall(r'(?:src|href)="(https?://[^"]+)"', HTML)
    allowed = ("https://fonts.googleapis.com", "https://github.com/chinmaya-chhatre/")
    assert all(url.startswith(allowed) for url in external), external
    assert re.findall(r'<script src="([^"]+)"', HTML) == [
        "signing.js"
    ]  # one local script, nothing third-party


def test_page_has_the_basics_for_embedding():
    assert '<html lang="en"' in HTML and 'name="viewport"' in HTML
    assert 'data-theme="dark"' in HTML  # dark theme tokens, matching the portfolio
    assert "prefers-reduced-motion" in HTML
