"""The portfolio demo (docs/demo) must stay in step with HookScope and with its built files."""

import importlib.util
import json
import re
from pathlib import Path
from urllib.parse import parse_qsl

import pytest

from hookscope import signatures

ROOT = Path(__file__).parent.parent
DEMO = ROOT / "docs" / "demo"
PROVIDERS = json.loads((DEMO / "src" / "providers.json").read_text(encoding="utf-8"))

_spec = importlib.util.spec_from_file_location("build_demo", ROOT / "scripts" / "build_demo.py")
build_demo = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(build_demo)


@pytest.fixture(scope="module")
def pages() -> dict[str, str]:
    return {name: (DEMO / "dist" / name).read_text(encoding="utf-8") for name in build_demo.OUTPUTS}


# ---------------------------------------------------------------- the data


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
        # Svix builds "<prefix>-signature" from a prefix, so match its suffix form there.
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


# ---------------------------------------------------------------- the built files


def test_dist_is_up_to_date_with_src():
    for name, text in build_demo.build().items():
        assert (DEMO / "dist" / name).read_text(encoding="utf-8") == text, (
            f"dist/{name} is stale: run python scripts/build_demo.py"
        )


@pytest.mark.parametrize("name", list(build_demo.OUTPUTS))
def test_each_output_is_one_self_contained_file(pages, name):
    html = pages[name]
    assert not re.findall(r'<script src="(?!/js/|/js/analytics)[^"]+"', html), "local scripts must be inlined"
    assert "{{" not in html
    assert 'id="providers"' in html and "HookScopeSigning" in html and 'id="hs-lab"' in html
    for provider in PROVIDERS:
        assert provider["label"] in html


def test_standalone_needs_nothing_from_the_portfolio(pages):
    html = pages["standalone.html"]
    external = re.findall(r'(?:src|href)="(https?://[^"]+)"', html)
    allowed = ("https://fonts.googleapis.com", "https://github.com/chinmaya-chhatre/")
    assert all(url.startswith(allowed) for url in external), external
    assert "<script src=" not in html and "/css/style.css" not in html
    assert 'id="theme"' in html and 'data-theme="dark"' in html and "prefers-reduced-motion" in html


def test_portfolio_page_uses_the_sites_shell(pages):
    html = pages["hookscope-demo.html"]
    for needle in (
        'href="/css/style.css"',
        'src="/js/analytics.js"',
        'src="/js/nav.js',
        'data-nav="auto"',
        'id="theme-toggle"',
        'rel="canonical" href="https://www.chinmaya-chhatre.com/playground/hookscope-demo.html"',
        'href="playground.html"',
    ):
        assert needle in html, needle
    assert "fonts.googleapis.com" not in html  # the site's stylesheet already loads its fonts
    assert 'id="theme"' not in html  # nav.js owns the theme toggle there
    assert ":root {" not in html  # no second set of tokens fighting the site's
    assert "cc-theme" not in html  # nav.js owns the stored theme


def test_lab_styles_are_scoped_so_they_cannot_leak_into_the_site():
    for line in (DEMO / "src" / "lab.css").read_text().splitlines():
        if "{" in line and not line.startswith(" ") and not line.startswith("@"):
            assert line.startswith("#hs-lab"), line
