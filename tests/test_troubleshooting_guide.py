import base64
import hashlib
import hmac
import json
import re

import pytest

from hookscope import providers, troubleshooting
from hookscope.diagnostics import CAUSE_HELP, DETECTORS, Delivery, diagnose
from hookscope.providers import PROVIDERS
from hookscope.samples import build_sample

NOW = 1_800_000_000
SECRETS = {name: "sample-secret" for name in PROVIDERS} | {"svix": "whsec_ZGV2LXNlY3JldC1kZXYtc2VjcmV0"}
URL = "https://hooks.example.com/hooks/twilio"


def delivery(source, headers, body, configured=None, url=URL, now=NOW):
    secret = configured or SECRETS[source]
    result = providers.verify(source, body, headers, secret, url=url, now=now)
    return Delivery(source, body, headers, secret, url, result, now=now)


def signed(source, when=NOW, secret=None, url=URL):
    sample = build_sample(source, secret or SECRETS[source], url=url, now=when)
    return sample.headers, sample.body


def stripe_with_secret(signing, configured):
    headers, body = signed("stripe", secret=signing)
    return delivery("stripe", headers, body, configured)


def case_missing_signature():
    headers, body = signed("github")
    return delivery("github", {k: v for k, v in headers.items() if k != "X-Hub-Signature-256"}, body)


def case_wrong_provider():
    headers, body = signed("github")
    return delivery("stripe", headers, body)


def case_wrong_scheme():
    headers, body = signed("generic")
    digest = hmac.new(b"k", body, hashlib.sha1).hexdigest()
    return delivery("generic", {**headers, "X-Signature": digest}, body)


def case_stale():
    headers, body = signed("stripe", when=NOW - 4_000)
    return delivery("stripe", headers, body)


def case_clock_ahead():
    headers, body = signed("stripe", when=NOW + 4_000)
    return delivery("stripe", headers, body)


def case_url():
    headers, body = signed("twilio", url=URL)
    return delivery("twilio", headers, body, url=URL.replace("https://", "http://"))


def case_whitespace():
    headers, body = signed("github")
    return delivery("github", headers, body, configured=SECRETS["github"] + "\n")


def case_quotes():
    headers, body = signed("github")
    return delivery("github", headers, body, configured=f'"{SECRETS["github"]}"')


def case_prefix():
    return stripe_with_secret("whsec_abc123", "abc123")


def case_encoding():
    key = b"secret-key-12"
    good = "whsec_" + base64.b64encode(key).decode()
    headers, body = signed("svix", secret=good)
    return delivery("svix", headers, body, configured=good.rstrip("="))


def case_svix_invalid():
    headers, body = signed("svix")
    return delivery("svix", headers, body, configured="whsec_!!not base64!!")


def case_body():
    headers, body = signed("generic")
    return delivery("generic", headers, json.dumps(json.loads(body), indent=2).encode())


def case_unexplained():
    headers, body = signed("github")
    return delivery("github", headers, body, configured="another-secret")


CASES = {
    "missing_signature": case_missing_signature,
    "wrong_provider": case_wrong_provider,
    "wrong_signature_scheme": case_wrong_scheme,
    "stale_timestamp": case_stale,
    "clock_ahead": case_clock_ahead,
    "url_mismatch": case_url,
    "secret_whitespace": case_whitespace,
    "secret_quotes": case_quotes,
    "secret_prefix": case_prefix,
    "secret_encoding": case_encoding,
    "svix_secret_invalid": case_svix_invalid,
    "body_reencoded": case_body,
    "unexplained": case_unexplained,
}


def declared_causes() -> list[str]:
    return [cause for detector in DETECTORS for cause in getattr(detector, "causes", ())]


def test_the_committed_guide_is_up_to_date():
    assert troubleshooting.GUIDE.read_text() == troubleshooting.render(), (
        "docs/troubleshooting.md is stale: run `python -m hookscope.troubleshooting`"
    )


def test_every_detector_declares_its_causes():
    for detector in DETECTORS:
        assert getattr(detector, "causes", ()), f"{detector.__name__} declares no causes (use @emits)"


def test_every_declared_cause_has_help_and_nothing_else_does():
    causes = declared_causes()
    assert len(causes) == len(set(causes)), "a cause is declared by two detectors"
    assert set(causes) == set(CAUSE_HELP)
    for title, meaning, fix in CAUSE_HELP.values():
        assert title and meaning and fix


@pytest.mark.parametrize("cause", sorted(CASES))
def test_each_declared_cause_is_really_reported_for_a_matching_delivery(cause):
    arrived = CASES[cause]()
    assert arrived.result.rejected
    assert diagnose(arrived).cause == cause


def test_the_cases_cover_every_declared_cause():
    assert set(CASES) == set(declared_causes())


def test_the_guide_mentions_every_cause_and_every_provider():
    text = troubleshooting.render()
    for cause in declared_causes():
        assert f"### `{cause}`" in text
    for name, provider in PROVIDERS.items():
        assert f"| `{name}` | `{provider.signature_header}` |" in text


def test_the_guide_lists_detectors_in_the_order_they_run():
    text = troubleshooting.render()
    order = [m.group(1) for m in re.finditer(r"^\| `\w+` \| `(\w+)` \|", text, re.M)]
    ran = [d.__name__ for d in DETECTORS for _ in getattr(d, "causes", ())]
    assert order[: len(ran)] == ran


def test_inline_code_in_summaries_is_markdown_not_restructuredtext():
    assert "``" not in troubleshooting.render()
