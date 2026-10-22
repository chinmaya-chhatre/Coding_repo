import hashlib
import hmac
import json
import logging

import pytest

from hookscope import diagnostics, providers
from hookscope.diagnostics import DETECTORS, Delivery, Diagnosis, detector, diagnose
from hookscope.providers import PROVIDERS
from hookscope.samples import build_sample
from hookscope.signatures import VerificationResult

SECRETS = {name: "sample-secret" for name in PROVIDERS} | {"svix": "whsec_ZGV2LXNlY3JldC1kZXYtc2VjcmV0"}


def delivery(status="invalid", source="github", reason="signature mismatch", **kwargs):
    return Delivery(
        source=source,
        body=kwargs.pop("body", b"{}"),
        headers=kwargs.pop("headers", {}),
        secret=kwargs.pop("secret", "s3cret"),
        url=kwargs.pop("url", "https://hooks.example.com/hooks/" + source),
        result=VerificationResult(status, reason),
        **kwargs,
    )


@pytest.mark.parametrize("status", ["valid", "no_secret"])
def test_only_rejected_deliveries_are_diagnosed(status):
    assert diagnose(delivery(status=status, reason="")) is None


@pytest.mark.parametrize("status", ["invalid", "unsigned"])
def test_rejected_deliveries_always_get_an_explanation(status):
    for source in PROVIDERS:
        found = diagnose(delivery(status=status, source=source))
        assert isinstance(found, Diagnosis) and found.cause and found.message and found.fix


def test_an_unknown_source_is_left_alone():
    assert diagnose(delivery(source="nope")) is None


@pytest.mark.parametrize("source", sorted(PROVIDERS))
def test_an_unsigned_delivery_names_the_missing_header(source):
    found = diagnose(delivery(status="unsigned", source=source, reason="missing header"))
    assert found.cause == "missing_signature"
    header = PROVIDERS[source].signature_header
    assert header in found.message and header in found.fix


def test_a_mismatch_with_no_known_cause_says_what_to_check():
    found = diagnose(delivery(source="stripe"))
    assert found.cause == "unexplained"
    assert "Stripe-Signature" in found.message and "HOOKSCOPE_SECRET_STRIPE" in found.fix
    assert "signature mismatch" in found.message


def test_the_secret_never_appears_in_a_diagnosis():
    found = diagnose(delivery(secret="hunter2-do-not-leak"))
    assert "hunter2" not in repr(found)


def test_every_provider_declares_its_signature_header():
    assert all(provider.signature_header for provider in PROVIDERS.values())


def test_diagnosis_serialises_to_plain_strings():
    found = Diagnosis("c", "m", "f")
    assert found.to_dict() == {"cause": "c", "message": "m", "fix": "f"}


def test_header_lookup_ignores_case():
    assert delivery(headers={"X-Hub-Signature-256": "x"}).header("x-hub-signature-256") == "x"
    assert delivery().header("x-missing") is None


# ---------------------------------------------------------------- the registry itself


@pytest.fixture
def isolated():
    saved = list(DETECTORS)
    DETECTORS.clear()
    yield
    DETECTORS[:] = saved


def test_the_first_detector_that_recognises_the_problem_wins(isolated):
    detector(lambda d: None)
    detector(lambda d: Diagnosis("first", "m", "f"))
    detector(lambda d: Diagnosis("second", "m", "f"))
    assert diagnose(delivery()).cause == "first"


def test_a_broken_detector_is_skipped_and_logged(isolated, caplog):
    def broken(d):
        raise RuntimeError("boom")

    detector(broken)
    detector(lambda d: Diagnosis("fallback", "m", "f"))
    with caplog.at_level(logging.ERROR, logger="hookscope.diagnostics"):
        assert diagnose(delivery()).cause == "fallback"
    assert "detector broken failed" in caplog.text


def test_with_no_detector_matching_there_is_no_diagnosis(isolated):
    detector(lambda d: None)
    assert diagnose(delivery()) is None


def test_the_general_fallback_runs_last():
    assert [d.__name__ for d in DETECTORS][-1] == "unexplained_mismatch"


# ------------------------------------------------------- with what the real verifiers report

URL = "https://hooks.example.com/x"


def received(source, body=None, drop=()):
    """A sample as it arrives, run through the real verifier, ready for ``diagnose``."""
    sample = build_sample(source, SECRETS[source], url=URL)
    body = sample.body if body is None else body
    headers = {k: v for k, v in sample.headers.items() if k.lower() not in drop}
    result = providers.verify(source, body, headers, SECRETS[source], url=URL)
    return Delivery(source, body, headers, SECRETS[source], URL, result)


@pytest.mark.parametrize("source", sorted(PROVIDERS))
def test_a_tampered_sample_is_explained(source):
    original = build_sample(source, SECRETS[source], url=URL).body
    arrived = received(source, body=original[::-1])  # different content, not just different encoding
    assert arrived.result.status == "invalid"
    assert diagnose(arrived).cause == "unexplained"


@pytest.mark.parametrize("source", sorted(PROVIDERS))
def test_a_sample_without_its_signature_is_explained(source):
    arrived = received(source, drop={PROVIDERS[source].signature_header.lower()})
    assert arrived.result.status == "unsigned"
    assert diagnose(arrived).cause == "missing_signature"


# ---------------------------------------------------------------- wrong provider

PAIRS = [(sent, to) for sent in sorted(PROVIDERS) for to in sorted(PROVIDERS) if sent != to]


def sent_to(source, to, headers=None):
    """A sample from ``source`` posted to ``/hooks/<to>``, as that endpoint's verifier sees it."""
    sample = build_sample(source, SECRETS[source], url=URL)
    headers = sample.headers if headers is None else headers
    url = f"https://hooks.example.com/hooks/{to}"
    result = providers.verify(to, sample.body, headers, SECRETS[to], url=url)
    return Delivery(to, sample.body, headers, SECRETS[to], url, result)


@pytest.mark.parametrize(("sent", "to"), PAIRS)
def test_every_provider_sent_to_every_other_endpoint_is_spotted(sent, to):
    arrived = sent_to(sent, to)
    assert arrived.result.status == "unsigned"
    found = diagnose(arrived)
    assert found.cause == "wrong_provider"
    assert f"came from {sent}" in found.message and f"/hooks/{to}" in found.message
    assert f"https://hooks.example.com/hooks/{sent}" in found.fix


def test_the_message_names_the_header_that_gave_it_away():
    found = diagnose(sent_to("github", "stripe"))
    assert "X-Hub-Signature-256" in found.message and "Stripe-Signature" in found.message


def test_an_event_header_alone_is_enough_evidence():
    headers = {"Content-Type": "application/json", "X-GitHub-Event": "push"}  # signing switched off
    found = diagnose(sent_to("github", "shopify", headers))
    assert found.cause == "wrong_provider" and "X-GitHub-Event" in found.message


def test_the_standard_webhooks_header_names_count_for_svix():
    headers = {"webhook-id": "msg_1", "webhook-timestamp": "1", "webhook-signature": "v1,abc"}
    found = diagnose(sent_to("svix", "github", headers))
    assert found.cause == "wrong_provider" and "came from svix" in found.message


def test_header_names_are_matched_without_regard_to_case():
    headers = {"x-hub-signature-256": "sha256=abc"}
    assert diagnose(sent_to("github", "stripe", headers)).cause == "wrong_provider"


def test_a_request_with_no_provider_headers_is_just_unsigned():
    found = diagnose(sent_to("github", "stripe", {"Content-Type": "application/json"}))
    assert found.cause == "missing_signature"


def test_a_bad_signature_of_the_right_kind_is_not_a_wrong_provider():
    arrived = received("github", body=b"{}")  # its own header, wrong content
    assert arrived.result.status == "invalid"
    assert diagnose(arrived).cause == "unexplained"


def test_a_url_without_a_hooks_path_still_gives_a_usable_fix():
    arrived = sent_to("github", "stripe")
    odd = Delivery(arrived.source, arrived.body, arrived.headers, "s", "http://x/y", arrived.result)
    assert "/hooks/github" in diagnose(odd).fix


def test_identifying_headers_are_lower_case_and_distinct_per_provider():
    seen = {}
    for name, provider in PROVIDERS.items():
        for header in provider.identifying_headers:
            assert header == header.lower()
            assert header not in seen, f"{header} identifies both {seen[header]} and {name}"
            seen[header] = name
    assert "webhook-signature" in PROVIDERS["svix"].identifying_headers


# ---------------------------------------------------------------- body changed in transit

BODY_JSON = {"id": 7, "name": "Zoë", "items": [1, 2], "a": {"z": 1, "b": 2}}
RAW = '{"id":7,"name":"Zoë","items":[1,2],"a":{"z":1,"b":2}}'.encode()  # as the provider sent it


def generic_arrival(received_body: bytes, signed_body: bytes = RAW):
    """A generic delivery signed over ``signed_body`` but received as ``received_body``."""
    secret = SECRETS["generic"]
    headers = {"X-Signature": hmac.new(secret.encode(), signed_body, hashlib.sha256).hexdigest()}
    result = providers.verify("generic", received_body, headers, secret)
    return Delivery("generic", received_body, headers, secret, "https://h.example/hooks/generic", result)


@pytest.mark.parametrize(
    ("label", "received_body"),
    [
        ("the body as compact JSON", json.dumps(BODY_JSON, indent=2, ensure_ascii=False).encode()),
        ("the body as compact JSON", json.dumps(BODY_JSON, indent=4, ensure_ascii=False).encode()),
        ("the body as compact JSON", json.dumps(BODY_JSON, ensure_ascii=False).encode()),
        ("the body as compact JSON", json.dumps(BODY_JSON, separators=(",", ":")).encode()),
        ("the body without its trailing newline", RAW + b"\n"),
        ("the body without its byte order mark (BOM)", b"\xef\xbb\xbf" + RAW),
        ("the body without surrounding whitespace", b"  " + RAW),
    ],
)
def test_a_re_encoded_body_is_recognised_and_the_change_named(label, received_body):
    arrived = generic_arrival(received_body)
    assert arrived.result.status == "invalid"
    found = diagnose(arrived)
    assert found.cause == "body_reencoded"
    assert label in found.message and "generic" in found.message
    assert "exact bytes" in found.fix


def test_sorted_keys_are_recognised():
    original = json.dumps(BODY_JSON, separators=(",", ":"), ensure_ascii=False, sort_keys=True).encode()
    reordered = json.dumps(BODY_JSON, separators=(",", ":"), ensure_ascii=False).encode()
    assert original != reordered
    found = diagnose(generic_arrival(reordered, signed_body=original))
    assert found.cause == "body_reencoded" and "JSON with sorted keys" in found.message


def test_line_endings_are_recognised_in_both_directions():
    multi = b'{\n  "a": 1,\n  "b": 2\n}'
    crlf = multi.replace(b"\n", b"\r\n")
    assert "LF line endings instead of CRLF" in diagnose(generic_arrival(crlf, multi)).message
    assert "CRLF line endings instead of LF" in diagnose(generic_arrival(multi, crlf)).message


def test_a_changed_value_is_not_blamed_on_encoding():
    changed = RAW.replace(b"7", b"8")
    assert diagnose(generic_arrival(changed)).cause == "unexplained"


def test_a_body_that_is_not_json_still_gets_the_byte_level_checks():
    signed = b"plain text payload"
    assert diagnose(generic_arrival(signed + b"\n", signed)).cause == "body_reencoded"
    assert diagnose(generic_arrival(b"something else", signed)).cause == "unexplained"


def test_a_form_body_from_twilio_with_an_added_newline():
    sample = build_sample("twilio", SECRETS["twilio"], url=URL)
    arrived = received("twilio", body=sample.body + b"\n")
    assert arrived.result.status == "invalid"
    assert diagnose(arrived).cause == "body_reencoded"


@pytest.mark.parametrize("source", ["github", "stripe", "shopify", "slack", "svix", "generic"])
def test_every_json_provider_is_covered(source):
    original = build_sample(source, SECRETS[source], url=URL).body
    pretty = json.dumps(json.loads(original), indent=2).encode()
    found = diagnose(received(source, body=pretty))
    assert found.cause == "body_reencoded"


def test_a_stale_stripe_timestamp_does_not_hide_a_re_encoded_body():
    sample = build_sample("stripe", SECRETS["stripe"], url=URL, now=1_000)
    body = json.dumps(json.loads(sample.body), indent=2).encode()
    result = providers.verify("stripe", body, sample.headers, SECRETS["stripe"], now=1_000)
    assert result.status == "invalid" and "signature mismatch" in result.reason
    arrived = Delivery("stripe", body, sample.headers, SECRETS["stripe"], URL, result, now=1_000)
    assert diagnose(arrived).cause == "body_reencoded"


def test_huge_bodies_are_not_re_verified():
    big = b'{"x": "' + b"a" * (diagnostics.MAX_VARIANT_BYTES + 1) + b'"}'
    assert diagnose(generic_arrival(big, b"anything")).cause == "unexplained"


def test_an_already_compact_body_offers_itself_as_a_variant_and_the_detector_skips_it():
    same = [what for what, variant in diagnostics.body_variants(RAW) if variant == RAW]
    assert same  # re-serialising compact JSON gives the same bytes: it must not count as a finding
    assert diagnose(generic_arrival(RAW.replace(b"7", b"8"))).cause == "unexplained"


def test_the_detector_sits_before_the_general_fallback():
    names = [d.__name__ for d in DETECTORS]
    assert names.index("body_changed_in_transit") < names.index("unexplained_mismatch")


# ---------------------------------------------------------------- stray characters in the secret

DIRTY = {
    "a trailing newline": (lambda s: s + "\n", "secret_whitespace"),
    "a trailing newline, CRLF": (lambda s: s + "\r\n", "secret_whitespace"),
    "leading or trailing whitespace": (lambda s: "  " + s + " ", "secret_whitespace"),
    "surrounding double quotes": (lambda s: f'"{s}"', "secret_quotes"),
    "surrounding single quotes": (lambda s: f"'{s}'", "secret_quotes"),
    "surrounding double quotes and whitespace": (lambda s: f' "{s}"\n', "secret_quotes"),
}


def with_configured_secret(source, configured):
    """A good delivery, checked by a HookScope whose configured secret is ``configured``."""
    sample = build_sample(source, SECRETS[source], url=URL)
    result = providers.verify(source, sample.body, sample.headers, configured, url=URL)
    return Delivery(source, sample.body, sample.headers, configured, URL, result)


@pytest.mark.parametrize("source", sorted(PROVIDERS))
@pytest.mark.parametrize("what", sorted(DIRTY))
def test_a_secret_with_stray_characters_is_recognised(source, what):
    dirty, cause = DIRTY[what]
    arrived = with_configured_secret(source, dirty(SECRETS[source]))
    assert arrived.result.status == "invalid"
    found = diagnose(arrived)
    assert found.cause == cause
    assert what.removesuffix(", CRLF") in found.message
    assert f"HOOKSCOPE_SECRET_{source.upper()}" in found.message and "bare secret" in found.fix


def test_the_diagnosis_never_contains_the_secret():
    secret = "very-private-value-123"
    sample = build_sample("github", secret, url=URL)
    result = providers.verify("github", sample.body, sample.headers, secret + "\n", url=URL)
    found = diagnose(Delivery("github", sample.body, sample.headers, secret + "\n", URL, result))
    assert found.cause == "secret_whitespace"
    assert "very-private" not in repr(found)


def test_a_genuinely_wrong_secret_is_not_blamed_on_whitespace():
    arrived = with_configured_secret("github", "an-entirely-different-secret\n")
    assert diagnose(arrived).cause == "unexplained"


def test_a_secret_that_is_only_quotes_or_blank_is_left_alone():
    for odd in ('""', "''", "   "):
        assert diagnose(with_configured_secret("github", odd)).cause == "unexplained"


def test_variants_of_a_clean_secret_are_empty():
    assert list(diagnostics.secret_variants("clean-secret")) == []


def test_a_secret_is_never_offered_twice():
    candidates = [c for _, _, c in diagnostics.secret_variants('  "abc"  ')]
    assert len(candidates) == len(set(candidates)) and "abc" in candidates


def test_the_secret_check_runs_before_the_body_check():
    names = [d.__name__ for d in DETECTORS]
    assert names.index("secret_has_stray_characters") < names.index("body_changed_in_transit")
