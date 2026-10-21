import logging

import pytest

from hookscope import providers
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
    arrived = received(source, body=build_sample(source, SECRETS[source], url=URL).body + b" ")
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
