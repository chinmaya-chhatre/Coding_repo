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
