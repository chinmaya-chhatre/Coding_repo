import json

import pytest

from hookscope import providers
from hookscope.providers import PROVIDERS, delivery_id
from hookscope.samples import SampleError, build_sample

SECRETS = {name: "sample-secret" for name in PROVIDERS} | {"svix": "whsec_ZGV2LXNlY3JldC1kZXYtc2VjcmV0"}
URL = "https://hooks.example.com/hooks/twilio"


def sample_for(source, **kwargs):
    return build_sample(source, SECRETS[source], url=URL, **kwargs)


@pytest.mark.parametrize("source", sorted(PROVIDERS))
def test_every_sample_passes_its_providers_verifier(source):
    sample = sample_for(source)
    result = providers.verify(source, sample.body, sample.headers, SECRETS[source], url=URL)
    assert result.status == "valid", result.reason


@pytest.mark.parametrize("source", sorted(PROVIDERS))
def test_a_sample_fails_with_the_wrong_secret(source):
    sample = sample_for(source)
    wrong = "whsec_d3Jvbmctc2VjcmV0LXdyb25n" if source == "svix" else "not-the-secret"
    assert providers.verify(source, sample.body, sample.headers, wrong, url=URL).status == "invalid"


@pytest.mark.parametrize("source", sorted(PROVIDERS))
def test_a_tampered_sample_fails(source):
    sample = sample_for(source)
    tampered = sample.body + b" "
    assert providers.verify(source, tampered, sample.headers, SECRETS[source], url=URL).status == "invalid"


@pytest.mark.parametrize("source", ["stripe", "slack", "svix"])
def test_timestamped_samples_go_stale(source):
    old = sample_for(source, now=1_000)
    assert providers.verify(source, old.body, old.headers, SECRETS[source]).reason.startswith("timestamp")


def test_twilio_signs_the_url_it_will_be_posted_to():
    sample = sample_for("twilio")
    other = "https://hooks.example.com/other"
    result = providers.verify("twilio", sample.body, sample.headers, SECRETS["twilio"], url=other)
    assert result.status == "invalid"
    with pytest.raises(SampleError, match="URL"):
        build_sample("twilio", "s")


def test_svix_needs_a_real_whsec_key():
    with pytest.raises(SampleError, match="whsec_"):
        build_sample("svix", "dev-secret")


def test_unknown_provider():
    with pytest.raises(SampleError):
        build_sample("nope", "s")


@pytest.mark.parametrize("source", sorted(PROVIDERS))
def test_every_sample_declares_a_content_type(source):
    content_type = sample_for(source).headers["Content-Type"]
    assert content_type in ("application/json", "application/x-www-form-urlencoded")


@pytest.mark.parametrize("source", ["github", "stripe", "shopify", "slack", "twilio", "svix"])
def test_samples_carry_a_delivery_id_the_registry_can_read(source):
    sample = sample_for(source)
    assert delivery_id(source, sample.headers, sample.body)


def test_event_types_are_what_forwarding_rules_match_on():
    from hookscope.rules import event_type

    def type_of(source):
        sample = sample_for(source)
        event = {"source": source, "body": sample.body.decode(), "headers": sample.headers}
        return event_type(event)

    assert type_of("github") == "pull_request"
    assert type_of("shopify") == "orders/create"
    assert type_of("stripe") == "invoice.paid"
    assert type_of("slack") == "app_mention"
    assert json.loads(sample_for("stripe").body)["id"].startswith("evt_sample_")
