import pytest

from hookscope import providers, rules, signatures
from hookscope.curl import build_curl
from hookscope.providers import PROVIDERS, Provider

EXPECTED = {"github", "stripe", "shopify", "slack", "twilio", "svix", "generic"}


def event(source, body="{}", headers=None):
    return {"id": 1, "source": source, "body": body, "headers": headers or {}, "received_at": "now"}


def test_every_provider_is_registered_under_its_own_name():
    assert set(PROVIDERS) == EXPECTED
    assert all(name == provider.name for name, provider in PROVIDERS.items())
    assert providers.get("github") is PROVIDERS["github"] and providers.get("nope") is None


def test_each_provider_verifies_with_its_own_function():
    for name in EXPECTED:
        assert PROVIDERS[name].verify is getattr(signatures, f"verify_{name}")


def test_only_twilio_signs_the_url():
    assert {name for name, p in PROVIDERS.items() if p.url_signed} == {"twilio"}


def test_verify_without_a_secret_says_so():
    result = providers.verify("github", b"{}", {}, None)
    assert result.status == "no_secret" and "github" in result.reason


def test_verify_passes_the_url_only_to_url_signed_providers():
    seen = {}

    def spy(body, headers, secret, url=None):
        seen["url"] = url
        return signatures.VerificationResult("valid")

    fake = {"a": Provider("a", spy, url_signed=True), "b": Provider("b", spy)}
    original = dict(PROVIDERS)
    PROVIDERS.update(fake)
    try:
        providers.verify("a", b"", {}, "s", "https://x.test/hooks/a")
        assert seen["url"] == "https://x.test/hooks/a"
        providers.verify("b", b"", {}, "s", "https://x.test/hooks/b")
        assert seen["url"] is None
    finally:
        PROVIDERS.clear()
        PROVIDERS.update(original)


@pytest.mark.parametrize(
    ("source", "headers", "body", "expected"),
    [
        ("github", {"X-GitHub-Event": "push"}, "{}", "push"),
        ("shopify", {"X-Shopify-Topic": "orders/create"}, "{}", "orders/create"),
        ("github", {}, "{}", None),
        ("stripe", {}, '{"type": "invoice.paid"}', "invoice.paid"),
        ("slack", {}, '{"type": "event_callback", "event": {"type": "app_mention"}}', "app_mention"),
        ("slack", {}, '{"type": "url_verification"}', "url_verification"),
        ("slack", {}, '{"type": "event_callback", "event": 5}', None),
        ("generic", {}, "not json", None),
    ],
)
def test_event_type_follows_the_providers_description(source, headers, body, expected):
    assert rules.event_type(event(source, body, headers)) == expected


def test_curl_notes_come_from_the_registry():
    timestamped = [("stripe", "Stripe-Signature"), ("slack", "X-Slack-Signature"), ("svix", "svix-signature")]
    for source, header in timestamped:
        assert f"{header} carries a timestamp" in build_curl(event(source), "http://h")
    assert "carries a timestamp" not in build_curl(event("github"), "http://h")
    assert "Twilio signs the full public URL" in build_curl(event("twilio"), "http://h")
    assert "Twilio" not in build_curl(event("generic"), "http://h")


def test_the_event_type_and_curl_code_no_longer_compare_source_names():
    from pathlib import Path

    for name in ("rules.py", "curl.py"):
        text = (Path(providers.__file__).parent / name).read_text()
        assert 'source"] ==' not in text and 'source ==' not in text, name


# ------------------------------------------------------------------------ delivery ids


@pytest.mark.parametrize(
    ("source", "headers", "body", "expected"),
    [
        ("github", {"X-GitHub-Delivery": "72d3162e-cc78"}, b"{}", "72d3162e-cc78"),
        ("shopify", {"x-shopify-webhook-id": "b54557e4-bdd9"}, b"{}", "b54557e4-bdd9"),
        ("svix", {"svix-id": "msg_2LJ"}, b"{}", "msg_2LJ"),
        ("twilio", {"I-Twilio-Idempotency-Token": "abc-123"}, b"a=1", "abc-123"),
        ("stripe", {}, b'{"id": "evt_1Qx", "type": "invoice.paid"}', "evt_1Qx"),
        ("slack", {}, b'{"type": "event_callback", "event_id": "Ev0PV52K21"}', "Ev0PV52K21"),
        ("github", {}, b"{}", None),  # no header
        ("stripe", {}, b"not json", None),
        ("stripe", {}, b'["evt_1"]', None),
        ("stripe", {}, b'{"id": 7}', None),  # not a string
        ("stripe", {}, b'{"id": "   "}', None),
        ("generic", {"X-Anything": "1"}, b'{"id": "x"}', None),  # nothing agreed to look at
        ("nope", {}, b"{}", None),
    ],
)
def test_delivery_id_is_read_where_the_provider_puts_it(source, headers, body, expected):
    assert providers.delivery_id(source, headers, body) == expected


def test_a_huge_delivery_id_is_clipped():
    assert len(providers.delivery_id("svix", {"svix-id": "x" * 5000}, b"")) == providers.MAX_DELIVERY_ID


def test_descriptions_say_where_things_are_read():
    assert PROVIDERS["github"].event_type_from == "header x-github-event"
    assert PROVIDERS["stripe"].event_type_from == "body type"
    assert PROVIDERS["slack"].event_type_from == (
        "body type, or the type inside 'event' when the outer type is 'event_callback'"
    )
    assert PROVIDERS["github"].delivery_id_from == "header x-github-delivery"
    assert PROVIDERS["stripe"].delivery_id_from == "body id"
    assert PROVIDERS["generic"].delivery_id_from is None
