import base64
import hashlib
import hmac

import pytest

from hookscope.signatures import verify, verify_github, verify_shopify, verify_slack, verify_stripe

SECRET = "s3cret"
BODY = b'{"hello": "world"}'


def _hex(payload: bytes) -> str:
    return hmac.new(SECRET.encode(), payload, hashlib.sha256).hexdigest()


def test_github_valid():
    headers = {"X-Hub-Signature-256": f"sha256={_hex(BODY)}"}
    assert verify_github(BODY, headers, SECRET).status == "valid"


def test_github_header_is_case_insensitive():
    headers = {"x-hub-signature-256": f"sha256={_hex(BODY)}"}
    assert verify_github(BODY, headers, SECRET).status == "valid"


def test_github_tampered_body():
    headers = {"X-Hub-Signature-256": f"sha256={_hex(BODY)}"}
    assert verify_github(b'{"hello": "evil"}', headers, SECRET).status == "invalid"


def test_github_missing_header():
    assert verify_github(BODY, {}, SECRET).status == "unsigned"


def test_stripe_valid():
    ts = "1700000000"
    headers = {"Stripe-Signature": f"t={ts},v1={_hex(ts.encode() + b'.' + BODY)}"}
    assert verify_stripe(BODY, headers, SECRET, now=1700000010).status == "valid"


def test_stripe_rejects_old_timestamp():
    ts = "1700000000"
    headers = {"Stripe-Signature": f"t={ts},v1={_hex(ts.encode() + b'.' + BODY)}"}
    result = verify_stripe(BODY, headers, SECRET, now=1700000000 + 3600)
    assert result.status == "invalid"
    assert "tolerance" in result.reason


def test_stripe_malformed_header():
    assert verify_stripe(BODY, {"Stripe-Signature": "garbage"}, SECRET).status == "invalid"


def test_no_secret_configured():
    assert verify("github", BODY, {}, None).status == "no_secret"


def _shopify_sig(payload: bytes) -> str:
    return base64.b64encode(hmac.new(SECRET.encode(), payload, hashlib.sha256).digest()).decode()


def test_shopify_valid():
    headers = {"X-Shopify-Hmac-Sha256": _shopify_sig(BODY)}
    assert verify_shopify(BODY, headers, SECRET).status == "valid"


def test_shopify_tampered_body():
    headers = {"X-Shopify-Hmac-Sha256": _shopify_sig(BODY)}
    assert verify_shopify(b'{"hello": "evil"}', headers, SECRET).status == "invalid"


def test_shopify_hex_digest_is_rejected():
    # Shopify sends base64; a hex digest (as GitHub uses) must not be accepted.
    headers = {"X-Shopify-Hmac-Sha256": _hex(BODY)}
    result = verify_shopify(BODY, headers, SECRET)
    assert result.status == "invalid"


def test_shopify_malformed_base64():
    result = verify_shopify(BODY, {"X-Shopify-Hmac-Sha256": "not base64!"}, SECRET)
    assert result.status == "invalid"
    assert "base64" in result.reason


def test_shopify_missing_header():
    assert verify_shopify(BODY, {}, SECRET).status == "unsigned"


def _slack_headers(ts: str, body: bytes = BODY) -> dict:
    signature = _hex(b"v0:" + ts.encode() + b":" + body)
    return {"X-Slack-Request-Timestamp": ts, "X-Slack-Signature": f"v0={signature}"}


def test_slack_valid():
    assert verify_slack(BODY, _slack_headers("1700000000"), SECRET, now=1700000030).status == "valid"


def test_slack_tampered_body():
    result = verify_slack(b'{"hello": "evil"}', _slack_headers("1700000000"), SECRET, now=1700000030)
    assert result.status == "invalid"


def test_slack_rejects_old_timestamp():
    result = verify_slack(BODY, _slack_headers("1700000000"), SECRET, now=1700000000 + 3600)
    assert result.status == "invalid"
    assert "tolerance" in result.reason


@pytest.mark.parametrize(
    "headers",
    [
        {"X-Slack-Signature": "v1=abc", "X-Slack-Request-Timestamp": "1700000000"},
        {"X-Slack-Signature": "v0=abc"},
        {"X-Slack-Signature": "v0=abc", "X-Slack-Request-Timestamp": "yesterday"},
    ],
)
def test_slack_malformed_headers(headers):
    assert verify_slack(BODY, headers, SECRET, now=1700000000).status == "invalid"


def test_slack_missing_signature():
    assert verify_slack(BODY, {"X-Slack-Request-Timestamp": "1700000000"}, SECRET).status == "unsigned"
