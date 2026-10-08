import base64
import hashlib
import hmac
from urllib.parse import urlencode

import pytest

from hookscope.signatures import (
    verify,
    verify_github,
    verify_shopify,
    verify_slack,
    verify_stripe,
    verify_svix,
    verify_twilio,
)

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


# Test vectors from Twilio's request validation docs and libraries (auth token "12345").
TWILIO_TOKEN = "12345"
TWILIO_URL = "https://mycompany.com/myapp.php?foo=1&bar=2"
TWILIO_PARAMS = [
    ("CallSid", "CA1234567890ABCDE"),
    ("Caller", "+12349013030"),
    ("Digits", "1234"),
    ("From", "+12349013030"),
    ("To", "+18005551212"),
]
TWILIO_FORM = urlencode(TWILIO_PARAMS).encode()
TWILIO_JSON = b'{"property": "value", "boolean": true}'
TWILIO_JSON_URL = TWILIO_URL + "&bodySHA256=0a1ff7634d9ab3b95db5c9a2dfe9416e41502b283a80c7cf19632632f96e6620"


def test_twilio_form_params_valid():
    headers = {"X-Twilio-Signature": "0/KCTR6DLpKmkAf8muzZqo1nDgQ="}
    assert verify_twilio(TWILIO_FORM, headers, TWILIO_TOKEN, TWILIO_URL).status == "valid"


def test_twilio_param_order_does_not_matter():
    reordered = urlencode(list(reversed(TWILIO_PARAMS))).encode()
    headers = {"X-Twilio-Signature": "0/KCTR6DLpKmkAf8muzZqo1nDgQ="}
    assert verify_twilio(reordered, headers, TWILIO_TOKEN, TWILIO_URL).status == "valid"


def test_twilio_json_body_sha256_valid():
    headers = {"X-Twilio-Signature": "a9nBmqA0ju/hNViExpshrM61xv4="}
    assert verify_twilio(TWILIO_JSON, headers, TWILIO_TOKEN, TWILIO_JSON_URL).status == "valid"


def test_twilio_json_body_tampered():
    headers = {"X-Twilio-Signature": "a9nBmqA0ju/hNViExpshrM61xv4="}
    result = verify_twilio(b'{"property": "evil"}', headers, TWILIO_TOKEN, TWILIO_JSON_URL)
    assert result.status == "invalid"
    assert "bodySHA256" in result.reason


def test_twilio_wrong_url_is_rejected():
    headers = {"X-Twilio-Signature": "0/KCTR6DLpKmkAf8muzZqo1nDgQ="}
    result = verify_twilio(TWILIO_FORM, headers, TWILIO_TOKEN, "http://localhost:8000/hooks/twilio")
    assert result.status == "invalid"


def test_twilio_missing_header_and_url():
    assert verify_twilio(TWILIO_FORM, {}, TWILIO_TOKEN, TWILIO_URL).status == "unsigned"
    headers = {"X-Twilio-Signature": "0/KCTR6DLpKmkAf8muzZqo1nDgQ="}
    assert verify_twilio(TWILIO_FORM, headers, TWILIO_TOKEN).status == "invalid"


def test_verify_passes_url_to_twilio():
    headers = {"X-Twilio-Signature": "0/KCTR6DLpKmkAf8muzZqo1nDgQ="}
    assert verify("twilio", TWILIO_FORM, headers, TWILIO_TOKEN, url=TWILIO_URL).status == "valid"


# Example from the Svix docs ("Verifying webhooks manually").
SVIX_SECRET = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"
SVIX_BODY = b'{"test": 2432232314}'
SVIX_SIG = "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE="
SVIX_TS = 1614265330


def _svix_headers(signature: str = SVIX_SIG, prefix: str = "svix") -> dict:
    return {
        f"{prefix}-id": "msg_p5jXN8AQM9LWM0D4loKWxJek",
        f"{prefix}-timestamp": str(SVIX_TS),
        f"{prefix}-signature": signature,
    }


def test_svix_docs_example_is_valid():
    assert verify_svix(SVIX_BODY, _svix_headers(), SVIX_SECRET, now=SVIX_TS + 10).status == "valid"


def test_svix_standard_webhooks_header_names():
    headers = _svix_headers(prefix="webhook")
    assert verify_svix(SVIX_BODY, headers, SVIX_SECRET, now=SVIX_TS).status == "valid"


def test_svix_accepts_any_listed_signature():
    headers = _svix_headers(f"v1,bm90IGl0 v2,ignored {SVIX_SIG}")
    assert verify_svix(SVIX_BODY, headers, SVIX_SECRET, now=SVIX_TS).status == "valid"


def test_svix_tampered_body():
    result = verify_svix(b'{"test": 1}', _svix_headers(), SVIX_SECRET, now=SVIX_TS)
    assert result.status == "invalid"


def test_svix_rejects_old_timestamp():
    result = verify_svix(SVIX_BODY, _svix_headers(), SVIX_SECRET, now=SVIX_TS + 3600)
    assert result.status == "invalid"
    assert "tolerance" in result.reason


def test_svix_bad_secret_and_headers():
    assert verify_svix(SVIX_BODY, _svix_headers(), "whsec_not*base64", now=SVIX_TS).status == "invalid"
    headers = {"svix-signature": SVIX_SIG}
    assert verify_svix(SVIX_BODY, headers, SVIX_SECRET, now=SVIX_TS).status == "invalid"
    assert verify_svix(SVIX_BODY, {}, SVIX_SECRET).status == "unsigned"
