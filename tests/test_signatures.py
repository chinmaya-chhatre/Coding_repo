import hashlib
import hmac

from hookscope.signatures import verify, verify_github, verify_stripe

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
