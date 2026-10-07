"""Signature verification for common webhook providers.

Each verifier takes the raw request body, the request headers and the shared
secret, and returns a ``VerificationResult``. Verifiers never raise on bad
input: a malformed header is reported as an invalid signature so the event can
still be stored and inspected.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from urllib.parse import parse_qs, parse_qsl, urlparse

STRIPE_TOLERANCE_SECONDS = 300
SLACK_TOLERANCE_SECONDS = 300


@dataclass(frozen=True)
class VerificationResult:
    status: str  # "valid" | "invalid" | "unsigned" | "no_secret"
    reason: str = ""

    @property
    def rejected(self) -> bool:
        return self.status in ("invalid", "unsigned")


def _hmac_sha256_hex(secret: str, payload: bytes) -> str:
    return hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()


def _get_header(headers: Mapping[str, str], name: str) -> str | None:
    name = name.lower()
    for key, value in headers.items():
        if key.lower() == name:
            return value
    return None


def verify_github(body: bytes, headers: Mapping[str, str], secret: str) -> VerificationResult:
    """GitHub: ``X-Hub-Signature-256: sha256=<hex hmac of body>``."""
    header = _get_header(headers, "X-Hub-Signature-256")
    if not header:
        return VerificationResult("unsigned", "missing X-Hub-Signature-256 header")
    scheme, _, received = header.partition("=")
    if scheme != "sha256" or not received:
        return VerificationResult("invalid", "expected format sha256=<hex>")
    expected = _hmac_sha256_hex(secret, body)
    if not hmac.compare_digest(expected, received):
        return VerificationResult("invalid", "signature mismatch")
    return VerificationResult("valid")


def verify_stripe(
    body: bytes,
    headers: Mapping[str, str],
    secret: str,
    now: float | None = None,
) -> VerificationResult:
    """Stripe: ``Stripe-Signature: t=<ts>,v1=<hex hmac of "ts.body">``."""
    header = _get_header(headers, "Stripe-Signature")
    if not header:
        return VerificationResult("unsigned", "missing Stripe-Signature header")

    timestamp = None
    signatures = []
    for part in header.split(","):
        key, _, value = part.strip().partition("=")
        if key == "t":
            timestamp = value
        elif key == "v1":
            signatures.append(value)
    if not timestamp or not timestamp.isdigit() or not signatures:
        return VerificationResult("invalid", "expected format t=<ts>,v1=<hex>")

    now = time.time() if now is None else now
    if abs(now - int(timestamp)) > STRIPE_TOLERANCE_SECONDS:
        return VerificationResult("invalid", "timestamp outside tolerance (possible replay)")

    expected = _hmac_sha256_hex(secret, timestamp.encode() + b"." + body)
    if not any(hmac.compare_digest(expected, sig) for sig in signatures):
        return VerificationResult("invalid", "signature mismatch")
    return VerificationResult("valid")


def verify_slack(
    body: bytes,
    headers: Mapping[str, str],
    secret: str,
    now: float | None = None,
) -> VerificationResult:
    """Slack: ``X-Slack-Signature: v0=<hex hmac of "v0:<ts>:body">`` plus ``X-Slack-Request-Timestamp``."""
    received = _get_header(headers, "X-Slack-Signature")
    timestamp = _get_header(headers, "X-Slack-Request-Timestamp")
    if not received:
        return VerificationResult("unsigned", "missing X-Slack-Signature header")
    version, _, digest = received.partition("=")
    if version != "v0" or not digest:
        return VerificationResult("invalid", "expected format v0=<hex>")
    if not timestamp or not timestamp.isdigit():
        return VerificationResult("invalid", "missing or malformed X-Slack-Request-Timestamp header")

    now = time.time() if now is None else now
    if abs(now - int(timestamp)) > SLACK_TOLERANCE_SECONDS:
        return VerificationResult("invalid", "timestamp outside tolerance (possible replay)")

    expected = _hmac_sha256_hex(secret, b"v0:" + timestamp.encode() + b":" + body)
    if not hmac.compare_digest(expected, digest):
        return VerificationResult("invalid", "signature mismatch")
    return VerificationResult("valid")


def verify_generic(body: bytes, headers: Mapping[str, str], secret: str) -> VerificationResult:
    """Generic: ``X-Signature: <hex hmac of body>``."""
    received = _get_header(headers, "X-Signature")
    if not received:
        return VerificationResult("unsigned", "missing X-Signature header")
    if not hmac.compare_digest(_hmac_sha256_hex(secret, body), received):
        return VerificationResult("invalid", "signature mismatch")
    return VerificationResult("valid")


def verify_shopify(body: bytes, headers: Mapping[str, str], secret: str) -> VerificationResult:
    """Shopify: ``X-Shopify-Hmac-Sha256: <base64 hmac of body>``."""
    received = _get_header(headers, "X-Shopify-Hmac-Sha256")
    if not received:
        return VerificationResult("unsigned", "missing X-Shopify-Hmac-Sha256 header")
    try:
        received_digest = base64.b64decode(received, validate=True)
    except (binascii.Error, ValueError):
        return VerificationResult("invalid", "expected a base64-encoded digest")
    expected = hmac.new(secret.encode(), body, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, received_digest):
        return VerificationResult("invalid", "signature mismatch")
    return VerificationResult("valid")


def verify_twilio(body: bytes, headers: Mapping[str, str], secret: str, url: str = "") -> VerificationResult:
    """Twilio: ``X-Twilio-Signature: <base64 HMAC-SHA1>`` of the full request URL plus the
    sorted form parameters. JSON requests instead carry ``bodySHA256`` in the URL query,
    so only the URL is signed and the body is checked against that hash."""
    received = _get_header(headers, "X-Twilio-Signature")
    if not received:
        return VerificationResult("unsigned", "missing X-Twilio-Signature header")
    if not url:
        return VerificationResult("invalid", "request URL unknown")

    body_hash = parse_qs(urlparse(url).query).get("bodySHA256")
    if body_hash:
        if not hmac.compare_digest(hashlib.sha256(body).hexdigest(), body_hash[0]):
            return VerificationResult("invalid", "body does not match bodySHA256")
        payload = url
    else:
        params = parse_qsl(body.decode("utf-8", errors="replace"), keep_blank_values=True)
        payload = url + "".join(key + value for key, value in sorted(params))

    digest = hmac.new(secret.encode(), payload.encode(), hashlib.sha1).digest()
    if not hmac.compare_digest(base64.b64encode(digest).decode(), received):
        return VerificationResult("invalid", "signature mismatch (check the public URL Twilio calls)")
    return VerificationResult("valid")


# Providers whose signature covers the request URL, so the verifier needs it.
URL_SIGNED = {"twilio"}

VERIFIERS: dict[str, Callable[..., VerificationResult]] = {
    "github": verify_github,
    "stripe": verify_stripe,
    "shopify": verify_shopify,
    "slack": verify_slack,
    "twilio": verify_twilio,
    "generic": verify_generic,
}


def verify(
    source: str, body: bytes, headers: Mapping[str, str], secret: str | None, url: str = ""
) -> VerificationResult:
    if not secret:
        return VerificationResult("no_secret", f"no secret configured for '{source}'")
    if source in URL_SIGNED:
        return VERIFIERS[source](body, headers, secret, url)
    return VERIFIERS[source](body, headers, secret)
