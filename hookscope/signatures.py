"""Signature verification for common webhook providers.

Each verifier takes the raw request body, the request headers and the shared
secret, and returns a ``VerificationResult``. Verifiers never raise on bad
input: a malformed header is reported as an invalid signature so the event can
still be stored and inspected.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass

STRIPE_TOLERANCE_SECONDS = 300


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


def verify_generic(body: bytes, headers: Mapping[str, str], secret: str) -> VerificationResult:
    """Generic: ``X-Signature: <hex hmac of body>``."""
    received = _get_header(headers, "X-Signature")
    if not received:
        return VerificationResult("unsigned", "missing X-Signature header")
    if not hmac.compare_digest(_hmac_sha256_hex(secret, body), received):
        return VerificationResult("invalid", "signature mismatch")
    return VerificationResult("valid")


VERIFIERS: dict[str, Callable[[bytes, Mapping[str, str], str], VerificationResult]] = {
    "github": verify_github,
    "stripe": verify_stripe,
    "generic": verify_generic,
}


def verify(source: str, body: bytes, headers: Mapping[str, str], secret: str | None) -> VerificationResult:
    if not secret:
        return VerificationResult("no_secret", f"no secret configured for '{source}'")
    return VERIFIERS[source](body, headers, secret)
