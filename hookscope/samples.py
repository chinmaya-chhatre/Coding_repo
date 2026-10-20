"""A correctly signed example delivery for each provider.

Used for "send a test": the sample is signed with the provider's configured secret exactly the way the
provider would sign it, so it passes that provider's verifier (the tests check every provider this way).
It does not claim to be a real event from the provider, only to be shaped like one.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from urllib.parse import urlencode

from . import signatures

JSON = "application/json"
FORM = "application/x-www-form-urlencoded"


class SampleError(ValueError):
    """The sample cannot be signed with the secret that is configured."""


@dataclass(frozen=True)
class Sample:
    body: bytes
    headers: dict[str, str]  # includes Content-Type


def _hex(secret: str, payload: bytes) -> str:
    return hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()


def _json(payload: dict) -> bytes:
    return json.dumps(payload, separators=(",", ":")).encode()


def build_sample(source: str, secret: str, url: str = "", now: float | None = None) -> Sample:
    """Sign a sample for ``source``; ``url`` is where it will be posted (Twilio signs the URL)."""
    if source not in _BUILDERS:
        raise SampleError(f"no sample for {source!r}")
    moment = time.time() if now is None else now
    return _BUILDERS[source](secret, url, int(moment))


def _github(secret: str, url: str, now: int) -> Sample:
    body = _json({"action": "opened", "pull_request": {"number": 42, "title": "Add retry logic"}})
    return Sample(
        body,
        {
            "Content-Type": JSON,
            "X-GitHub-Event": "pull_request",
            "X-GitHub-Delivery": f"sample-{now}",
            "X-Hub-Signature-256": f"sha256={_hex(secret, body)}",
        },
    )


def _stripe(secret: str, url: str, now: int) -> Sample:
    body = _json(
        {
            "id": f"evt_sample_{now}",
            "object": "event",
            "type": "invoice.paid",
            "created": now,
            "data": {"object": {"id": "in_sample", "amount_paid": 4900, "currency": "usd"}},
        }
    )
    stamp = str(now)
    signature = _hex(secret, stamp.encode() + b"." + body)
    return Sample(body, {"Content-Type": JSON, "Stripe-Signature": f"t={stamp},v1={signature}"})


def _shopify(secret: str, url: str, now: int) -> Sample:
    body = _json({"id": 820982911946154508, "email": "jon@example.com", "total_price": "49.00"})
    digest = base64.b64encode(hmac.new(secret.encode(), body, hashlib.sha256).digest()).decode()
    return Sample(
        body,
        {
            "Content-Type": JSON,
            "X-Shopify-Topic": "orders/create",
            "X-Shopify-Webhook-Id": f"sample-{now}",
            "X-Shopify-Hmac-Sha256": digest,
        },
    )


def _slack(secret: str, url: str, now: int) -> Sample:
    body = _json(
        {
            "type": "event_callback",
            "event_id": f"EvSample{now}",
            "event": {"type": "app_mention", "text": "<@U123> deploy status?"},
        }
    )
    stamp = str(now)
    signature = _hex(secret, b"v0:" + stamp.encode() + b":" + body)
    return Sample(
        body,
        {"Content-Type": JSON, "X-Slack-Request-Timestamp": stamp, "X-Slack-Signature": f"v0={signature}"},
    )


def _twilio(secret: str, url: str, now: int) -> Sample:
    if not url:
        raise SampleError("Twilio signs the request URL, so the URL is needed")
    params = {"MessageSid": "SMsample", "From": "+15551230000", "To": "+15559870000", "Body": "STATUS"}
    signed = url + "".join(key + value for key, value in sorted(params.items()))
    digest = base64.b64encode(hmac.new(secret.encode(), signed.encode(), hashlib.sha1).digest()).decode()
    return Sample(
        urlencode(params).encode(),
        {
            "Content-Type": FORM,
            "I-Twilio-Idempotency-Token": f"sample-{now}",
            "X-Twilio-Signature": digest,
        },
    )


def _svix(secret: str, url: str, now: int) -> Sample:
    key = signatures._svix_key(secret)
    if key is None:
        raise SampleError("the configured secret is not a valid whsec_ key (whsec_ followed by base64)")
    body = _json({"type": "invoice.paid", "data": {"id": "inv_42", "amount": 4900}})
    msg_id, stamp = f"msg_sample_{now}", str(now)
    mac = hmac.new(key, f"{msg_id}.{stamp}.".encode() + body, hashlib.sha256).digest()
    return Sample(
        body,
        {
            "Content-Type": JSON,
            "svix-id": msg_id,
            "svix-timestamp": stamp,
            "svix-signature": f"v1,{base64.b64encode(mac).decode()}",
        },
    )


def _generic(secret: str, url: str, now: int) -> Sample:
    body = _json({"event": "user.signup", "user": {"id": 7, "plan": "pro"}})
    return Sample(body, {"Content-Type": JSON, "X-Signature": _hex(secret, body)})


_BUILDERS = {
    "github": _github,
    "stripe": _stripe,
    "shopify": _shopify,
    "slack": _slack,
    "twilio": _twilio,
    "svix": _svix,
    "generic": _generic,
}
