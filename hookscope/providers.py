"""The providers HookScope knows, each described once.

Everything that differs between providers lives on one ``Provider`` object: how to verify the
signature, whether the signature covers the request URL, where the event type is found, and what to
tell someone replaying a request. Code elsewhere asks the registry instead of comparing a source name,
so supporting a new provider means adding one entry here.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from . import signatures
from .signatures import VerificationResult


@dataclass(frozen=True)
class Provider:
    name: str
    verify: Callable[..., VerificationResult]
    # The header the signature travels in, as the provider documents it (for messages to people).
    signature_header: str = ""
    # The signature covers the public URL, so ``verify`` also needs it.
    url_signed: bool = False
    # The signature header whose value carries a timestamp, if the provider rejects stale requests.
    timestamp_header: str | None = None
    # Header holding the event type (lower case), when the provider does not put it in the body.
    event_type_header: str | None = None
    # (outer type, key) when an outer envelope wraps the real event, as Slack's ``event_callback`` does.
    event_envelope: tuple[str, str] | None = None
    # Where the provider's own id for this delivery is, for matching an event to the provider's
    # dashboard or logs: a header (lower case), or a key of the JSON body.
    delivery_id_header: str | None = None
    delivery_id_key: str | None = None
    # Extra advice shown above a rebuilt curl command.
    replay_note: str = ""

    @property
    def event_type_from(self) -> str:
        """Where the event type is found, in words."""
        if self.event_type_header:
            return f"header {self.event_type_header}"
        if self.event_envelope:
            outer, key = self.event_envelope
            return f"body type, or the type inside '{key}' when the outer type is '{outer}'"
        return "body type"

    @property
    def delivery_id_from(self) -> str | None:
        if self.delivery_id_header:
            return f"header {self.delivery_id_header}"
        if self.delivery_id_key:
            return f"body {self.delivery_id_key}"
        return None


PROVIDERS: dict[str, Provider] = {
    provider.name: provider
    for provider in (
        Provider(
            "github",
            signatures.verify_github,
            signature_header="X-Hub-Signature-256",
            event_type_header="x-github-event",
            delivery_id_header="x-github-delivery",
        ),
        Provider(
            "stripe",
            signatures.verify_stripe,
            signature_header="Stripe-Signature",
            timestamp_header="Stripe-Signature",
            delivery_id_key="id",
        ),
        Provider(
            "shopify",
            signatures.verify_shopify,
            signature_header="X-Shopify-Hmac-Sha256",
            event_type_header="x-shopify-topic",
            delivery_id_header="x-shopify-webhook-id",
        ),
        Provider(
            "slack",
            signatures.verify_slack,
            signature_header="X-Slack-Signature",
            timestamp_header="X-Slack-Signature",
            event_envelope=("event_callback", "event"),
            delivery_id_key="event_id",
        ),
        Provider(
            "twilio",
            signatures.verify_twilio,
            signature_header="X-Twilio-Signature",
            url_signed=True,
            delivery_id_header="i-twilio-idempotency-token",
            replay_note=(
                "Twilio signs the full public URL: use the URL Twilio was configured with, not this one."
            ),
        ),
        Provider(
            "svix",
            signatures.verify_svix,
            signature_header="svix-signature",
            timestamp_header="svix-signature",
            delivery_id_header="svix-id",
        ),
        Provider("generic", signatures.verify_generic, signature_header="X-Signature"),
    )
}


MAX_DELIVERY_ID = 128


def delivery_id(source: str, headers: Mapping[str, str], body: bytes) -> str | None:
    """The provider's own id for this delivery (``X-GitHub-Delivery``, a Stripe ``evt_...``), if sent."""
    provider = PROVIDERS.get(source)
    if provider is None:
        return None
    value: object = None
    if provider.delivery_id_header:
        value = next((v for k, v in headers.items() if k.lower() == provider.delivery_id_header), None)
    elif provider.delivery_id_key:
        try:
            payload = json.loads(body)
        except ValueError:
            return None
        value = payload.get(provider.delivery_id_key) if isinstance(payload, dict) else None
    if not isinstance(value, str) or not value.strip():
        return None
    return value.strip()[:MAX_DELIVERY_ID]


def get(source: str) -> Provider | None:
    return PROVIDERS.get(source)


def verify(
    source: str, body: bytes, headers: Mapping[str, str], secret: str | None, url: str = ""
) -> VerificationResult:
    if not secret:
        return VerificationResult("no_secret", f"no secret configured for '{source}'")
    provider = PROVIDERS[source]
    if provider.url_signed:
        return provider.verify(body, headers, secret, url)
    return provider.verify(body, headers, secret)
