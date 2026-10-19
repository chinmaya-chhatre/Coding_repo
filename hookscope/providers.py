"""The providers HookScope knows, each described once.

Everything that differs between providers lives on one ``Provider`` object: how to verify the
signature, whether the signature covers the request URL, where the event type is found, and what to
tell someone replaying a request. Code elsewhere asks the registry instead of comparing a source name,
so supporting a new provider means adding one entry here.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass

from . import signatures
from .signatures import VerificationResult


@dataclass(frozen=True)
class Provider:
    name: str
    verify: Callable[..., VerificationResult]
    # The signature covers the public URL, so ``verify`` also needs it.
    url_signed: bool = False
    # The signature header whose value carries a timestamp, if the provider rejects stale requests.
    timestamp_header: str | None = None
    # Header holding the event type (lower case), when the provider does not put it in the body.
    event_type_header: str | None = None
    # (outer type, key) when an outer envelope wraps the real event, as Slack's ``event_callback`` does.
    event_envelope: tuple[str, str] | None = None
    # Extra advice shown above a rebuilt curl command.
    replay_note: str = ""


PROVIDERS: dict[str, Provider] = {
    provider.name: provider
    for provider in (
        Provider("github", signatures.verify_github, event_type_header="x-github-event"),
        Provider(
            "stripe",
            signatures.verify_stripe,
            timestamp_header="Stripe-Signature",
        ),
        Provider("shopify", signatures.verify_shopify, event_type_header="x-shopify-topic"),
        Provider(
            "slack",
            signatures.verify_slack,
            timestamp_header="X-Slack-Signature",
            event_envelope=("event_callback", "event"),
        ),
        Provider(
            "twilio",
            signatures.verify_twilio,
            url_signed=True,
            replay_note=(
                "Twilio signs the full public URL: use the URL Twilio was configured with, not this one."
            ),
        ),
        Provider("svix", signatures.verify_svix, timestamp_header="svix-signature"),
        Provider("generic", signatures.verify_generic),
    )
}


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
