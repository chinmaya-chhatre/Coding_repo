"""Request and response models for the HTTP API.

They exist so that the OpenAPI document (`/openapi.json`, `/docs`) describes every response
precisely, and so that responses are checked against that description. They mirror what the
store and the delivery code already produce; they do not change any JSON.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

Verification = Literal["valid", "invalid", "unsigned", "no_secret"]
VERIFICATION_DESCRIPTION = (
    "Signature check result: `valid`, `invalid` (wrong or malformed), `unsigned` (no signature "
    "header) or `no_secret` (nothing configured for this source, so the delivery was accepted)."
)


# ---------------------------------------------------------------------------------- responses


class ErrorOut(BaseModel):
    detail: str = Field(description="What went wrong.")


def error_responses(*codes: int) -> dict[int | str, dict[str, Any]]:
    """OpenAPI ``responses`` entries describing ``{"detail": ...}`` errors for these status codes."""
    return {code: {"model": ErrorOut} for code in codes}


class HealthOut(BaseModel):
    status: str = Field(examples=["ok"])
    version: str = Field(examples=["0.1.0"])


class ReceiveOut(BaseModel):
    """What a provider gets back from `POST /hooks/{source}`."""

    id: int = Field(description="Id of the stored event.")
    verification: Verification = Field(description=VERIFICATION_DESCRIPTION)
    reason: str = Field(description="Why verification failed; empty when it passed.")
    forwarded_to: list[str] = Field(description="Names of the forwarding rules this event matched.")


class SlackChallengeOut(BaseModel):
    """The reply to Slack's endpoint verification handshake (`url_verification`)."""

    challenge: str


class EventOut(BaseModel):
    id: int
    source: str = Field(examples=["github"])
    received_at: str = Field(description="UTC time of receipt, ISO 8601.")
    headers: dict[str, str] = Field(description="Request headers; credential headers are `[redacted]`.")
    body: str = Field(description="Request body as text (lossy if it was not valid UTF-8).")
    verification: Verification = Field(description=VERIFICATION_DESCRIPTION)
    reason: str
    body_base64: str | None = Field(
        description="The exact bytes received, base64-encoded; only set when the body is not valid UTF-8."
    )


class ForwardOut(BaseModel):
    """One delivery attempt of an event to a forwarding rule's target."""

    id: int
    event_id: int
    rule: str = Field(description="Name of the forwarding rule.")
    target_url: str
    forwarded_at: str
    status_code: int | None = Field(description="The target's HTTP status; null when unreachable.")
    elapsed_ms: int
    error: str = Field(description="Connection error, if the target could not be reached.")
    attempt: int = Field(description="1 for the first try, then 2, 3, ... for retries and re-sends.")


class DeadLetterOut(ForwardOut):
    """A forward whose latest attempt failed for good (retries used up, or a permanent error)."""

    resendable: bool = Field(description="False when the rule has since been removed from the rules file.")


class ReplayOut(BaseModel):
    """The outcome of sending a stored event to a URL."""

    target_url: str
    status_code: int | None = Field(description="The target's HTTP status; null when it was unreachable.")
    elapsed_ms: int
    response_body: str = Field(description="The start of the target's response body.")
    error: str
    ok: bool = Field(description="True for any status below 400.")


class ResendOut(ReplayOut):
    rule: str
    attempt: int


class RetryPolicyOut(BaseModel):
    attempts: int
    backoff_seconds: float
    max_backoff_seconds: float


class RuleOut(BaseModel):
    name: str
    target_url: str
    source: str | None = Field(description="Only events from this source match; null for any.")
    event_types: list[str] = Field(description="Only these event types match; empty for any.")
    format: str = Field(examples=["raw"])
    transform: dict[str, Any] | None
    retry: RetryPolicyOut


class CurlOut(BaseModel):
    command: str = Field(description="A shell command that sends this event to this HookScope again.")
    omitted_headers: list[str] = Field(description="Credential headers that were never stored.")


class PurgeOut(BaseModel):
    removed: int
    remaining: int


class TransformPreviewOut(BaseModel):
    event_id: int
    event_type: str | None
    rule: str | None
    matches: bool | None = Field(
        description="Whether the rule would forward this event; null for an ad-hoc transform."
    )
    output: Any = Field(description="The document the transform produces for this event.")


# ----------------------------------------------------------------------------------- requests


class ReplayRequest(BaseModel):
    target_url: str = Field(
        description="Absolute http(s) URL to send the stored event to.",
        examples=["https://example.com/webhooks"],
    )


class PurgeRequest(BaseModel):
    older_than: str | None = Field(
        default=None, description="ISO date or datetime; older events go.", examples=["2026-09-01"]
    )
    keep_last: int | None = Field(
        default=None, description="Keep only this many newest events.", examples=[1000]
    )


class TransformPreviewRequest(BaseModel):
    rule: str | None = Field(
        default=None, description="Name of a rule whose transform to preview.", examples=["notify-slack"]
    )
    transform: dict[str, Any] | None = Field(
        default=None,
        description="An ad-hoc mapping to preview.",
        examples=[{"kind": "$.type", "repo": "$.repository.full_name"}],
    )
