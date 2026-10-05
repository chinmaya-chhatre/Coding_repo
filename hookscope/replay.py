"""Re-send a captured event to another URL.

Useful for reproducing a delivery against a local dev server or a staging
endpoint without asking the provider to send it again. The original headers
are forwarded (minus hop-by-hop headers that httpx sets itself), so signature
headers stay intact and the target can verify the replayed request.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from urllib.parse import urlparse

import httpx

# Headers that describe the original connection rather than the payload.
DROPPED_HEADERS = {"host", "content-length", "connection", "transfer-encoding", "accept-encoding"}
REPLAY_HEADER = "X-HookScope-Replay"
MAX_RESPONSE_CHARS = 2000


class InvalidTargetError(ValueError):
    pass


@dataclass(frozen=True)
class ReplayResult:
    target_url: str
    status_code: int | None
    elapsed_ms: int
    response_body: str = ""
    error: str = ""
    # Seconds the target asked us to wait (``Retry-After``); used by forwarding retries only.
    retry_after: float | None = field(default=None, compare=False)

    @property
    def ok(self) -> bool:
        return self.status_code is not None and self.status_code < 400

    def to_dict(self) -> dict:
        data = asdict(self)
        data.pop("retry_after")
        return {**data, "ok": self.ok}


def validate_target(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise InvalidTargetError("target_url must be an absolute http(s) URL")
    return url


def replay_headers(event: dict) -> dict[str, str]:
    headers = {k: v for k, v in event["headers"].items() if k.lower() not in DROPPED_HEADERS}
    headers[REPLAY_HEADER] = str(event["id"])
    return headers


def replay_event(
    event: dict, target_url: str, client: httpx.Client, headers: dict[str, str] | None = None
) -> ReplayResult:
    """POST the stored body with its original headers (or ``headers``) to ``target_url``."""
    validate_target(target_url)
    headers = replay_headers(event) if headers is None else headers
    started = time.perf_counter()
    try:
        response = client.post(target_url, content=event["body"].encode(), headers=headers)
    except httpx.HTTPError as exc:
        return ReplayResult(target_url, None, _elapsed_ms(started), error=f"{type(exc).__name__}: {exc}")
    return ReplayResult(
        target_url,
        response.status_code,
        _elapsed_ms(started),
        response_body=response.text[:MAX_RESPONSE_CHARS],
        retry_after=parse_retry_after(response.headers.get("retry-after")),
    )


def parse_retry_after(value: str | None, now: datetime | None = None) -> float | None:
    """Seconds to wait from a ``Retry-After`` header (delay-seconds or HTTP-date); None if absent/invalid."""
    if not value:
        return None
    value = value.strip()
    if value.isdigit():
        return float(value)
    try:
        when = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    return max(0.0, (when - (now or datetime.now(UTC))).total_seconds())


def _elapsed_ms(started: float) -> int:
    return int((time.perf_counter() - started) * 1000)
