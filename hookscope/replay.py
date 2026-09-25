"""Re-send a captured event to another URL.

Useful for reproducing a delivery against a local dev server or a staging
endpoint without asking the provider to send it again. The original headers
are forwarded (minus hop-by-hop headers that httpx sets itself), so signature
headers stay intact and the target can verify the replayed request.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass
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

    @property
    def ok(self) -> bool:
        return self.status_code is not None and self.status_code < 400

    def to_dict(self) -> dict:
        return {**asdict(self), "ok": self.ok}


def validate_target(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise InvalidTargetError("target_url must be an absolute http(s) URL")
    return url


def replay_headers(event: dict) -> dict[str, str]:
    headers = {k: v for k, v in event["headers"].items() if k.lower() not in DROPPED_HEADERS}
    headers[REPLAY_HEADER] = str(event["id"])
    return headers


def replay_event(event: dict, target_url: str, client: httpx.Client) -> ReplayResult:
    """POST the stored body with its original headers to ``target_url``."""
    validate_target(target_url)
    started = time.perf_counter()
    try:
        response = client.post(target_url, content=event["body"].encode(), headers=replay_headers(event))
    except httpx.HTTPError as exc:
        return ReplayResult(target_url, None, _elapsed_ms(started), error=f"{type(exc).__name__}: {exc}")
    return ReplayResult(
        target_url,
        response.status_code,
        _elapsed_ms(started),
        response_body=response.text[:MAX_RESPONSE_CHARS],
    )


def _elapsed_ms(started: float) -> int:
    return int((time.perf_counter() - started) * 1000)
