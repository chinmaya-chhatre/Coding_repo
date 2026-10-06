"""Forwarding (fan-out) rules.

A rule says "when an accepted event from <source> of type <event type> arrives,
POST it to <target_url>". Rules are loaded from a JSON file (``HOOKSCOPE_RULES``)
so they can live next to the deployment config::

    {
      "rules": [
        {"name": "billing", "source": "stripe", "event_types": ["invoice.paid"],
         "target_url": "https://billing.internal/webhooks/stripe"},
        {"name": "ci", "source": "github", "event_types": ["push", "pull_request"],
         "target_url": "http://localhost:3000/github"}
      ]
    }

``source`` and ``event_types`` are optional; an omitted field matches everything.
Forwarded requests carry the original body and headers (so signatures still
verify) plus ``X-HookScope-Forward: <rule name>``. Rejected deliveries (bad or
missing signature) are never forwarded.

A rule with ``"format": "slack"`` posts a readable summary of the event to a
Slack incoming webhook instead of the raw payload (see ``hookscope.slack``).
The provider's headers are not sent in that case, so signatures never leak
into Slack.

A rule with a ``transform`` mapping sends a new JSON document built from the
payload with JSONPath expressions (see ``hookscope.transform``). The original
signature would not match the new body, so provider headers are not sent either.

A rule with a ``retry`` policy re-sends a failed forward with exponential backoff::

    {"name": "ci", "target_url": "http://ci.internal/hook",
     "retry": {"attempts": 4, "backoff_seconds": 2, "max_backoff_seconds": 60}}

Only transient failures are retried: no response at all (connection error,
timeout), ``408``, ``425``, ``429`` and ``5xx``. The wait before attempt *n+1*
is ``backoff_seconds * 2**(n-1)``, raised to the target's ``Retry-After`` when
it sends one, and capped at ``max_backoff_seconds``. ``"retry": 3`` is short
for ``{"attempts": 3}``. Without ``retry`` a forward is attempted once.
Every attempt is recorded, and a rule that is backing off never delays the
other rules' deliveries for the same event.
"""

from __future__ import annotations

import heapq
import json
import time
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from .replay import (
    REPLAY_HEADER,
    InvalidTargetError,
    ReplayResult,
    replay_event,
    replay_headers,
    validate_target,
)
from .signatures import VERIFIERS
from .slack import slack_message
from .transform import InvalidTransformError, apply_transform, validate_mapping

FORWARD_HEADER = "X-HookScope-Forward"
FORWARDABLE_STATUSES = {"valid", "no_secret"}
FORMATS = ("raw", "slack")
RETRYABLE_STATUS_CODES = {408, 425, 429}
MAX_ATTEMPTS = 10
MAX_BACKOFF_SECONDS = 3600.0


class InvalidRuleError(ValueError):
    pass


@dataclass(frozen=True)
class RetryPolicy:
    """How often, and how patiently, to re-send a forward that failed transiently."""

    attempts: int = 1
    backoff_seconds: float = 1.0
    max_backoff_seconds: float = 60.0

    def delay(self, attempt: int, retry_after: float | None = None) -> float:
        """Seconds to wait after failed attempt number ``attempt`` (1-based)."""
        wait = self.backoff_seconds * 2 ** (attempt - 1)
        if retry_after is not None:
            wait = max(wait, retry_after)
        return min(wait, self.max_backoff_seconds)

    def to_dict(self) -> dict:
        return {
            "attempts": self.attempts,
            "backoff_seconds": self.backoff_seconds,
            "max_backoff_seconds": self.max_backoff_seconds,
        }


def status_is_retryable(status: int | None) -> bool:
    return status is None or status in RETRYABLE_STATUS_CODES or status >= 500


def is_retryable(result: ReplayResult) -> bool:
    """Transient failures worth another try: no response, 408/425/429 or a server error."""
    return status_is_retryable(result.status_code)


def is_dead_letter(forward: dict, rule: ForwardRule | None) -> bool:
    """Whether a (rule, event)'s latest stored attempt is a failure that nothing will retry.

    A failure is dead when the error is permanent (a non-retryable 4xx), the rule's attempts
    are used up, or the rule no longer exists. A transient failure with attempts left is
    still backing off, so it is not dead yet.
    """
    status = forward["status_code"]
    if status is not None and 200 <= status < 300:
        return False
    if rule is None or not status_is_retryable(status):
        return True
    return forward["attempt"] >= rule.retry.attempts


@dataclass(frozen=True)
class ForwardRule:
    name: str
    target_url: str
    source: str | None = None
    event_types: tuple[str, ...] = ()
    format: str = "raw"
    transform: dict | None = None
    retry: RetryPolicy = field(default_factory=RetryPolicy)

    def matches(self, event: dict) -> bool:
        if event["verification"] not in FORWARDABLE_STATUSES:
            return False
        if self.source and event["source"] != self.source:
            return False
        if self.event_types and event_type(event) not in self.event_types:
            return False
        return True

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "target_url": self.target_url,
            "source": self.source,
            "event_types": list(self.event_types),
            "format": self.format,
            "transform": self.transform,
            "retry": self.retry.to_dict(),
        }


def event_type(event: dict) -> str | None:
    """Provider-specific event type: GitHub's ``X-GitHub-Event`` header, else the body's ``type``."""
    if event["source"] == "github":
        for key, value in event["headers"].items():
            if key.lower() == "x-github-event":
                return value
        return None
    try:
        payload = json.loads(event["body"])
    except ValueError:
        return None
    value = payload.get("type") if isinstance(payload, dict) else None
    return value if isinstance(value, str) else None


def parse_rules(data: object) -> list[ForwardRule]:
    """Validate rule definitions (a list, or a ``{"rules": [...]}`` object)."""
    if isinstance(data, dict):
        data = data.get("rules", [])
    if not isinstance(data, list):
        raise InvalidRuleError("rules must be a list or an object with a 'rules' list")

    rules: list[ForwardRule] = []
    seen: set[str] = set()
    for index, raw in enumerate(data):
        if not isinstance(raw, dict):
            raise InvalidRuleError(f"rule #{index} must be an object")
        name = raw.get("name") or f"rule-{index}"
        if not isinstance(name, str):
            raise InvalidRuleError(f"rule #{index}: name must be a string")
        if name in seen:
            raise InvalidRuleError(f"duplicate rule name '{name}'")
        seen.add(name)

        target_url = raw.get("target_url")
        if not isinstance(target_url, str):
            raise InvalidRuleError(f"rule '{name}': target_url is required")
        try:
            validate_target(target_url)
        except InvalidTargetError as exc:
            raise InvalidRuleError(f"rule '{name}': {exc}") from exc

        source = raw.get("source")
        if source is not None and source not in VERIFIERS:
            supported = sorted(VERIFIERS)
            raise InvalidRuleError(f"rule '{name}': unknown source '{source}'. Supported: {supported}")

        event_types = raw.get("event_types", [])
        if isinstance(event_types, str):
            event_types = [event_types]
        if not isinstance(event_types, list) or not all(isinstance(t, str) for t in event_types):
            raise InvalidRuleError(f"rule '{name}': event_types must be a list of strings")

        fmt = raw.get("format", "raw")
        if fmt not in FORMATS:
            raise InvalidRuleError(f"rule '{name}': format must be one of {list(FORMATS)}")

        transform = raw.get("transform")
        if transform is not None:
            if fmt != "raw":
                raise InvalidRuleError(f"rule '{name}': transform cannot be combined with format '{fmt}'")
            try:
                validate_mapping(transform)
            except InvalidTransformError as exc:
                raise InvalidRuleError(f"rule '{name}': {exc}") from exc

        retry = parse_retry(raw.get("retry"), name)
        rules.append(ForwardRule(name, target_url, source, tuple(event_types), fmt, transform, retry))
    return rules


def parse_retry(raw: object, name: str) -> RetryPolicy:
    """Validate a rule's ``retry`` setting: omitted, an attempt count, or a policy object."""
    if raw is None:
        return RetryPolicy()
    if isinstance(raw, int) and not isinstance(raw, bool):
        raw = {"attempts": raw}
    if not isinstance(raw, dict):
        raise InvalidRuleError(f"rule '{name}': retry must be a number of attempts or an object")
    unknown = sorted(set(raw) - {"attempts", "backoff_seconds", "max_backoff_seconds"})
    if unknown:
        raise InvalidRuleError(f"rule '{name}': unknown retry setting(s) {unknown}")

    defaults = RetryPolicy()
    attempts = raw.get("attempts", defaults.attempts)
    if isinstance(attempts, bool) or not isinstance(attempts, int) or not 1 <= attempts <= MAX_ATTEMPTS:
        raise InvalidRuleError(f"rule '{name}': retry attempts must be an integer from 1 to {MAX_ATTEMPTS}")
    values = {}
    for key in ("backoff_seconds", "max_backoff_seconds"):
        value = raw.get(key, getattr(defaults, key))
        is_number = isinstance(value, int | float) and not isinstance(value, bool)
        if not is_number or not 0 <= value <= MAX_BACKOFF_SECONDS:
            raise InvalidRuleError(
                f"rule '{name}': retry {key} must be a number from 0 to {MAX_BACKOFF_SECONDS:g}"
            )
        values[key] = float(value)
    if values["max_backoff_seconds"] < values["backoff_seconds"]:
        raise InvalidRuleError(f"rule '{name}': retry max_backoff_seconds is less than backoff_seconds")
    return RetryPolicy(attempts, values["backoff_seconds"], values["max_backoff_seconds"])


def load_rules(path: str | None) -> list[ForwardRule]:
    """Load rules from a JSON file; no path means no rules."""
    if not path:
        return []
    try:
        data = json.loads(Path(path).read_text())
    except OSError as exc:
        raise InvalidRuleError(f"cannot read rules file {path}: {exc}") from exc
    except ValueError as exc:
        raise InvalidRuleError(f"rules file {path} is not valid JSON: {exc}") from exc
    return parse_rules(data)


def matching_rules(event: dict, rules: Iterable[ForwardRule]) -> list[ForwardRule]:
    return [rule for rule in rules if rule.matches(event)]


def forward_event(event: dict, rule: ForwardRule, client: httpx.Client) -> ReplayResult:
    """POST the event to the rule's target with its original headers (or a Slack/transformed body)."""
    if rule.format == "slack":
        document = slack_message(event, rule.name, event_type(event))
    elif rule.transform is not None:
        document = apply_transform(rule.transform, event, event_type(event))
    else:
        document = None
    if document is not None:
        new_event = {**event, "body": json.dumps(document)}
        headers = {"Content-Type": "application/json", FORWARD_HEADER: rule.name}
        return replay_event(new_event, rule.target_url, client, headers=headers)
    headers = replay_headers(event)
    headers.pop(REPLAY_HEADER, None)
    headers[FORWARD_HEADER] = rule.name
    return replay_event(event, rule.target_url, client, headers=headers)


def forward_attempts(
    event: dict, rule: ForwardRule, client: httpx.Client
) -> Iterator[tuple[int, ReplayResult, float | None]]:
    """Forward the event lazily, one attempt per ``next()``, following the rule's retry policy.

    Yields ``(attempt, result, delay)`` where ``delay`` is how long to wait before the
    next attempt, or None when there is none (success, permanent failure, or out of attempts).
    """
    for attempt in range(1, rule.retry.attempts + 1):
        result = forward_event(event, rule, client)
        if attempt == rule.retry.attempts or not is_retryable(result):
            yield attempt, result, None
            return
        yield attempt, result, rule.retry.delay(attempt, result.retry_after)


def deliver(
    event: dict,
    rules: Iterable[ForwardRule],
    client: httpx.Client,
    record: Callable[[ForwardRule, int, ReplayResult], None],
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> None:
    """Forward an event to every rule, interleaving retries.

    Every rule gets its first attempt straight away; retries wait for their backoff
    without holding up the other rules. ``record`` is called after each attempt.
    """
    now = clock()
    queue = [(now, index, rule, forward_attempts(event, rule, client)) for index, rule in enumerate(rules)]
    heapq.heapify(queue)
    while queue:
        due, index, rule, attempts = heapq.heappop(queue)
        wait = due - clock()
        if wait > 0:
            sleep(wait)
        attempt, result, delay = next(attempts)
        record(rule, attempt, result)
        if delay is not None:
            heapq.heappush(queue, (clock() + delay, index, rule, attempts))
