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
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
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

FORWARD_HEADER = "X-HookScope-Forward"
FORWARDABLE_STATUSES = {"valid", "no_secret"}
FORMATS = ("raw", "slack")


class InvalidRuleError(ValueError):
    pass


@dataclass(frozen=True)
class ForwardRule:
    name: str
    target_url: str
    source: str | None = None
    event_types: tuple[str, ...] = ()
    format: str = "raw"

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

        rules.append(ForwardRule(name, target_url, source, tuple(event_types), fmt))
    return rules


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
    """POST the event to the rule's target with its original headers (or as a Slack message)."""
    if rule.format == "slack":
        message = slack_message(event, rule.name, event_type(event))
        slack_event = {**event, "body": json.dumps(message)}
        headers = {"Content-Type": "application/json", FORWARD_HEADER: rule.name}
        return replay_event(slack_event, rule.target_url, client, headers=headers)
    headers = replay_headers(event)
    headers.pop(REPLAY_HEADER, None)
    headers[FORWARD_HEADER] = rule.name
    return replay_event(event, rule.target_url, client, headers=headers)
