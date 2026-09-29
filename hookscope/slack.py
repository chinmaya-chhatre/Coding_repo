"""Format captured events as Slack messages.

Used by forwarding rules with ``"format": "slack"``: instead of re-sending the
raw provider payload, HookScope posts a short, human-readable summary to a
Slack incoming webhook URL. The summary picks out the fields people usually
look for first (repository and sender for GitHub, object id and amount for
Stripe, id/type for generic payloads).
"""

from __future__ import annotations

import json

# Stripe amounts are in the currency's smallest unit; these currencies have none.
ZERO_DECIMAL_CURRENCIES = {
    "bif", "clp", "djf", "gnf", "jpy", "kmf", "krw", "mga",
    "pyg", "rwf", "ugx", "vnd", "vuv", "xaf", "xof", "xpf",
}  # fmt: skip
MAX_FIELD_CHARS = 150


def escape(text: str) -> str:
    """Escape the three characters Slack treats as control sequences in message text."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def slack_message(event: dict, rule_name: str, event_type: str | None) -> dict:
    """Build a Slack incoming-webhook payload (``text`` fallback plus Block Kit blocks)."""
    kind = f" `{escape(event_type)}`" if event_type else ""
    title = f"*{escape(event['source'])}*{kind} · event #{event['id']}"
    fields = _summary_fields(event)
    lines = [title] + [f"*{name}:* {escape(_clip(value))}" for name, value in fields]
    context = f"{event['verification']} · received {event['received_at']} · rule `{escape(rule_name)}`"
    label = f"{event['source']} {event_type}" if event_type else event["source"]
    return {
        "text": f"{escape(label)} (event #{event['id']})",
        "blocks": [
            {"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(lines)}},
            {"type": "context", "elements": [{"type": "mrkdwn", "text": context}]},
        ],
    }


def _summary_fields(event: dict) -> list[tuple[str, str]]:
    try:
        payload = json.loads(event["body"])
    except ValueError:
        return [("Body", "not JSON")] if event["body"] else []
    if not isinstance(payload, dict):
        return []
    if event["source"] == "github":
        return _github_fields(payload)
    if event["source"] == "stripe":
        return _stripe_fields(payload)
    return _generic_fields(payload)


def _github_fields(payload: dict) -> list[tuple[str, str]]:
    fields = []
    repo = _get(payload, "repository", "full_name")
    if repo:
        fields.append(("Repository", repo))
    sender = _get(payload, "sender", "login")
    if sender:
        fields.append(("Sender", sender))
    if isinstance(payload.get("action"), str):
        fields.append(("Action", payload["action"]))
    if isinstance(payload.get("ref"), str):
        fields.append(("Ref", payload["ref"]))
    for key, label in (("pull_request", "Pull request"), ("issue", "Issue")):
        number, title = _get(payload, key, "number"), _get(payload, key, "title")
        if number is not None:
            fields.append((label, f"#{number} {title or ''}".strip()))
            break
    commits = payload.get("commits")
    if isinstance(commits, list):
        fields.append(("Commits", str(len(commits))))
    return fields


def _stripe_fields(payload: dict) -> list[tuple[str, str]]:
    fields = []
    obj = _get(payload, "data", "object")
    if isinstance(obj, dict):
        if isinstance(obj.get("id"), str):
            fields.append(("Object", obj["id"]))
        amount = obj.get("amount_paid", obj.get("amount"))
        currency = obj.get("currency")
        if isinstance(amount, int) and isinstance(currency, str):
            fields.append(("Amount", format_amount(amount, currency)))
        if isinstance(obj.get("status"), str):
            fields.append(("Status", obj["status"]))
    if payload.get("livemode") is False:
        fields.append(("Mode", "test"))
    return fields


def _generic_fields(payload: dict) -> list[tuple[str, str]]:
    return [(key.capitalize(), str(payload[key])) for key in ("id", "type") if key in payload]


def format_amount(amount: int, currency: str) -> str:
    code = currency.lower()
    if code in ZERO_DECIMAL_CURRENCIES:
        return f"{amount:,} {code.upper()}"
    return f"{amount / 100:,.2f} {code.upper()}"


def _get(payload: dict, *keys: str):
    value: object = payload
    for key in keys:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def _clip(value: str) -> str:
    return value if len(value) <= MAX_FIELD_CHARS else value[: MAX_FIELD_CHARS - 1] + "…"
