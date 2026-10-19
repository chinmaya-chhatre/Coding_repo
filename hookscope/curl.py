"""Rebuild a stored event as a ``curl`` command, so it can be sent again by hand.

The command targets this HookScope's own ``/hooks/<source>`` endpoint with the stored headers and
the exact body bytes, which is what you want for reproducing a problem: the signature, the
verification and the forwarding all run again. Credential headers were never stored (they are
``[redacted]``), so they are left out and the command says so.
"""

from __future__ import annotations

import shlex

from .providers import PROVIDERS
from .store import REDACTED

# Added by the client or the connection, not part of what the sender chose to send.
TRANSPORT_HEADERS = frozenset(
    {"host", "content-length", "connection", "keep-alive", "accept-encoding", "transfer-encoding", "expect"}
)


def redacted_headers(event: dict) -> list[str]:
    return sorted(name for name, value in event["headers"].items() if value == REDACTED)


def build_curl(event: dict, base_url: str) -> str:
    """The command as a shell script fragment: comment lines first, then the curl call."""
    source = event["source"]
    url = f"{base_url.rstrip('/')}/hooks/{source}"
    notes = [f"Rebuilt from HookScope event #{event['id']} ({source}, received {event['received_at']})."]
    omitted = redacted_headers(event)
    if omitted:
        notes.append(f"Not included, because credentials are never stored: {', '.join(omitted)}.")
    provider = PROVIDERS.get(source)
    if provider and provider.timestamp_header:
        notes.append(
            f"{provider.timestamp_header} carries a timestamp: "
            "it only verifies for a few minutes after sending."
        )
    if provider and provider.replay_note:
        notes.append(provider.replay_note)

    parts = ["curl -sS -X POST " + shlex.quote(url)]
    for name, value in event["headers"].items():
        if name.lower() in TRANSPORT_HEADERS or value == REDACTED:
            continue
        parts.append("-H " + shlex.quote(f"{name}: {value}"))

    if event.get("body_base64"):
        # Not valid UTF-8: send the exact bytes through a decoder rather than a lossy string.
        parts.append("--data-binary @-")
        command = " \\\n  ".join(parts)
        command = f"printf %s {shlex.quote(event['body_base64'])} | base64 -d | {command}"
    else:
        parts.append("--data-binary " + shlex.quote(event["body"]))
        command = " \\\n  ".join(parts)
    return "".join(f"# {note}\n" for note in notes) + command
