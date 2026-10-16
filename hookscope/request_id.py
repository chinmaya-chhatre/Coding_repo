"""Request IDs: one identifier per request, accepted from the caller or generated here.

A caller (a proxy, a load balancer, the sender itself) may supply ``X-Request-ID``; it is kept if it
is short and made of safe characters, so it can be searched for in logs and copied around without
surprises. Anything else is replaced by a fresh random id rather than rejected, because losing a
webhook over a malformed correlation header would be the wrong trade. The id is returned on every
response and stored on the event, then passed on when the event is forwarded.
"""

from __future__ import annotations

import re
import uuid

HEADER = "X-Request-ID"
MAX_LENGTH = 128
_SAFE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/=+\-]*")


def generate() -> str:
    return uuid.uuid4().hex


def accept_or_generate(supplied: str | None) -> str:
    """The caller's id when it is usable, otherwise a new one."""
    if supplied:
        candidate = supplied.strip()
        if len(candidate) <= MAX_LENGTH and _SAFE.fullmatch(candidate):
            return candidate
    return generate()
