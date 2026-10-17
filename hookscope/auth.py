"""Optional password protection for the dashboard, JSON API and metrics.

Set ``HOOKSCOPE_ADMIN_PASSWORD`` to require credentials everywhere except the endpoints
that must stay public: ``/hooks/*`` (providers cannot log in; they are authenticated by
their signatures) and ``/healthz`` / ``/readyz`` (load balancer and orchestrator probes).
Without it, everything is open, as before, which suits local use but not a public deployment:
the API can replay events to arbitrary URLs and delete stored data.

Credentials are HTTP Basic (any username, the password above), so browsers show a login
prompt and the dashboard's own requests carry them, or ``Authorization: Bearer <password>``
for scripts. Responses to unauthenticated requests are 401 with a ``WWW-Authenticate``
challenge.
"""

from __future__ import annotations

import base64
import binascii
import hmac
from collections.abc import Mapping

PUBLIC_PREFIXES = ("/hooks/",)
PUBLIC_PATHS = frozenset({"/healthz", "/readyz"})


def password_from_env(env: Mapping[str, str]) -> str | None:
    """The configured password, or None when protection is off (unset or blank)."""
    return env.get("HOOKSCOPE_ADMIN_PASSWORD", "").strip() or None


def is_public(path: str) -> bool:
    return path in PUBLIC_PATHS or path.startswith(PUBLIC_PREFIXES)


def _supplied_password(authorization: str | None) -> str | None:
    if not authorization:
        return None
    scheme, _, value = authorization.partition(" ")
    scheme, value = scheme.lower(), value.strip()
    if scheme == "bearer":
        return value
    if scheme == "basic":
        try:
            decoded = base64.b64decode(value, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
            return None
        # Basic credentials are "user:password"; the username is ignored.
        return decoded.partition(":")[2]
    return None


def is_authorized(authorization: str | None, password: str) -> bool:
    supplied = _supplied_password(authorization)
    if supplied is None:
        return False
    return hmac.compare_digest(supplied.encode(), password.encode())
