"""Settings, read once from the environment.

Every ``HOOKSCOPE_*`` variable is parsed here, so the full list of knobs lives in one place
and a mistyped value is reported at startup, together with any other mistyped values,
instead of one at a time as each part of the app happens to read its own variable.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import TypeVar

from . import auth
from .retention import RetentionPolicy
from .signatures import VERIFIERS

DEFAULT_DB_PATH = "hookscope.db"
# Webhook payloads are small (GitHub caps its own at 25 MB and typical ones are a few KB).
DEFAULT_MAX_BODY_BYTES = 5 * 1024 * 1024

T = TypeVar("T")


class ConfigError(ValueError):
    """One or more settings are invalid. ``errors`` has one message per problem."""

    def __init__(self, errors: list[str]) -> None:
        self.errors = errors
        super().__init__("invalid configuration:\n" + "\n".join(f"  - {error}" for error in errors))


def max_body_bytes_from_env(env: Mapping[str, str]) -> int:
    raw = env.get("HOOKSCOPE_MAX_BODY_BYTES", "").strip()
    if not raw:
        return DEFAULT_MAX_BODY_BYTES
    try:
        value = int(raw)
    except ValueError:
        value = 0
    if value < 1:
        raise ValueError(f"HOOKSCOPE_MAX_BODY_BYTES must be a positive integer, got {raw!r}")
    return value


def secrets_from_env(env: Mapping[str, str]) -> dict[str, str]:
    """``HOOKSCOPE_SECRET_<SOURCE>`` for every supported source that has one set."""
    secrets = {}
    for source in VERIFIERS:
        value = env.get(f"HOOKSCOPE_SECRET_{source.upper()}")
        if value:
            secrets[source] = value
    return secrets


@dataclass(frozen=True)
class Settings:
    db_path: str = DEFAULT_DB_PATH
    rules_path: str | None = None
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES
    retention: RetentionPolicy = field(default_factory=RetentionPolicy)
    # Secrets stay out of repr() so logging a Settings object cannot leak them.
    secrets: dict[str, str] = field(default_factory=dict, repr=False)
    admin_password: str | None = field(default=None, repr=False)

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Settings:
        """Parse the environment (``os.environ`` by default); raises ``ConfigError`` listing every
        invalid value, not just the first."""
        env = os.environ if env is None else env
        errors: list[str] = []

        def attempt(parse: Callable[[], T], fallback: T) -> T:
            try:
                return parse()
            except ValueError as exc:
                errors.append(str(exc))
                return fallback

        settings = cls(
            db_path=env.get("HOOKSCOPE_DB", "").strip() or DEFAULT_DB_PATH,
            rules_path=env.get("HOOKSCOPE_RULES", "").strip() or None,
            max_body_bytes=attempt(lambda: max_body_bytes_from_env(env), DEFAULT_MAX_BODY_BYTES),
            retention=attempt(lambda: RetentionPolicy.from_env(env), RetentionPolicy()),
            secrets=secrets_from_env(env),
            admin_password=auth.password_from_env(env),
        )
        if errors:
            raise ConfigError(errors)
        return settings
