"""Retention policy: keep the event store from growing forever.

Configured with ``HOOKSCOPE_RETENTION_DAYS`` (drop events older than N days) and/or
``HOOKSCOPE_MAX_EVENTS`` (keep only the newest N). Purging runs after incoming
deliveries, at most once per ``HOOKSCOPE_PURGE_INTERVAL_SECONDS`` (default 300), so a
burst can briefly exceed the limits; set the interval to 0 to purge after every delivery.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from .store import EventStore

DEFAULT_INTERVAL_SECONDS = 300.0


@dataclass(frozen=True)
class RetentionPolicy:
    max_age_days: float | None = None
    max_events: int | None = None
    interval_seconds: float = DEFAULT_INTERVAL_SECONDS

    def __post_init__(self) -> None:
        if self.max_age_days is not None and self.max_age_days <= 0:
            raise ValueError("retention days must be > 0")
        if self.max_events is not None and self.max_events < 1:
            raise ValueError("max events must be >= 1")
        if self.interval_seconds < 0:
            raise ValueError("purge interval must be >= 0")

    @property
    def enabled(self) -> bool:
        return self.max_age_days is not None or self.max_events is not None

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> RetentionPolicy:
        env = os.environ if env is None else env
        days = env.get("HOOKSCOPE_RETENTION_DAYS", "").strip()
        events = env.get("HOOKSCOPE_MAX_EVENTS", "").strip()
        interval = env.get("HOOKSCOPE_PURGE_INTERVAL_SECONDS", "").strip()
        try:
            return cls(
                max_age_days=float(days) if days else None,
                max_events=int(events) if events else None,
                interval_seconds=float(interval) if interval else DEFAULT_INTERVAL_SECONDS,
            )
        except ValueError as exc:
            raise ValueError(
                f"invalid retention settings (HOOKSCOPE_RETENTION_DAYS={days!r}, "
                f"HOOKSCOPE_MAX_EVENTS={events!r}, HOOKSCOPE_PURGE_INTERVAL_SECONDS={interval!r}): {exc}"
            ) from exc

    def cutoff(self, now: datetime | None = None) -> str | None:
        """ISO timestamp before which events are expired, or None without an age limit."""
        if self.max_age_days is None:
            return None
        now = now or datetime.now(UTC)
        return (now - timedelta(days=self.max_age_days)).isoformat(timespec="seconds")


class Purger:
    """Applies a policy to a store, throttled by a monotonic clock."""

    def __init__(self, store: EventStore, policy: RetentionPolicy, clock: Callable[[], float]) -> None:
        self.store = store
        self.policy = policy
        self.clock = clock
        self._last_run: float | None = None

    def run(self) -> int:
        """Purge now, regardless of the interval. Returns the number of events removed."""
        self._last_run = self.clock()
        if not self.policy.enabled:
            return 0
        return self.store.purge(older_than=self.policy.cutoff(), keep_last=self.policy.max_events)

    def maybe_run(self) -> int:
        """Purge if enabled and the interval has passed since the last run."""
        if not self.policy.enabled:
            return 0
        if self._last_run is not None and self.clock() - self._last_run < self.policy.interval_seconds:
            return 0
        return self.run()
