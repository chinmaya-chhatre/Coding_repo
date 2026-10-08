"""Prometheus metrics in the text exposition format.

Counts are read from the event store on each scrape rather than kept in memory, so
they survive restarts and agree with what the dashboard shows. They only go down if
stored events are deleted, which Prometheus treats as a counter reset.
"""

from __future__ import annotations

from collections.abc import Iterable

from . import __version__
from .store import EventStore

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"
VERIFICATION_STATUSES = ("valid", "invalid", "unsigned", "no_secret")


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _labels(**labels: str) -> str:
    return "{" + ",".join(f'{key}="{_escape(value)}"' for key, value in labels.items()) + "}"


def _family(name: str, kind: str, help_text: str, samples: Iterable[tuple[str, int]]) -> list[str]:
    lines = [f"# HELP {name} {help_text}", f"# TYPE {name} {kind}"]
    lines += [f"{name}{labels} {value}" for labels, value in samples]
    return lines


def render(store: EventStore, sources: Iterable[str], dead_letters: int) -> str:
    """All HookScope metrics. Every known source/status pair is listed, even at 0,
    so rate() and alerts work from the first delivery."""
    deliveries = {(source, status): 0 for source in sources for status in VERIFICATION_STATUSES}
    for source, status, count in store.delivery_counts():
        deliveries[(source, status)] = count
    forwards = store.forward_counts()

    lines: list[str] = []
    lines += _family(
        "hookscope_info", "gauge", "HookScope build information.", [(_labels(version=__version__), 1)]
    )
    lines += _family(
        "hookscope_deliveries_total",
        "counter",
        "Webhook deliveries received, by source and signature verification result.",
        [
            (_labels(source=source, verification=status), count)
            for (source, status), count in sorted(deliveries.items())
        ],
    )
    lines += _family(
        "hookscope_forward_attempts_total",
        "counter",
        "Forward attempts by rule and outcome (success means a 2xx response).",
        [(_labels(rule=rule, outcome=outcome), count) for rule, outcome, count in sorted(forwards)],
    )
    lines += _family(
        "hookscope_dead_letters",
        "gauge",
        "Forwards that exhausted their retries and are waiting for a manual re-send.",
        [("", dead_letters)],
    )
    return "\n".join(lines) + "\n"
