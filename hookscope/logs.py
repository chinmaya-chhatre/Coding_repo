"""Structured logging: one JSON object per line when ``HOOKSCOPE_LOG_FORMAT=json``.

Every record carries the request id of the request being handled (see ``request_id``), so a
single delivery can be followed from the access line through its forwards, in a log search or
``jq``. Fields passed as ``extra={...}`` become keys of the JSON object (or ``key=value`` pairs in
the default text format). Event bodies, headers and secrets are never logged.
"""

from __future__ import annotations

import contextvars
import json
import logging
from datetime import UTC, datetime

LOG_FORMATS = ("text", "json")
LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")

# Set by the request-id middleware for the duration of a request, background work included.
current_request_id: contextvars.ContextVar[str | None] = contextvars.ContextVar("request_id", default=None)

_STANDARD = set(vars(logging.LogRecord("", 0, "", 0, "", (), None))) | {"message", "asctime", "taskName"}
_MARK = "_hookscope_handler"


def _extras(record: logging.LogRecord) -> dict:
    return {k: v for k, v in vars(record).items() if k not in _STANDARD and not k.startswith("_")}


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": current_request_id.get(),
            **_extras(record),
        }
        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry, default=str, separators=(",", ":"))


class TextFormatter(logging.Formatter):
    def __init__(self) -> None:
        super().__init__("%(asctime)s %(levelname)s %(name)s%(_request)s %(message)s%(_fields)s")

    def format(self, record: logging.LogRecord) -> str:
        rid = current_request_id.get()
        fields = _extras(record)
        # Underscore names are skipped by _extras, so formatting twice never mistakes them for fields.
        record._request = f" [{rid}]" if rid else ""
        record._fields = " " + " ".join(f"{k}={v}" for k, v in fields.items()) if fields else ""
        return super().format(record)


def configure(log_format: str = "text", level: str = "INFO") -> None:
    """Send the ``hookscope`` loggers to stderr in the chosen format. Safe to call repeatedly."""
    logger = logging.getLogger("hookscope")
    for handler in list(logger.handlers):
        if getattr(handler, _MARK, False):
            logger.removeHandler(handler)
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter() if log_format == "json" else TextFormatter())
    setattr(handler, _MARK, True)
    logger.addHandler(handler)
    logger.setLevel(level)
