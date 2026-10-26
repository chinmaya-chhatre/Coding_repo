"""The ``hookscope`` command line: ``python -m hookscope serve``.

``serve`` starts the app with uvicorn. Every setting still comes from the ``HOOKSCOPE_*`` environment
variables; a flag, when given, overrides the matching variable for this run. Secrets are deliberately
not flags (they would show up in the process list): set ``HOOKSCOPE_SECRET_<SOURCE>`` instead.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence

from . import __version__
from .config import ConfigError, Settings
from .logs import LOG_FORMATS, LOG_LEVELS
from .providers import PROVIDERS

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8000

# flag attribute -> the environment variable it overrides
OVERRIDES = {
    "db": "HOOKSCOPE_DB",
    "rules": "HOOKSCOPE_RULES",
    "log_format": "HOOKSCOPE_LOG_FORMAT",
    "log_level": "HOOKSCOPE_LOG_LEVEL",
    "max_body_bytes": "HOOKSCOPE_MAX_BODY_BYTES",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hookscope", description="Receive, verify and inspect webhooks.")
    parser.add_argument("--version", action="version", version=f"hookscope {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    serve = commands.add_parser(
        "serve",
        help="start the server",
        description="Start the server. A flag overrides the matching HOOKSCOPE_* environment variable.",
    )
    serve.add_argument("--host", default=None, help=f"address to listen on (default {DEFAULT_HOST})")
    serve.add_argument("--port", type=int, default=None, help="port (default $PORT, else 8000)")
    serve.add_argument("--db", help="SQLite database file (HOOKSCOPE_DB)")
    serve.add_argument("--rules", help="forwarding rules JSON file (HOOKSCOPE_RULES)")
    serve.add_argument("--log-format", choices=LOG_FORMATS, help="HOOKSCOPE_LOG_FORMAT")
    serve.add_argument("--log-level", type=str.upper, choices=LOG_LEVELS, help="HOOKSCOPE_LOG_LEVEL")
    serve.add_argument("--max-body-bytes", type=int, help="largest accepted body (HOOKSCOPE_MAX_BODY_BYTES)")
    serve.add_argument(
        "--proxy-headers",
        action="store_true",
        help="trust X-Forwarded-* headers from any address (for use behind a load balancer)",
    )
    serve.add_argument(
        "--check",
        action="store_true",
        help="check the configuration, print what would run, and exit without starting",
    )
    return parser


def apply_overrides(args: argparse.Namespace, env: dict[str, str] | os._Environ[str] = os.environ) -> None:
    """Put the flags that were given into the environment, so the app reads one source of truth."""
    for attribute, variable in OVERRIDES.items():
        value = getattr(args, attribute)
        if value is not None:
            env[variable] = str(value)


def describe(settings: Settings, host: str, port: int) -> str:
    configured = sorted(settings.secrets)
    return "\n".join(
        [
            f"listening on http://{host}:{port}",
            f"database: {settings.db_path}",
            f"rules: {settings.rules_path or 'none'}",
            f"secrets set for: {', '.join(configured) if configured else 'none'}"
            + (f" (of {', '.join(sorted(PROVIDERS))})" if not configured else ""),
        ]
    )


def serve(args: argparse.Namespace) -> int:
    apply_overrides(args)
    host = args.host or DEFAULT_HOST
    port = args.port if args.port is not None else int(os.environ.get("PORT") or DEFAULT_PORT)
    try:
        settings = Settings.from_env()
    except ConfigError as error:
        print(f"hookscope: invalid configuration:\n{error}", file=sys.stderr)
        return 2
    print(describe(settings, host, port))
    if args.check:
        return 0
    import uvicorn  # imported late so --help and --check stay fast

    # The app module builds the app when imported, so it must be imported only after the overrides above.
    uvicorn.run(
        "hookscope.main:app",
        host=host,
        port=port,
        proxy_headers=args.proxy_headers,
        forwarded_allow_ips="*" if args.proxy_headers else None,
    )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return serve(args)  # "serve" is the only command so far
