"""The ``hookscope`` command line: ``python -m hookscope serve`` and ``python -m hookscope send``.

``send`` posts a signed sample delivery to a running HookScope, in one of four scenarios. ``serve``
starts the app with uvicorn. Every setting still comes from the ``HOOKSCOPE_*`` environment
variables; a flag, when given, overrides the matching variable for this run. Secrets are deliberately
not flags (they would show up in the process list): set ``HOOKSCOPE_SECRET_<SOURCE>`` instead.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Sequence
from dataclasses import dataclass

from . import __version__
from .config import ConfigError, Settings
from .logs import LOG_FORMATS, LOG_LEVELS
from .providers import PROVIDERS
from .samples import SampleError, build_sample

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

    send = commands.add_parser(
        "send",
        help="send a signed sample delivery to a running HookScope",
        description="Send a sample for a provider and print what HookScope answered. The exit status is 0 "
        "when the answer is the one the scenario should get (202 for good, 401 for the others).",
    )
    send.add_argument("provider", choices=sorted(PROVIDERS))
    send.add_argument("--url", default="http://127.0.0.1:8000", help="where HookScope runs")
    send.add_argument(
        "--secret", help="signing secret (default: HOOKSCOPE_SECRET_<PROVIDER>, else a demo value)"
    )
    send.add_argument(
        "--scenario",
        choices=[*SCENARIOS, "all"],
        default="good",
        help="good: a valid delivery; bad-secret: signed with another secret; tampered: body changed "
        "after signing; stale-timestamp: signed an hour ago (Stripe, Slack, Svix); all: each in turn",
    )
    return parser


# --------------------------------------------------------------------------------------- send

SCENARIOS = ("good", "bad-secret", "tampered", "stale-timestamp")
STALE_SECONDS = 3_600
DEMO_SECRETS = {"svix": "whsec_ZGV2LXNlY3JldC1kZXYtc2VjcmV0"}
WRONG_SECRETS = {"svix": "whsec_d3Jvbmctc2VjcmV0LXdyb25n"}


def demo_secret(provider: str) -> str:
    return os.environ.get(f"HOOKSCOPE_SECRET_{provider.upper()}") or DEMO_SECRETS.get(provider, "dev-secret")


@dataclass(frozen=True)
class Outcome:
    scenario: str
    status: int | None
    answer: str
    expected: int

    @property
    def as_expected(self) -> bool:
        return self.status == self.expected


def post(url: str, body: bytes, headers: dict[str, str], timeout: float = 10.0) -> tuple[int | None, str]:
    """POST and return ``(status, body text)``; ``(None, reason)`` when HookScope cannot be reached."""
    request = urllib.request.Request(url, data=body, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode("utf-8", "replace")
    except OSError as error:
        return None, str(error.reason if isinstance(error, urllib.error.URLError) else error)


def tamper(body: bytes) -> bytes:
    """The body with its last byte changed: still signed, no longer the same message."""
    return body[:-1] + (b"X" if body[-1:] != b"X" else b"Y")


def scenario_request(
    provider: str, scenario: str, secret: str, target: str
) -> tuple[bytes, dict[str, str], int]:
    """``(body, headers, expected HTTP status)`` for a scenario; ``SampleError`` if it does not apply."""
    if scenario == "stale-timestamp" and PROVIDERS[provider].timestamp_from is None:
        raise SampleError(f"{provider} signatures carry no timestamp, so there is nothing to make stale")
    signing = WRONG_SECRETS.get(provider, "not-the-secret") if scenario == "bad-secret" else secret
    now = time.time() - STALE_SECONDS if scenario == "stale-timestamp" else None
    sample = build_sample(provider, signing, url=target, now=now)
    body = tamper(sample.body) if scenario == "tampered" else sample.body
    return body, sample.headers, 202 if scenario == "good" else 401


def send(args: argparse.Namespace) -> int:
    target = f"{args.url.rstrip('/')}/hooks/{args.provider}"
    secret = args.secret or demo_secret(args.provider)
    scenarios = SCENARIOS if args.scenario == "all" else (args.scenario,)
    outcomes: list[Outcome] = []
    for scenario in scenarios:
        try:
            body, headers, expected = scenario_request(args.provider, scenario, secret, target)
        except SampleError as error:
            if args.scenario != "all":
                print(f"hookscope: {error}", file=sys.stderr)
                return 2
            print(f"{scenario:16} skipped: {error}")
            continue
        status, answer = post(target, body, headers)
        outcomes.append(Outcome(scenario, status, answer, expected))
        print(f"{scenario:16} {status if status is not None else 'no answer'}  {answer}")
        if status is None:
            print(f"hookscope: could not reach {target}", file=sys.stderr)
            return 1
    wrong = [o for o in outcomes if not o.as_expected]
    for outcome in wrong:
        print(f"hookscope: {outcome.scenario} should have been {outcome.expected}", file=sys.stderr)
    return 1 if wrong else 0


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
    return send(args) if args.command == "send" else serve(args)
