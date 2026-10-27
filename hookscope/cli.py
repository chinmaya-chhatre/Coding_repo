"""The ``hookscope`` command line: ``serve``, ``send``, ``tail`` and ``replay``.

``serve`` starts the app with uvicorn. ``send`` posts a signed sample delivery to a running HookScope in
one of four scenarios. ``tail`` follows the events a running HookScope has stored. ``replay`` sends a
stored event to a URL.

Every setting of ``serve`` still comes from the ``HOOKSCOPE_*`` environment variables; a flag, when
given, overrides the matching variable for this run. Secrets are deliberately not flags (they would show
up in the process list): set ``HOOKSCOPE_SECRET_<SOURCE>`` instead.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from urllib.parse import urlencode

from . import __version__
from .config import ConfigError, Settings
from .logs import LOG_FORMATS, LOG_LEVELS
from .providers import PROVIDERS
from .rules import event_type
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

    tail = commands.add_parser(
        "tail",
        help="follow the events a running HookScope receives",
        description="Print stored events as they arrive, oldest first. Set HOOKSCOPE_ADMIN_PASSWORD "
        "when the server has a password (any user name is accepted).",
    )
    tail.add_argument("--url", default="http://127.0.0.1:8000", help="where HookScope runs")
    tail.add_argument("--source", choices=sorted(PROVIDERS), help="only this provider")
    tail.add_argument(
        "--verification", choices=("valid", "invalid", "unsigned", "no_secret"), help="only this result"
    )
    tail.add_argument("--json", action="store_true", help="one JSON object per line, as the API returns it")
    tail.add_argument("--last", type=int, default=10, help="events to show first (default 10, 0 for none)")
    tail.add_argument("--interval", type=float, default=1.0, help="seconds between checks (default 1)")
    tail.add_argument("--no-follow", action="store_true", help="show the last events and exit")

    replay = commands.add_parser(
        "replay",
        help="send a stored event to a URL",
        description="Send the stored body and original headers of an event to a URL, through a running "
        "HookScope, and print what the target answered. The exit status is 0 when the target answered "
        "below 400, 1 when it failed, and 2 when HookScope could not do it (unknown event, bad URL, "
        "wrong password). Set HOOKSCOPE_ADMIN_PASSWORD when the server has a password.",
    )
    replay.add_argument("event_id", type=int, help="the event's id, as shown by `tail` or the dashboard")
    replay.add_argument("--to", required=True, metavar="URL", help="where to send it (an http(s) URL)")
    replay.add_argument("--url", default="http://127.0.0.1:8000", help="where HookScope runs")
    replay.add_argument("--json", action="store_true", help="print the API's answer as JSON")
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


# --------------------------------------------------------------------------------------- tail

PAGE = 50


def get_json(url: str, headers: dict[str, str], timeout: float = 10.0) -> tuple[int | None, object]:
    """GET and decode JSON: ``(status, data)``, or ``(None, reason)`` when HookScope cannot be reached."""
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode("utf-8", "replace")
    except (OSError, ValueError) as error:
        return None, str(error.reason if isinstance(error, urllib.error.URLError) else error)


def auth_headers() -> dict[str, str]:
    password = os.environ.get("HOOKSCOPE_ADMIN_PASSWORD")
    if not password:
        return {}
    return {"Authorization": "Basic " + base64.b64encode(f"hookscope:{password}".encode()).decode()}


class TailError(Exception):
    """HookScope could not be asked: ``fatal`` errors (a wrong password) are not worth retrying."""

    def __init__(self, message: str, fatal: bool = False) -> None:
        super().__init__(message)
        self.fatal = fatal


def fetch_page(base: str, filters: dict[str, str], before_id: int | None, fetch: Callable) -> list[dict]:
    query = {"limit": str(PAGE), **filters, **({"before_id": str(before_id)} if before_id else {})}
    status, data = fetch(f"{base}/api/events?{urlencode(query)}", auth_headers())
    if status is None:
        raise TailError(f"could not reach {base}: {data}")
    if status in (401, 403):
        raise TailError("HookScope wants a password: set HOOKSCOPE_ADMIN_PASSWORD", fatal=True)
    if status != 200 or not isinstance(data, list):
        raise TailError(f"unexpected answer {status} from {base}/api/events", fatal=status < 500)
    return data


def newer_than(base: str, filters: dict[str, str], last_id: int, fetch: Callable) -> list[dict]:
    """Every matching event with an id above ``last_id``, oldest first, however many arrived."""
    found: list[dict] = []
    before: int | None = None
    while True:
        page = fetch_page(base, filters, before, fetch)
        fresh = [event for event in page if event["id"] > last_id]
        found += fresh
        if len(fresh) < PAGE or len(page) < PAGE:  # reached what was already shown (or the start)
            break
        before = page[-1]["id"]
    return sorted(found, key=lambda event: event["id"])


def format_event(event: dict) -> str:
    """One line: id, time, source, result, event type and, for a rejected event, why."""
    clock = str(event["received_at"])[11:19]
    kind = event_type(event) or "-"
    line = f"#{event['id']:<5} {clock}  {event['source']:8} {event['verification']:9} {kind}"
    diagnosis = event.get("diagnosis")
    if diagnosis:
        line += f"  [{diagnosis['cause']}] {diagnosis['message']}"
    elif event["verification"] in ("invalid", "unsigned") and event.get("reason"):
        line += f"  {event['reason']}"
    return line


def tail(args: argparse.Namespace, fetch: Callable = get_json, sleep: Callable = time.sleep) -> int:
    base = args.url.rstrip("/")
    filters = {k: v for k, v in (("source", args.source), ("verification", args.verification)) if v}

    def show(event: dict) -> None:
        print(json.dumps(event) if args.json else format_event(event), flush=True)

    try:
        recent = fetch_page(base, filters, None, fetch)
    except TailError as error:
        print(f"hookscope: {error}", file=sys.stderr)
        return 2 if error.fatal else 1
    last_id = max((event["id"] for event in recent), default=0)
    for event in sorted(recent, key=lambda event: event["id"])[-args.last :] if args.last > 0 else []:
        show(event)
    if args.no_follow:
        return 0
    warned = False
    try:
        while True:
            sleep(args.interval)
            try:
                for event in newer_than(base, filters, last_id, fetch):
                    show(event)
                    last_id = max(last_id, event["id"])
                warned = False
            except TailError as error:
                if error.fatal:
                    print(f"hookscope: {error}", file=sys.stderr)
                    return 2
                if not warned:  # a restarting server is normal: say so once, keep trying
                    print(f"hookscope: {error}; retrying", file=sys.stderr)
                    warned = True
    except KeyboardInterrupt:
        return 0


# ------------------------------------------------------------------------------------- replay


def error_message(text: str) -> str:
    """The message of HookScope's error body, or the text itself when it is not one."""
    try:
        return str(json.loads(text)["error"]["message"])
    except (ValueError, KeyError, TypeError):
        return text.strip() or "no explanation"


def replay(args: argparse.Namespace, send_request: Callable = post) -> int:
    base = args.url.rstrip("/")
    headers = {"Content-Type": "application/json", **auth_headers()}
    body = json.dumps({"target_url": args.to}).encode()
    status, text = send_request(f"{base}/api/events/{args.event_id}/replay", body, headers)
    if status is None:
        print(f"hookscope: could not reach {base}: {text}", file=sys.stderr)
        return 2
    if status in (401, 403):
        print("hookscope: HookScope wants a password: set HOOKSCOPE_ADMIN_PASSWORD", file=sys.stderr)
        return 2
    try:
        answer = json.loads(text)
    except ValueError:
        answer = None
    if not isinstance(answer, dict) or "ok" not in answer:  # an error body, not a replay result
        print(f"hookscope: {error_message(text)}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(answer))
    else:
        print(f"replayed event #{args.event_id} to {answer['target_url']}")
        if answer["status_code"] is None:
            print(f"no response: {answer['error']}")
        else:
            print(f"HTTP {answer['status_code']} in {answer['elapsed_ms']} ms")
            if answer["response_body"]:
                print(answer["response_body"])
    return 0 if answer["ok"] else 1


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
    handlers = {"send": send, "tail": tail, "replay": replay}
    return handlers.get(args.command, serve)(args)
