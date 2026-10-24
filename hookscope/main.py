"""FastAPI application: webhook receiver, JSON API and dashboard."""

from __future__ import annotations

import json
import logging
import re
import time
from collections.abc import Callable
from pathlib import Path
from typing import Annotated

import httpx
from fastapi import BackgroundTasks, FastAPI, Query, Request
from fastapi import Path as PathParam
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.templating import Jinja2Templates

from . import __version__, auth, errors, logs, metrics, request_id
from .config import Settings
from .curl import build_curl, redacted_headers
from .diagnostics import Delivery, diagnose
from .errors import ApiError
from .providers import PROVIDERS, delivery_id, verify
from .replay import InvalidTargetError, ReplayResult, replay_event
from .retention import Purger, RetentionPolicy
from .rules import ForwardRule, deliver, event_type, forward_event, is_dead_letter, load_rules, matching_rules
from .samples import SampleError, build_sample
from .schemas import (
    CurlOut,
    DeadLetterOut,
    EventOut,
    ForwardOut,
    HealthOut,
    ProviderOut,
    PurgeOut,
    PurgeRequest,
    ReadyOut,
    ReceiveOut,
    ReplayOut,
    ReplayRequest,
    ResendOut,
    RuleOut,
    SlackChallengeOut,
    TransformPreviewOut,
    TransformPreviewRequest,
    error_responses,
)
from .store import EventStore
from .transform import InvalidTransformError, apply_transform, validate_mapping

TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
# Keep mapping keys in rule order: the output document follows the order of its transform.
TEMPLATES.env.policies["json.dumps_kwargs"] = {"sort_keys": False}
log = logging.getLogger("hookscope")

# Provider names are short lowercase words; anything else is refused before it can reach a log line.
SOURCE_PATTERN = re.compile(r"[a-z][a-z0-9_-]{0,31}")
# SQLite integers are 64-bit: a larger id in a query would raise inside the driver and become a 500.
MAX_ID = 2**63 - 1
EventId = Annotated[int, PathParam(ge=1, le=MAX_ID, description="The event's id.")]
PageSize = Annotated[int, Query(ge=1, description="How many to return (at most 500).")]
BeforeId = Annotated[int | None, Query(ge=0, le=MAX_ID, description="Only events with a smaller id.")]
SearchText = Annotated[str | None, Query(max_length=200, description="Text to find in bodies and headers.")]
ShortText = Annotated[str | None, Query(max_length=64)]


def unknown_source(source: str) -> ApiError:
    # repr() keeps control characters from reaching the message or a log; clip a huge one.
    return ApiError(404, "unknown_source", f"unknown source {source[:40]!r}. Supported: {sorted(PROVIDERS)}")


def header_problem(request: Request, max_headers: int, max_bytes: int) -> str | None:
    """Why this request's headers are too big, or None. Counts name, value and separators."""
    raw = request.scope["headers"]
    if len(raw) > max_headers:
        return f"too many headers: {len(raw)} (the limit is {max_headers})"
    size = sum(len(name) + len(value) + 4 for name, value in raw)
    if size > max_bytes:
        return f"headers are {size} bytes (the limit is {max_bytes})"
    return None
REPLAY_TIMEOUT_SECONDS = 10.0
DASHBOARD_PAGE_SIZE = 100

API_DESCRIPTION = (
    "Receives webhooks from GitHub, Stripe, Shopify, Slack, Twilio, Svix-style senders and "
    "generic HMAC senders; verifies their signatures; stores every delivery; and forwards, "
    "retries and replays them. `/hooks/*`, `/healthz` and `/readyz` are always public. When "
    "`HOOKSCOPE_ADMIN_PASSWORD` is set, everything else, this page included, needs HTTP Basic "
    "(any username) or `Authorization: Bearer <password>`."
)
OPENAPI_TAGS = [
    {"name": "webhooks", "description": "Where providers send events. Authenticated by signature."},
    {"name": "events", "description": "Browse, search and delete stored deliveries."},
    {"name": "forwarding", "description": "Rules, forward attempts, dead letters, replay and transforms."},
    {"name": "system", "description": "Health and Prometheus metrics."},
    {"name": "dashboard", "description": "The HTML dashboard."},
]


class BodyTooLargeError(Exception):
    pass


async def read_body_limited(request: Request, limit: int) -> bytes:
    """The request body, refusing early when it is larger than ``limit`` bytes.

    A declared Content-Length is checked before reading anything; chunked bodies without one
    are counted as they stream in, so a client cannot make the server buffer more than the
    limit by lying about (or omitting) the length.
    """
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > limit:
        raise BodyTooLargeError
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit:
            raise BodyTooLargeError
        chunks.append(chunk)
    return b"".join(chunks)


def create_app(
    store: EventStore | None = None,
    secrets: dict[str, str] | None = None,
    http_client: httpx.Client | None = None,
    rules: list[ForwardRule] | None = None,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
    retention: RetentionPolicy | None = None,
    admin_password: str | None = None,
    max_body_bytes: int | None = None,
    max_headers: int | None = None,
    max_header_bytes: int | None = None,
) -> FastAPI:
    # Explicit arguments (used by tests and embedding) win over the environment.
    settings = Settings.from_env()
    logs.configure(settings.log_format, settings.log_level)
    if store is None:
        store = EventStore(
            settings.db_path,
            journal_mode=settings.db_journal_mode,
            busy_timeout_ms=settings.db_busy_timeout_ms,
        )
        if store.journal_mode != settings.db_journal_mode:  # e.g. WAL on a network filesystem
            log.warning(
                "journal mode not applied",
                extra={"wanted": settings.db_journal_mode, "actual": store.journal_mode},
            )
    secrets = settings.secrets if secrets is None else secrets
    http_client = http_client or httpx.Client(timeout=REPLAY_TIMEOUT_SECONDS)
    rules = load_rules(settings.rules_path) if rules is None else rules
    purger = Purger(store, settings.retention if retention is None else retention, clock)

    def run_forwards(event_id: int, rule_list: list[ForwardRule]) -> None:
        event = store.get(event_id)
        if event is None:
            return

        def record(rule: ForwardRule, attempt: int, result: ReplayResult) -> None:
            log.log(
                logging.INFO if result.ok else logging.WARNING,
                "forward attempt",
                extra={
                    "event_id": event_id,
                    "rule": rule.name,
                    "attempt": attempt,
                    "status_code": result.status_code,
                    "elapsed_ms": result.elapsed_ms,
                    "error": result.error or None,
                },
            )
            # Each attempt is stored as it completes, so retries show up while backing off.
            store.add_forward(
                event_id,
                rule.name,
                rule.target_url,
                result.status_code,
                result.elapsed_ms,
                result.error,
                attempt,
            )

        deliver(event, rule_list, http_client, record, sleep, clock)

    def decorate_events(events: list[dict]) -> None:
        """Add what the event templates show: pretty body and the forward attempts."""
        forwards = store.forwards_by_event([event["id"] for event in events])
        for event in events:
            event["pretty_body"] = _pretty(event["body"])
            event["forwards"] = forwards[event["id"]]
            event["forwards_failed"] = sum(1 for f in event["forwards"] if not _forward_ok(f))

    def dead_letters(limit: int | None = None) -> list[dict]:
        by_name = {rule.name: rule for rule in rules}
        dead = []
        for forward in store.latest_forwards():
            rule = by_name.get(forward["rule"])
            if is_dead_letter(forward, rule):
                # A rule removed from the rules file can no longer be re-sent.
                dead.append({**forward, "resendable": rule is not None})
        return dead[:limit]

    body_limit = settings.max_body_bytes if max_body_bytes is None else max_body_bytes

    app = FastAPI(
        title="HookScope",
        version=__version__,
        description=API_DESCRIPTION,
        openapi_tags=OPENAPI_TAGS,
    )
    errors.install(app)
    header_limit = (
        settings.max_headers if max_headers is None else max_headers,
        settings.max_header_bytes if max_header_bytes is None else max_header_bytes,
    )

    password = settings.admin_password if admin_password is None else admin_password or None
    if password:

        @app.middleware("http")
        async def require_password(request: Request, call_next):
            if auth.is_public(request.url.path) or auth.is_authorized(
                request.headers.get("authorization"), password
            ):
                return await call_next(request)
            return errors.error_response(
                request,
                401,
                "authentication_required",
                "authentication required",
                headers={"WWW-Authenticate": 'Basic realm="HookScope", charset="UTF-8"'},
            )

    @app.middleware("http")
    async def assign_request_id(request: Request, call_next):
        # Registered after the password check, so it wraps it: even a 401 carries the id.
        rid = request_id.accept_or_generate(request.headers.get(request_id.HEADER))
        request.state.request_id = rid
        token = logs.current_request_id.set(rid)
        started = time.monotonic()
        try:
            response = await call_next(request)
            response.headers[request_id.HEADER] = rid
            # Health checks run every few seconds; they stay out of the INFO log.
            level = logging.DEBUG if request.url.path in ("/healthz", "/readyz") else logging.INFO
            log.log(
                level,
                "request",
                extra={
                    "method": request.method,
                    "path": request.url.path,
                    "status": response.status_code,
                    "duration_ms": round((time.monotonic() - started) * 1000, 1),
                },
            )
            return response
        finally:
            logs.current_request_id.reset(token)

    @app.get(
        "/healthz",
        tags=["system"],
        summary="Liveness check",
        response_model=HealthOut,
    )
    def healthz() -> dict:
        return {"status": "ok", "version": __version__}

    @app.get(
        "/readyz",
        tags=["system"],
        summary="Readiness check",
        response_model=ReadyOut,
        responses={503: {"model": ReadyOut, "description": "Not ready: do not route traffic here."}},
    )
    def readyz() -> JSONResponse:
        """Whether this instance can do its job: today, whether the database accepts writes.

        `/healthz` only says the process is up and costs nothing, so use it for liveness; use this
        one to decide whether to route traffic here.
        """
        started = time.monotonic()
        error = None
        try:
            store.check_writable()
        except Exception as exc:  # any failure means "not ready", whatever its type
            error = f"{type(exc).__name__}: {exc}"
        check = {"ok": error is None, "latency_ms": round((time.monotonic() - started) * 1000, 1)}
        if error:
            check["error"] = error
            log.warning("not ready", extra={"check": "database", "error": error})
        body = {
            "status": "ready" if error is None else "not_ready",
            "version": __version__,
            "checks": {"database": check},
        }
        return JSONResponse(body, status_code=200 if error is None else 503)

    def ingest(
        source: str,
        body: bytes,
        headers: dict[str, str],
        url: str,
        rid: str,
        background: BackgroundTasks,
    ) -> JSONResponse:
        """Verify, store and forward one delivery; shared by the real endpoint and the provider test."""
        result = verify(source, body, headers, secrets.get(source), url=url)
        diagnosis = diagnose(Delivery(source, body, headers, secrets.get(source), url, result))
        event_id = store.add(
            source=source,
            headers=headers,
            body=body.decode("utf-8", errors="replace"),
            raw_body=body,
            verification=result.status,
            reason=result.reason,
            request_id=rid,
            diagnosis=diagnosis.to_dict() if diagnosis else None,
        )
        log.log(
            logging.WARNING if result.rejected else logging.INFO,
            "event received",
            extra={
                "event_id": event_id,
                "source": source,
                "verification": result.status,
                "reason": result.reason or None,
                "cause": diagnosis.cause if diagnosis else None,
                "delivery_id": delivery_id(source, headers, body),
                "bytes": len(body),
            },
        )
        challenge = _slack_challenge(source, body) if not result.rejected else None
        if challenge is not None:
            # Slack's endpoint verification handshake: echo the challenge, never forward it.
            return JSONResponse({"challenge": challenge}, status_code=200)
        # Forward after responding so a slow target never delays the provider's delivery.
        to_forward = matching_rules(store.get(event_id), rules)
        if to_forward:
            background.add_task(run_forwards, event_id, to_forward)
        # Runs after forwarding, and keeps at least the newest event, so this one survives.
        background.add_task(purger.maybe_run)
        # Rejected events are still stored so they can be debugged in the UI.
        status_code = 401 if result.rejected else 202
        return JSONResponse(
            {
                "id": event_id,
                "verification": result.status,
                "reason": result.reason,
                "forwarded_to": [rule.name for rule in to_forward],
                "diagnosis": diagnosis.to_dict() if diagnosis else None,
            },
            status_code=status_code,
            background=background,
        )

    @app.post(
        "/hooks/{source}",
        tags=["webhooks"],
        summary="Receive a webhook",
        status_code=202,
        # Rejected deliveries (bad signature) answer 401 with the same body, and are still stored.
        responses={
            202: {"model": ReceiveOut},
            200: {"model": SlackChallengeOut, "description": "Slack `url_verification` handshake."},
            401: {"model": ReceiveOut, "description": "Signature check failed; the event is stored anyway."},
            **error_responses(404, 413),
        },
    )
    async def receive(source: str, request: Request, background: BackgroundTasks) -> JSONResponse:
        if not SOURCE_PATTERN.fullmatch(source) or source not in PROVIDERS:
            raise unknown_source(source)
        if (problem := header_problem(request, *header_limit)) is not None:
            raise ApiError(431, "headers_too_large", problem)

        try:
            body = await read_body_limited(request, body_limit)
        except BodyTooLargeError:
            raise ApiError(
                413, "payload_too_large", f"request body exceeds the {body_limit} byte limit"
            ) from None
        return ingest(
            source, body, dict(request.headers), str(request.url), request.state.request_id, background
        )

    @app.get(
        "/api/providers",
        tags=["webhooks"],
        summary="List supported providers",
        response_model=list[ProviderOut],
    )
    def list_providers() -> list[dict]:
        return [
            {
                "name": provider.name,
                "path": f"/hooks/{provider.name}",
                "secret_env": f"HOOKSCOPE_SECRET_{provider.name.upper()}",
                "secret_configured": provider.name in secrets,
                "url_signed": provider.url_signed,
                "timestamp_header": provider.timestamp_header,
                "event_type_from": provider.event_type_from,
                "delivery_id_from": provider.delivery_id_from,
            }
            for provider in PROVIDERS.values()
        ]

    @app.post(
        "/api/providers/{name}/test",
        tags=["webhooks"],
        summary="Send a signed test event",
        status_code=202,
        responses={202: {"model": ReceiveOut}, **error_responses(404, 409)},
    )
    def send_test(name: str, request: Request, background: BackgroundTasks) -> JSONResponse:
        """Deliver a sample signed with the provider's configured secret, through the normal pipeline.

        The event is verified, stored and forwarded like a real one, so rules and the dashboard can be
        tried without waiting for the provider. The signature never leaves the server.
        """
        if name not in PROVIDERS:
            raise unknown_source(name)
        secret = secrets.get(name)
        if not secret:
            raise ApiError(
                409,
                "secret_not_configured",
                f"set HOOKSCOPE_SECRET_{name.upper()} first: a test event is signed with it",
            )
        url = f"{str(request.base_url).rstrip('/')}/hooks/{name}"
        try:
            sample = build_sample(name, secret, url=url)
        except SampleError as exc:
            raise ApiError(409, "sample_unavailable", str(exc)) from None
        headers = {key.lower(): value for key, value in sample.headers.items()}
        return ingest(name, sample.body, headers, url, request.state.request_id, background)

    @app.get(
        "/metrics",
        tags=["system"],
        summary="Prometheus metrics",
    )
    def prometheus_metrics() -> Response:
        body = metrics.render(store, sources=PROVIDERS, dead_letters=len(dead_letters()))
        return Response(body, media_type=metrics.CONTENT_TYPE)

    @app.get(
        "/api/events",
        tags=["events"],
        summary="List and search events",
        response_model=list[EventOut],
        responses={
            200: {
                "headers": {
                    "X-Next-Cursor": {
                        "description": "Set when more events match; use it as `before_id` for the next page.",
                        "schema": {"type": "integer"},
                    }
                }
            },
            **error_responses(422),
        },
    )
    def list_events(
        response: Response,
        limit: PageSize = 50,
        source: ShortText = None,
        q: SearchText = None,
        since: ShortText = None,
        until: ShortText = None,
        verification: ShortText = None,
        before_id: BeforeId = None,
    ) -> list[dict]:
        """Newest first. When more events match, `X-Next-Cursor` holds the `before_id` for the next page."""
        limit = min(limit, 500)
        try:
            # One extra row tells us whether another page exists without a second query.
            events = store.list(
                limit=limit + 1 if limit >= 1 else limit,
                source=source,
                q=q,
                since=since,
                until=until,
                verification=verification,
                before_id=before_id,
            )
        except ValueError as exc:
            raise ApiError(422, "invalid_date", f"since/until must be ISO dates or datetimes: {exc}") from exc
        if limit >= 1 and len(events) > limit:
            events = events[:limit]
            response.headers["X-Next-Cursor"] = str(events[-1]["id"])
        return events

    @app.get(
        "/api/events/{event_id}",
        tags=["events"],
        summary="Get one event",
        response_model=EventOut,
        responses=error_responses(404),
    )
    def get_event(event_id: EventId) -> dict:
        event = store.get(event_id)
        if event is None:
            raise ApiError(404, "event_not_found", "event not found")
        return event

    @app.get(
        "/api/events/{event_id}/curl",
        tags=["events"],
        summary="Rebuild an event as a curl command",
        response_model=CurlOut,
        responses=error_responses(404),
    )
    def event_as_curl(event_id: EventId, request: Request) -> dict:
        """The stored headers and exact body, aimed at this server's `/hooks/<source>`."""
        event = store.get(event_id)
        if event is None:
            raise ApiError(404, "event_not_found", "event not found")
        return {
            "command": build_curl(event, str(request.base_url)),
            "omitted_headers": redacted_headers(event),
        }

    @app.get(
        "/api/events/{event_id}/forwards",
        tags=["forwarding"],
        summary="List an event's forward attempts",
        response_model=list[ForwardOut],
        responses=error_responses(404),
    )
    def list_forwards(event_id: EventId) -> list[dict]:
        if store.get(event_id) is None:
            raise ApiError(404, "event_not_found", "event not found")
        return store.list_forwards(event_id)

    @app.get(
        "/api/dead-letters",
        tags=["forwarding"],
        summary="List dead letters",
        response_model=list[DeadLetterOut],
    )
    def list_dead_letters(limit: PageSize = 100) -> list[dict]:
        """Forwards whose latest attempt failed for good (retries exhausted or a permanent error)."""
        return dead_letters(min(limit, 500))

    @app.post(
        "/api/events/{event_id}/forwards/{rule_name}/resend",
        tags=["forwarding"],
        summary="Re-send a forward",
        responses={
            200: {"model": ResendOut},
            502: {"model": ResendOut, "description": "The target could not be reached."},
            **error_responses(404),
        },
    )
    def resend_forward(event_id: EventId, rule_name: str) -> JSONResponse:
        event = store.get(event_id)
        if event is None:
            raise ApiError(404, "event_not_found", "event not found")
        rule = next((r for r in rules if r.name == rule_name), None)
        if rule is None:
            raise ApiError(404, "rule_not_found", f"unknown rule '{rule_name}'")
        history = [f for f in store.list_forwards(event_id) if f["rule"] == rule_name]
        if not history:
            raise ApiError(
                404, "forward_not_found", f"event {event_id} was never forwarded by rule '{rule_name}'"
            )
        result = forward_event(event, rule, http_client)
        attempt = history[-1]["attempt"] + 1
        store.add_forward(
            event_id, rule.name, rule.target_url, result.status_code, result.elapsed_ms, result.error, attempt
        )
        return JSONResponse(
            {**result.to_dict(), "rule": rule.name, "attempt": attempt},
            status_code=502 if result.status_code is None else 200,
        )

    @app.get(
        "/api/rules",
        tags=["forwarding"],
        summary="List forwarding rules",
        response_model=list[RuleOut],
    )
    def list_rules() -> list[dict]:
        return [rule.to_dict() for rule in rules]

    @app.post(
        "/api/purge",
        tags=["events"],
        summary="Delete events now",
        response_model=PurgeOut,
        responses=error_responses(400, 422),
    )
    def purge(payload: PurgeRequest | None = None) -> dict:
        """Delete events now: by the given rules, or by the configured retention policy."""
        if payload and (payload.older_than or payload.keep_last is not None):
            try:
                removed = store.purge(older_than=payload.older_than, keep_last=payload.keep_last)
            except ValueError as exc:
                raise ApiError(422, "invalid_purge", str(exc)) from exc
        elif purger.policy.enabled:
            removed = purger.run()
        else:
            raise ApiError(
                400,
                "no_retention_policy",
                "no retention policy configured; pass older_than and/or keep_last, or set "
                "HOOKSCOPE_RETENTION_DAYS / HOOKSCOPE_MAX_EVENTS",
            )
        return {"removed": removed, "remaining": store.count()}

    @app.post(
        "/api/events/{event_id}/replay",
        tags=["forwarding"],
        summary="Replay an event to a URL",
        responses={
            200: {"model": ReplayOut},
            502: {"model": ReplayOut, "description": "The target could not be reached."},
            **error_responses(404, 422),
        },
    )
    def replay(event_id: EventId, payload: ReplayRequest) -> JSONResponse:
        event = store.get(event_id)
        if event is None:
            raise ApiError(404, "event_not_found", "event not found")
        try:
            result = replay_event(event, payload.target_url, http_client)
        except InvalidTargetError as exc:
            raise ApiError(422, "invalid_target", str(exc)) from exc
        # 502 when the target could not be reached at all; otherwise pass the outcome through.
        return JSONResponse(result.to_dict(), status_code=502 if result.status_code is None else 200)

    @app.post(
        "/api/events/{event_id}/transform-preview",
        tags=["forwarding"],
        summary="Preview a transform",
        response_model=TransformPreviewOut,
        responses=error_responses(404, 422),
    )
    def preview_transform(event_id: EventId, payload: TransformPreviewRequest) -> dict:
        event = store.get(event_id)
        if event is None:
            raise ApiError(404, "event_not_found", "event not found")
        if (payload.rule is None) == (payload.transform is None):
            raise ApiError(
                422,
                "invalid_transform_request",
                "send exactly one of 'rule' (a rule name) or 'transform' (a mapping)",
            )
        rule = None
        mapping = payload.transform
        if payload.rule is not None:
            rule = next((r for r in rules if r.name == payload.rule), None)
            if rule is None:
                raise ApiError(404, "rule_not_found", f"unknown rule '{payload.rule}'")
            if rule.transform is None:
                raise ApiError(422, "rule_has_no_transform", f"rule '{rule.name}' has no transform")
            mapping = rule.transform
        try:
            validate_mapping(mapping)
        except InvalidTransformError as exc:
            raise ApiError(422, "invalid_transform", str(exc)) from exc
        kind = event_type(event)
        return {
            "event_id": event_id,
            "event_type": kind,
            "rule": rule.name if rule else None,
            # Whether the rule would actually forward this event; null for an ad-hoc transform.
            "matches": rule.matches(event) if rule else None,
            "output": apply_transform(mapping, event, kind),
        }

    @app.get(
        "/",
        tags=["dashboard"],
        summary="Dashboard",
        response_class=HTMLResponse,
    )
    def dashboard(
        request: Request,
        source: ShortText = None,
        q: SearchText = None,
        since: ShortText = None,
        until: ShortText = None,
        verification: ShortText = None,
        before_id: BeforeId = None,
    ) -> HTMLResponse:
        # Empty form fields arrive as "", which means "no filter".
        filters = {"q": q or None, "since": since or None, "until": until or None,
                   "verification": verification or None}
        filter_error = ""
        older_id = None
        try:
            # One extra row says whether an older page exists.
            events = store.list(
                limit=DASHBOARD_PAGE_SIZE + 1, source=source, before_id=before_id, **filters
            )
            if len(events) > DASHBOARD_PAGE_SIZE:
                events = events[:DASHBOARD_PAGE_SIZE]
                older_id = events[-1]["id"]
        except ValueError:
            filter_error = "Dates must look like 2026-10-08 (or a full ISO datetime)."
            events = []
        decorate_events(events)
        return TEMPLATES.TemplateResponse(
            request,
            "index.html",
            {
                "events": events,
                "sources": sorted(PROVIDERS),
                "active": source,
                "filters": {k: v for k, v in filters.items() if v},
                "filter_error": filter_error,
                "older_id": older_id,
                "paged": before_id is not None,
                "verifications": ["valid", "invalid", "unsigned", "no_secret"],
                "configured": sorted(secrets),
                "dead_letters": dead_letters(),
                # Rule mappings let the preview form start from a rule's transform and tweak it.
                "transform_rules": {rule.name: rule.transform for rule in rules if rule.transform},
            },
        )

    @app.get(
        "/events/{event_id}",
        tags=["dashboard"],
        summary="Event detail page",
        response_class=HTMLResponse,
        responses={404: {"description": "No such event (an HTML page).", "content": {"text/html": {}}}},
    )
    def event_page(event_id: EventId, request: Request) -> HTMLResponse:
        """A shareable page for one event: body, headers, forwards, replay and transform preview."""
        event = store.get(event_id)
        if event is not None:
            decorate_events([event])
        return TEMPLATES.TemplateResponse(
            request,
            "event.html",
            {
                "event": event,
                "transform_rules": {rule.name: rule.transform for rule in rules if rule.transform},
            },
            status_code=200 if event else 404,
        )

    return app


def _forward_ok(forward: dict) -> bool:
    status = forward["status_code"]
    return status is not None and 200 <= status < 300


def _pretty(body: str) -> str:
    try:
        return json.dumps(json.loads(body), indent=2)
    except ValueError:
        return body


def _slack_challenge(source: str, body: bytes) -> str | None:
    """The ``challenge`` of a Slack ``url_verification`` request, which must be echoed back."""
    if source != "slack":
        return None
    try:
        payload = json.loads(body)
    except ValueError:
        return None
    if not isinstance(payload, dict) or payload.get("type") != "url_verification":
        return None
    challenge = payload.get("challenge")
    return challenge if isinstance(challenge, str) else None


app = create_app()
