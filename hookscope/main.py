"""FastAPI application: webhook receiver, JSON API and dashboard."""

from __future__ import annotations

import json
import os
import time
from collections.abc import Callable
from pathlib import Path

import httpx
from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from . import __version__
from .replay import InvalidTargetError, ReplayResult, replay_event
from .rules import ForwardRule, deliver, event_type, forward_event, is_dead_letter, load_rules, matching_rules
from .signatures import VERIFIERS, verify
from .store import EventStore
from .transform import InvalidTransformError, apply_transform, validate_mapping

TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
# Keep mapping keys in rule order: the output document follows the order of its transform.
TEMPLATES.env.policies["json.dumps_kwargs"] = {"sort_keys": False}
REPLAY_TIMEOUT_SECONDS = 10.0


class ReplayRequest(BaseModel):
    target_url: str


class TransformPreviewRequest(BaseModel):
    rule: str | None = None
    transform: dict | None = None


def load_secrets_from_env() -> dict[str, str]:
    """Read HOOKSCOPE_SECRET_<SOURCE> for every supported source."""
    secrets = {}
    for source in VERIFIERS:
        value = os.environ.get(f"HOOKSCOPE_SECRET_{source.upper()}")
        if value:
            secrets[source] = value
    return secrets


def create_app(
    store: EventStore | None = None,
    secrets: dict[str, str] | None = None,
    http_client: httpx.Client | None = None,
    rules: list[ForwardRule] | None = None,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> FastAPI:
    store = store or EventStore(os.environ.get("HOOKSCOPE_DB", "hookscope.db"))
    secrets = load_secrets_from_env() if secrets is None else secrets
    http_client = http_client or httpx.Client(timeout=REPLAY_TIMEOUT_SECONDS)
    rules = load_rules(os.environ.get("HOOKSCOPE_RULES")) if rules is None else rules

    def run_forwards(event_id: int, rule_list: list[ForwardRule]) -> None:
        event = store.get(event_id)
        if event is None:
            return

        def record(rule: ForwardRule, attempt: int, result: ReplayResult) -> None:
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

    def dead_letters(limit: int | None = None) -> list[dict]:
        by_name = {rule.name: rule for rule in rules}
        dead = []
        for forward in store.latest_forwards():
            rule = by_name.get(forward["rule"])
            if is_dead_letter(forward, rule):
                # A rule removed from the rules file can no longer be re-sent.
                dead.append({**forward, "resendable": rule is not None})
        return dead[:limit]

    app = FastAPI(title="HookScope", version=__version__)

    @app.get("/healthz")
    def healthz() -> dict:
        return {"status": "ok", "version": __version__}

    @app.post("/hooks/{source}", status_code=202)
    async def receive(source: str, request: Request, background: BackgroundTasks) -> JSONResponse:
        if source not in VERIFIERS:
            raise HTTPException(404, f"unknown source '{source}'. Supported: {sorted(VERIFIERS)}")

        body = await request.body()
        headers = dict(request.headers)
        result = verify(source, body, headers, secrets.get(source), url=str(request.url))
        event_id = store.add(
            source=source,
            headers=headers,
            body=body.decode("utf-8", errors="replace"),
            verification=result.status,
            reason=result.reason,
        )
        challenge = _slack_challenge(source, body) if not result.rejected else None
        if challenge is not None:
            # Slack's endpoint verification handshake: echo the challenge, never forward it.
            return JSONResponse({"challenge": challenge}, status_code=200)
        # Forward after responding so a slow target never delays the provider's delivery.
        to_forward = matching_rules(store.get(event_id), rules)
        if to_forward:
            background.add_task(run_forwards, event_id, to_forward)
        # Rejected events are still stored so they can be debugged in the UI.
        status_code = 401 if result.rejected else 202
        return JSONResponse(
            {
                "id": event_id,
                "verification": result.status,
                "reason": result.reason,
                "forwarded_to": [rule.name for rule in to_forward],
            },
            status_code=status_code,
            background=background,
        )

    @app.get("/api/events")
    def list_events(
        limit: int = 50,
        source: str | None = None,
        q: str | None = None,
        since: str | None = None,
        until: str | None = None,
        verification: str | None = None,
    ) -> list[dict]:
        try:
            return store.list(
                limit=min(limit, 500),
                source=source,
                q=q,
                since=since,
                until=until,
                verification=verification,
            )
        except ValueError as exc:
            raise HTTPException(422, f"since/until must be ISO dates or datetimes: {exc}") from exc

    @app.get("/api/events/{event_id}")
    def get_event(event_id: int) -> dict:
        event = store.get(event_id)
        if event is None:
            raise HTTPException(404, "event not found")
        return event

    @app.get("/api/events/{event_id}/forwards")
    def list_forwards(event_id: int) -> list[dict]:
        if store.get(event_id) is None:
            raise HTTPException(404, "event not found")
        return store.list_forwards(event_id)

    @app.get("/api/dead-letters")
    def list_dead_letters(limit: int = 100) -> list[dict]:
        """Forwards whose latest attempt failed for good (retries exhausted or a permanent error)."""
        return dead_letters(min(limit, 500))

    @app.post("/api/events/{event_id}/forwards/{rule_name}/resend")
    def resend_forward(event_id: int, rule_name: str) -> JSONResponse:
        event = store.get(event_id)
        if event is None:
            raise HTTPException(404, "event not found")
        rule = next((r for r in rules if r.name == rule_name), None)
        if rule is None:
            raise HTTPException(404, f"unknown rule '{rule_name}'")
        history = [f for f in store.list_forwards(event_id) if f["rule"] == rule_name]
        if not history:
            raise HTTPException(404, f"event {event_id} was never forwarded by rule '{rule_name}'")
        result = forward_event(event, rule, http_client)
        attempt = history[-1]["attempt"] + 1
        store.add_forward(
            event_id, rule.name, rule.target_url, result.status_code, result.elapsed_ms, result.error, attempt
        )
        return JSONResponse(
            {**result.to_dict(), "rule": rule.name, "attempt": attempt},
            status_code=502 if result.status_code is None else 200,
        )

    @app.get("/api/rules")
    def list_rules() -> list[dict]:
        return [rule.to_dict() for rule in rules]

    @app.post("/api/events/{event_id}/replay")
    def replay(event_id: int, payload: ReplayRequest) -> JSONResponse:
        event = store.get(event_id)
        if event is None:
            raise HTTPException(404, "event not found")
        try:
            result = replay_event(event, payload.target_url, http_client)
        except InvalidTargetError as exc:
            raise HTTPException(422, str(exc)) from exc
        # 502 when the target could not be reached at all; otherwise pass the outcome through.
        return JSONResponse(result.to_dict(), status_code=502 if result.status_code is None else 200)

    @app.post("/api/events/{event_id}/transform-preview")
    def preview_transform(event_id: int, payload: TransformPreviewRequest) -> dict:
        event = store.get(event_id)
        if event is None:
            raise HTTPException(404, "event not found")
        if (payload.rule is None) == (payload.transform is None):
            raise HTTPException(422, "send exactly one of 'rule' (a rule name) or 'transform' (a mapping)")
        rule = None
        mapping = payload.transform
        if payload.rule is not None:
            rule = next((r for r in rules if r.name == payload.rule), None)
            if rule is None:
                raise HTTPException(404, f"unknown rule '{payload.rule}'")
            if rule.transform is None:
                raise HTTPException(422, f"rule '{rule.name}' has no transform")
            mapping = rule.transform
        try:
            validate_mapping(mapping)
        except InvalidTransformError as exc:
            raise HTTPException(422, str(exc)) from exc
        kind = event_type(event)
        return {
            "event_id": event_id,
            "event_type": kind,
            "rule": rule.name if rule else None,
            # Whether the rule would actually forward this event; null for an ad-hoc transform.
            "matches": rule.matches(event) if rule else None,
            "output": apply_transform(mapping, event, kind),
        }

    @app.get("/", response_class=HTMLResponse)
    def dashboard(
        request: Request,
        source: str | None = None,
        q: str | None = None,
        since: str | None = None,
        until: str | None = None,
        verification: str | None = None,
    ) -> HTMLResponse:
        # Empty form fields arrive as "", which means "no filter".
        filters = {"q": q or None, "since": since or None, "until": until or None,
                   "verification": verification or None}
        filter_error = ""
        try:
            events = store.list(limit=100, source=source, **filters)
        except ValueError:
            filter_error = "Dates must look like 2026-10-08 (or a full ISO datetime)."
            events = []
        forwards = store.forwards_by_event([event["id"] for event in events])
        for event in events:
            event["pretty_body"] = _pretty(event["body"])
            event["forwards"] = forwards[event["id"]]
            event["forwards_failed"] = sum(1 for f in event["forwards"] if not _forward_ok(f))
        return TEMPLATES.TemplateResponse(
            request,
            "index.html",
            {
                "events": events,
                "sources": sorted(VERIFIERS),
                "active": source,
                "filters": {k: v for k, v in filters.items() if v},
                "filter_error": filter_error,
                "verifications": ["valid", "invalid", "unsigned", "no_secret"],
                "configured": sorted(secrets),
                "dead_letters": dead_letters(),
                # Rule mappings let the preview form start from a rule's transform and tweak it.
                "transform_rules": {rule.name: rule.transform for rule in rules if rule.transform},
            },
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
