"""FastAPI application: webhook receiver, JSON API and dashboard."""

from __future__ import annotations

import json
import os
from pathlib import Path

import httpx
from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from . import __version__
from .replay import InvalidTargetError, replay_event
from .rules import ForwardRule, event_type, forward_event, load_rules, matching_rules
from .signatures import VERIFIERS, verify
from .store import EventStore
from .transform import InvalidTransformError, apply_transform, validate_mapping

TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
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
) -> FastAPI:
    store = store or EventStore(os.environ.get("HOOKSCOPE_DB", "hookscope.db"))
    secrets = load_secrets_from_env() if secrets is None else secrets
    http_client = http_client or httpx.Client(timeout=REPLAY_TIMEOUT_SECONDS)
    rules = load_rules(os.environ.get("HOOKSCOPE_RULES")) if rules is None else rules

    def run_forwards(event_id: int, rule_list: list[ForwardRule]) -> None:
        event = store.get(event_id)
        if event is None:
            return
        for rule in rule_list:
            result = forward_event(event, rule, http_client)
            store.add_forward(
                event_id, rule.name, rule.target_url, result.status_code, result.elapsed_ms, result.error
            )

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
        result = verify(source, body, headers, secrets.get(source))
        event_id = store.add(
            source=source,
            headers=headers,
            body=body.decode("utf-8", errors="replace"),
            verification=result.status,
            reason=result.reason,
        )
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
    def list_events(limit: int = 50, source: str | None = None) -> list[dict]:
        return store.list(limit=min(limit, 500), source=source)

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
    def dashboard(request: Request, source: str | None = None) -> HTMLResponse:
        events = store.list(limit=100, source=source)
        forwards = store.forwards_by_event([event["id"] for event in events])
        for event in events:
            event["pretty_body"] = _pretty(event["body"])
            event["forwards"] = forwards[event["id"]]
            event["forwards_failed"] = sum(1 for f in event["forwards"] if not _forward_ok(f))
        return TEMPLATES.TemplateResponse(
            request,
            "index.html",
            {"events": events, "sources": sorted(VERIFIERS), "active": source, "configured": sorted(secrets)},
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


app = create_app()
