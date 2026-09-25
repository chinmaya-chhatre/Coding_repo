"""FastAPI application: webhook receiver, JSON API and dashboard."""

from __future__ import annotations

import json
import os
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from . import __version__
from .signatures import VERIFIERS, verify
from .store import EventStore

TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


def load_secrets_from_env() -> dict[str, str]:
    """Read HOOKSCOPE_SECRET_<SOURCE> for every supported source."""
    secrets = {}
    for source in VERIFIERS:
        value = os.environ.get(f"HOOKSCOPE_SECRET_{source.upper()}")
        if value:
            secrets[source] = value
    return secrets


def create_app(store: EventStore | None = None, secrets: dict[str, str] | None = None) -> FastAPI:
    store = store or EventStore(os.environ.get("HOOKSCOPE_DB", "hookscope.db"))
    secrets = load_secrets_from_env() if secrets is None else secrets

    app = FastAPI(title="HookScope", version=__version__)

    @app.get("/healthz")
    def healthz() -> dict:
        return {"status": "ok", "version": __version__}

    @app.post("/hooks/{source}", status_code=202)
    async def receive(source: str, request: Request) -> JSONResponse:
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
        # Rejected events are still stored so they can be debugged in the UI.
        status_code = 401 if result.rejected else 202
        return JSONResponse(
            {"id": event_id, "verification": result.status, "reason": result.reason},
            status_code=status_code,
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

    @app.get("/", response_class=HTMLResponse)
    def dashboard(request: Request, source: str | None = None) -> HTMLResponse:
        events = store.list(limit=100, source=source)
        for event in events:
            event["pretty_body"] = _pretty(event["body"])
        return TEMPLATES.TemplateResponse(
            request,
            "index.html",
            {"events": events, "sources": sorted(VERIFIERS), "active": source, "configured": sorted(secrets)},
        )

    return app


def _pretty(body: str) -> str:
    try:
        return json.dumps(json.loads(body), indent=2)
    except ValueError:
        return body


app = create_app()
