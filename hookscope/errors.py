"""One error shape for the whole API::

    {"error": {"code": "event_not_found", "message": "event not found", "request_id": "..."}}

``code`` is stable and meant for programs (switch on it); ``message`` is for people and may be
reworded. ``request_id`` matches the ``X-Request-ID`` header and the log lines, so a report of an
error can be traced. Validation errors (422) add ``details``, one entry per invalid field.

Every failure goes through here: errors the routes raise on purpose (``ApiError``), FastAPI's own
(unknown paths, wrong methods, invalid parameters) and anything unexpected, which becomes a 500
without leaking internals.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

log = logging.getLogger("hookscope")

# What a status means when the code that raised it did not pick a more specific code.
DEFAULT_CODES = {
    400: "bad_request",
    401: "authentication_required",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    409: "conflict",
    413: "payload_too_large",
    415: "unsupported_media_type",
    422: "validation_error",
    429: "rate_limited",
    431: "headers_too_large",
    500: "internal_error",
    502: "bad_gateway",
    503: "unavailable",
}


class ApiError(Exception):
    """Raised by a route to answer with the standard error body."""

    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        details: list[dict[str, Any]] | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.status, self.code, self.message = status, code, message
        self.details, self.headers = details, headers


def error_body(
    code: str, message: str, request_id: str | None = None, details: list[dict[str, Any]] | None = None
) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if request_id:
        error["request_id"] = request_id
    if details:
        error["details"] = details
    return {"error": error}


def error_response(
    request: Request,
    status: int,
    code: str,
    message: str,
    details: list[dict[str, Any]] | None = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    rid = getattr(request.state, "request_id", None)
    return JSONResponse(error_body(code, message, rid, details), status_code=status, headers=headers)


def _field_errors(exc: RequestValidationError) -> list[dict[str, Any]]:
    return [
        {"field": ".".join(str(part) for part in item["loc"]), "message": item["msg"], "type": item["type"]}
        for item in exc.errors()
    ]


def install(app: FastAPI) -> None:
    """Make every error the app can produce use the standard body."""

    @app.exception_handler(ApiError)
    async def api_error(request: Request, exc: ApiError) -> JSONResponse:
        return error_response(request, exc.status, exc.code, exc.message, exc.details, exc.headers)

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = DEFAULT_CODES.get(exc.status_code, "error")
        message = exc.detail if isinstance(exc.detail, str) else code.replace("_", " ")
        if exc.status_code == 404 and message == "Not Found":
            message = f"no such endpoint: {request.method} {request.url.path}"
        return error_response(request, exc.status_code, code, message, headers=getattr(exc, "headers", None))

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        details = _field_errors(exc)
        names = ", ".join(sorted({d["field"] for d in details}))
        return error_response(request, 422, "validation_error", f"invalid request: {names}", details)

    @app.exception_handler(Exception)
    async def unexpected(request: Request, exc: Exception) -> JSONResponse:
        log.exception("unhandled error", extra={"path": request.url.path})
        return error_response(request, 500, "internal_error", "internal server error")
