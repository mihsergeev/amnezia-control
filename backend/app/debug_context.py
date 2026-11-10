"""Support diagnostics contain categories, never request/response or SSH payloads."""

import secrets
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field

from fastapi.exception_handlers import http_exception_handler
from starlette.exceptions import HTTPException
from starlette.concurrency import run_in_threadpool

from app.debuglog import emit_event


@dataclass
class DiagnosticContext:
    store: object
    scope: dict
    correlation_id: str = field(default_factory=lambda: secrets.token_hex(16))
    failed: bool = False
    fields: dict = field(default_factory=dict)


_current: ContextVar[DiagnosticContext | None] = ContextVar("support_diagnostics", default=None)
_EXCLUDED = {"auth", "debug_logs", "health", "branding", "stats", "audit"}
_PROTOCOLS = {"awg", "awg2", "awg3", "wireguard", "openvpn", "xray", "vless", "gre"}


def _metadata(scope: dict) -> dict | None:
    endpoint = scope.get("endpoint")
    module = getattr(endpoint, "__module__", "")
    if not module.startswith("app.api."):
        return None
    module = module.removeprefix("app.api.")
    if module in _EXCLUDED:
        return None
    route = getattr(scope.get("route"), "path", "")
    # Only the registered route template is examined, never a submitted URL.
    operation = {
        "cascades": "cascade", "bulk_clients": "clients", "clients": "clients",
        "backup": "backup", "transfer": "import", "importer": "import",
        "alerts": "alerts",
    }.get(module, "request")
    if module == "cascades" and "/probe" in route:
        operation = "probe"
    elif any(part in route.split("/") for part in ("deploy", "update", "rebuild", "upgrade31")):
        operation = "deploy"
    elif "clients" in route.split("/"):
        operation = "clients"
    parts = ["awg_legacy" if part == "awg-legacy" else part for part in route.split("/")]
    protocol = next((part for part in parts if part in _PROTOCOLS or part == "awg_legacy"), None)
    params = scope.get("path_params", {})
    sid = params.get("server_id")
    if isinstance(sid, str) and sid.isascii() and sid.isdigit() and len(sid) <= 10:
        sid = int(sid)
    return {"operation": operation, "protocol": protocol,
            "server_id": sid if type(sid) is int and 0 < sid <= 2**31 - 1 else None}


def record(*, store=None, **fields):
    """Classify transient errors at the call site; only allowlisted fields survive."""
    ctx = _current.get()
    if ctx is not None:
        meta = _metadata(ctx.scope) or {}
        fields = {**meta, **ctx.fields, "correlation_id": ctx.correlation_id, **fields}
        store = store if store is not None else ctx.store
    if store is not None:
        return emit_event(store, **fields)
    return None


async def arecord(*, store=None, **fields):
    """Storage and cross-process locking must never run on the event loop."""
    return await run_in_threadpool(record, store=store, **fields)


@contextmanager
def bind(*, store=None, **fields):
    """Keep one correlation ID for a job, including jobs outside HTTP requests."""
    current = _current.get()
    context = DiagnosticContext(
        store=store if store is not None else current.store if current else None,
        scope=current.scope if current else {},
        correlation_id=current.correlation_id if current else secrets.token_hex(16),
        fields={**(current.fields if current else {}), **fields},
    )
    token = _current.set(context)
    try:
        yield
    finally:
        _current.reset(token)


async def diagnostic_http_exception(request, exc: HTTPException):
    ctx = _current.get()
    if ctx is not None and _metadata(ctx.scope) is not None and exc.status_code not in (401, 403, 404):
        code = {400: "validation", 409: "conflict", 422: "validation", 429: "conflict",
                499: "timeout", 503: "connect", 504: "timeout"}.get(exc.status_code)
        # A generic HTTP code must not mask a more specific SSH/deployment cause.
        await arecord(level="error" if exc.status_code >= 500 else "warning",
               code=None if exc.status_code >= 500 else code,
               text=exc.detail if isinstance(exc.detail, str) else None, exc=exc, stage="request")
        ctx.failed = True
    return await http_exception_handler(request, exc)


class DiagnosticMiddleware:
    def __init__(self, app, store):
        self.app = app
        self.store = store

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        ctx = DiagnosticContext(self.store, scope)
        token = _current.set(ctx)
        response_status = 0

        async def observed_send(message):
            nonlocal response_status
            if message["type"] == "http.response.start":
                response_status = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, observed_send)
            meta = _metadata(scope)
            if meta is not None and not ctx.failed:
                if response_status >= 500 or response_status in (400, 409, 422, 429):
                    await arecord(level="error" if response_status >= 500 else "warning",
                           code="validation" if response_status in (400, 422) else
                           "conflict" if response_status in (409, 429) else "unexpected",
                           stage="request")
                elif 200 <= response_status < 300 and scope.get("method") in ("POST", "PUT", "PATCH", "DELETE"):
                    await arecord(level="info", code="accepted" if response_status == 202 else "request_completed", stage="request")
        except Exception as exc:
            if _metadata(scope) is not None and not ctx.failed:
                await arecord(exc=exc, stage="request")
            raise
        finally:
            _current.reset(token)
