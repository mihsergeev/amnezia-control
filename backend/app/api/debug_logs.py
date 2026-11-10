from typing import Literal

from fastapi import APIRouter, Query, Request, Response
from starlette.concurrency import run_in_threadpool

from app.debuglog import MAX_BYTES, RETENTION_DAYS, build_archive, get_store
from app.config import get_settings
from app.deps import CurrentUser

router = APIRouter(prefix="/debug-logs", tags=["debug-logs"])
Level = Literal["info", "warning", "error"]
Operation = Literal["request", "ssh", "deploy", "cascade", "probe", "clients", "backup", "import", "alerts", "system"]


@router.get("")
async def list_debug_logs(request: Request, response: Response, _: CurrentUser, limit: int = Query(200, ge=1, le=1000), level: Level | None = None, operation: Operation | None = None) -> dict:
    store = get_store(request)
    response.headers["Cache-Control"] = "no-store"
    events = await run_in_threadpool(store.read, limit, level=level, operation=operation) if store else []
    return {"events": events, "retention_days": RETENTION_DAYS, "max_bytes": MAX_BYTES}


@router.get("/download")
async def download_debug_logs(request: Request, _: CurrentUser, level: Level | None = None, operation: Operation | None = None) -> Response:
    store = get_store(request)
    version = get_settings().version
    data = await run_in_threadpool(store.download, version, level=level, operation=operation) if store else build_archive([], version)
    return Response(data, media_type="application/zip", headers={"Content-Disposition": 'attachment; filename="acontrol-debug-logs.zip"', "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})
