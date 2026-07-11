from fastapi import APIRouter, Request, Response, status
from sqlalchemy import text

from app.config import get_settings
from app.deps import CurrentUser
from app.schemas import ConfigOut

router = APIRouter(tags=["system"])


@router.get("/health")
async def health(request: Request, response: Response) -> dict[str, str]:
    """Проверяет и БД: раньше отдавал ok при мёртвом Postgres (compose-healthcheck
    и фронт считали панель здоровой). Теперь при недоступной БД — 503, чтобы
    healthcheck перезапустил backend. Версия отдаётся всегда (не ломаем фронт)."""
    settings = get_settings()
    db = "unknown"
    factory = getattr(request.app.state, "session_factory", None)
    if factory is not None:
        try:
            async with factory() as session:
                await session.execute(text("SELECT 1"))
            db = "ok"
        except Exception:  # noqa: BLE001 — БД недоступна
            db = "down"
            response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return {
        "status": "ok" if db != "down" else "degraded",
        "db": db,
        "version": settings.version,
    }


@router.get("/config", response_model=ConfigOut)
async def config(_: CurrentUser) -> ConfigOut:
    settings = get_settings()
    return ConfigOut(
        default_ssh_user=settings.default_ssh_user, panel_ip=settings.panel_ip
    )
