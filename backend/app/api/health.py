from fastapi import APIRouter

from app.config import get_settings
from app.deps import CurrentUser
from app.schemas import ConfigOut

router = APIRouter(tags=["system"])


@router.get("/health")
async def health() -> dict[str, str]:
    settings = get_settings()
    return {"status": "ok", "version": settings.version}


@router.get("/config", response_model=ConfigOut)
async def config(_: CurrentUser) -> ConfigOut:
    settings = get_settings()
    return ConfigOut(
        default_ssh_user=settings.default_ssh_user, panel_ip=settings.panel_ip
    )
