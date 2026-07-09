import asyncio
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI

from app.api import (
    alerts,
    audit,
    auth,
    awg,
    backup,
    fullaccess,
    health,
    importer,
    openvpn,
    servers,
    stats,
    xray,
)
from app.autobackup import backup_loop
from app.bootstrap import ensure_admin
from app.collector import collector_loop
from app.expiry import expiry_loop
from app.config import get_settings
from app.db import create_engine_and_factory
from app.sshkeys import ensure_panel_key


_WEAK_SECRETS = {"", "changeme", "dev-insecure-change-me"}
_WEAK_PASSWORDS = {"", "changeme", "admin"}


def _enforce_secrets(settings) -> None:
    """Отказываемся стартовать в проде с дефолтными/слабыми секретами."""
    if settings.debug:
        return
    if settings.jwt_secret in _WEAK_SECRETS or len(settings.jwt_secret) < 32:
        raise RuntimeError(
            "VPNPANEL_JWT_SECRET не задан или слишком слабый — задайте случайный "
            "секрет (openssl rand -hex 32). Панель не запущена в целях безопасности."
        )
    if settings.admin_password in _WEAK_PASSWORDS:
        raise RuntimeError(
            "VPNPANEL_ADMIN_PASSWORD не задан или дефолтный — задайте надёжный "
            "пароль. Панель не запущена в целях безопасности."
        )


def create_app() -> FastAPI:
    settings = get_settings()
    engine, session_factory = create_engine_and_factory(settings.db_url)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        _enforce_secrets(settings)
        ensure_panel_key(settings.data_dir)
        await ensure_admin(session_factory, settings)
        task = asyncio.create_task(collector_loop(session_factory, settings))
        backup_task = asyncio.create_task(backup_loop(session_factory, settings))
        expiry_task = asyncio.create_task(expiry_loop(session_factory, settings))
        yield
        task.cancel()
        backup_task.cancel()
        expiry_task.cancel()
        await engine.dispose()

    # доки/схему API отдаём только в debug — в проде не раскрываем поверхность API
    docs_url = "/api/docs" if settings.debug else None
    openapi_url = "/api/openapi.json" if settings.debug else None
    app = FastAPI(
        title=settings.app_name,
        version=settings.version,
        docs_url=docs_url,
        openapi_url=openapi_url,
        lifespan=lifespan,
    )
    app.state.engine = engine
    app.state.session_factory = session_factory

    app.include_router(health.router, prefix="/api")
    app.include_router(auth.router, prefix="/api")
    app.include_router(servers.router, prefix="/api")
    app.include_router(awg.router, prefix="/api")
    app.include_router(openvpn.router, prefix="/api")
    app.include_router(xray.router, prefix="/api")
    app.include_router(importer.router, prefix="/api")
    app.include_router(stats.router, prefix="/api")
    app.include_router(backup.router, prefix="/api")
    app.include_router(fullaccess.router, prefix="/api")
    app.include_router(audit.router, prefix="/api")
    app.include_router(alerts.router, prefix="/api")
    return app


app = create_app()
