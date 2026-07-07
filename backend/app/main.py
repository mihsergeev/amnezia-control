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


def create_app() -> FastAPI:
    settings = get_settings()
    engine, session_factory = create_engine_and_factory(settings.db_url)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
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

    app = FastAPI(
        title=settings.app_name,
        version=settings.version,
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
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
