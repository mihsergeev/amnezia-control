import asyncio
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from app.api import (
    alerts,
    apikeys,
    audit,
    auth,
    awg,
    awg_legacy,
    backup,
    fullaccess,
    health,
    importer,
    openvpn,
    servers,
    stats,
    v1,
    xray,
)
from app.autobackup import backup_loop
from app.bootstrap import ensure_admin
from app.collector import collector_loop
from app.expiry import expiry_loop
from app.heartbeat import heartbeat_loop
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
        hb_task = asyncio.create_task(heartbeat_loop(session_factory, settings))
        yield
        task.cancel()
        backup_task.cancel()
        expiry_task.cancel()
        hb_task.cancel()
        await engine.dispose()

    # Доки/схему отдаём в debug ИЛИ когда явно включены (api_docs) — интегратору
    # нужен читаемый контракт /api/v1. Сами ручки при этом всё равно закрыты
    # (JWT или X-API-Key), доки раскрывают только форму запросов.
    show_docs = settings.debug or settings.api_docs
    app = FastAPI(
        title=settings.app_name,
        version=settings.version,
        # Штатную страницу доков отключаем и отдаём свою (см. ниже): встроенная
        # тянет JS/CSS с внешнего CDN и инициализируется ИНЛАЙН-скриптом, а CSP
        # панели (script-src 'self', без 'unsafe-inline') блокирует и то, и то —
        # страница открывалась пустой.
        docs_url=None,
        openapi_url="/api/openapi.json" if show_docs else None,
        lifespan=lifespan,
        description=(
            "Панель управления VPN-серверами.\n\n"
            "**`/api/v1/*` — интеграционный API** со стабильным контрактом для "
            "внешних систем: аутентификация ключом в заголовке `X-API-Key` "
            "(создать ключ: в панели → «API-ключи»). Права ключа ограничены "
            "клиентскими операциями AmneziaWG и чтением списка серверов.\n\n"
            "Остальные ручки обслуживают веб-интерфейс панели, требуют "
            "пользовательский JWT и могут меняться без сохранения совместимости."
        ),
    )
    app.state.engine = engine
    app.state.session_factory = session_factory

    app.include_router(health.router, prefix="/api")
    app.include_router(auth.router, prefix="/api")
    app.include_router(servers.router, prefix="/api")
    app.include_router(awg.router, prefix="/api")
    app.include_router(awg_legacy.router, prefix="/api")
    app.include_router(openvpn.router, prefix="/api")
    app.include_router(xray.router, prefix="/api")
    app.include_router(importer.router, prefix="/api")
    app.include_router(stats.router, prefix="/api")
    app.include_router(backup.router, prefix="/api")
    app.include_router(fullaccess.router, prefix="/api")
    app.include_router(audit.router, prefix="/api")
    app.include_router(alerts.router, prefix="/api")
    app.include_router(apikeys.router, prefix="/api")
    app.include_router(v1.router, prefix="/api")

    if show_docs:
        # Ассеты берём со своего origin (/swagger/* раздаёт nginx фронтенда из
        # npm-пакета swagger-ui-dist), инициализацию — отдельным файлом, а не
        # инлайном: так строгая CSP не ослабляется и внешний CDN не нужен —
        # доки работают и в сети, где jsdelivr недоступен.
        @app.get("/api/docs", include_in_schema=False)
        async def swagger_ui() -> HTMLResponse:
            return HTMLResponse(
                "<!DOCTYPE html>"
                '<html lang="ru"><head><meta charset="utf-8">'
                '<meta name="viewport" content="width=device-width,initial-scale=1">'
                '<meta name="robots" content="noindex,nofollow">'
                f"<title>{settings.app_name} — API</title>"
                '<link rel="stylesheet" href="/swagger/swagger-ui.css">'
                "</head><body>"
                '<div id="swagger-ui"></div>'
                '<script src="/swagger/swagger-ui-bundle.js"></script>'
                '<script src="/swagger/swagger-init.js"></script>'
                "</body></html>"
            )

    return app


app = create_app()
