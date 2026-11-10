"""Фоновая слежка за результатом (пере)развёртывания.

Деплой запускается детачед; окно с логом пользователь мог закрыть. Эта задача
дожидается финального маркера в логе на ноде и, если DEPLOY_ERROR, шлёт алерт —
чтобы провал не остался незамеченным."""

import asyncio
import logging

from app import alerts, deploy, server_ops, sshops
from app.config import get_settings
from app import debug_context
from app.models import Server
from app.sshkeys import key_paths

log = logging.getLogger("acontrol.deploywatch")

# держим ссылки на активные задачи, иначе их может собрать GC
_tasks: set[asyncio.Task] = set()

_POLL_SECONDS = 20
_MAX_POLLS = 18  # ~6 минут — с запасом на сборку образа


async def _watch(
    host: str, port: int, user: str, tag: str, label: str,
    server_id: int, session_factory, settings, diagnostic_store=None,
) -> None:
    with debug_context.bind(store=diagnostic_store, operation="deploy", protocol=tag, server_id=server_id):
        try:
            await _watch_job(host, port, user, tag, label, server_id, session_factory, settings)
        except Exception as exc:
            await debug_context.arecord(exc=exc, stage="verify")
            raise


async def _watch_job(host, port, user, tag, label, server_id, session_factory, settings) -> None:
    async def report(**fields):
        await debug_context.arecord(**fields)

    await report(level="info", code="started", stage="install")
    key_path, _pub = key_paths(settings.data_dir)
    # срок на один опрос: зависшая нода иначе остановила бы слежку навсегда
    step = max(settings.ssh_connect_timeout * 4, 30)
    reported_poll_error = False
    for _ in range(_MAX_POLLS):
        await asyncio.sleep(_POLL_SECONDS)
        try:
            async with asyncio.timeout(step), sshops.connect(
                host, port, user, key_path, settings.ssh_connect_timeout
            ) as conn:
                st = await deploy.read_status(conn, tag=tag)
        except Exception as exc:  # noqa: BLE001 — нода моргнула, попробуем ещё
            if not reported_poll_error:
                await report(level="warning", exc=exc, stage="verify")
                reported_poll_error = True
            continue
        state = st.get("state")
        if state == "done":
            await report(level="info", code="completed", stage="install")
            # После успешного деплоя перечитываем статус ноды, иначе карточка
            # держит доеплойный снимок (docker=false, без протокола) и пугает
            # надписью «docker недоступен», хотя контейнер уже поднят.
            try:
                async with session_factory() as session:
                    server = await session.get(Server, server_id)
                    if server is not None:
                        await server_ops.run_check(session, server, settings)
            except Exception as exc:  # noqa: BLE001 — best-effort, деплой уже успешен
                await report(level="warning", exc=exc, stage="verify")
                log.warning(
                    "post-deploy re-check failed for server %s", server_id,
                    exc_info=True,
                )
            return
        if state == "error":
            await report(text=st.get("log", ""), stage="install")
            await alerts.maybe_alert(
                session_factory, settings,
                alerts.Card("crit", "🚀", alerts.t("Развертывание {proto} не удалось",
                                                    proto=tag.upper()),
                            alerts.t("лог в карточке сервера"), subject=label),
                server_id=server_id,
            )
            return
    await report(code="timeout", stage="verify")


def spawn(app, server, tag: str) -> None:
    """Запускает фоновую слежку за деплоем (best-effort, не блокирует ответ)."""
    factory = getattr(app.state, "session_factory", None)
    if factory is None:
        return
    task = asyncio.create_task(
        _watch(
            server.host, server.ssh_port, server.ssh_user, tag, server.name,
            server.id, factory, get_settings(), getattr(app.state, "debug_logs", None),
        )
    )
    _tasks.add(task)
    def done(t):
        _tasks.discard(t)
        if not t.cancelled() and t.exception() is not None:
            log.error("deployment watcher failed", exc_info=t.exception())

    task.add_done_callback(done)
