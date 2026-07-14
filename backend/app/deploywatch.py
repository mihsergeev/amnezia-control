"""Фоновая слежка за результатом (пере)развёртывания.

Деплой запускается детачед; окно с логом пользователь мог закрыть. Эта задача
дожидается финального маркера в логе на ноде и, если DEPLOY_ERROR, шлёт алерт —
чтобы провал не остался незамеченным."""

import asyncio
import logging

from app import alerts, deploy, server_ops, sshops
from app.config import get_settings
from app.models import Server
from app.sshkeys import key_paths

log = logging.getLogger("acontrol.deploywatch")

# держим ссылки на активные задачи, иначе их может собрать GC
_tasks: set[asyncio.Task] = set()

_POLL_SECONDS = 20
_MAX_POLLS = 18  # ~6 минут — с запасом на сборку образа


async def _watch(
    host: str, port: int, user: str, tag: str, label: str,
    server_id: int, session_factory, settings,
) -> None:
    key_path, _pub = key_paths(settings.data_dir)
    for _ in range(_MAX_POLLS):
        await asyncio.sleep(_POLL_SECONDS)
        try:
            async with sshops.connect(
                host, port, user, key_path, settings.ssh_connect_timeout
            ) as conn:
                st = await deploy.read_status(conn, tag=tag)
        except Exception:  # noqa: BLE001 — нода моргнула, попробуем ещё
            continue
        state = st.get("state")
        if state == "done":
            # После успешного деплоя перечитываем статус ноды, иначе карточка
            # держит доеплойный снимок (docker=false, без протокола) и пугает
            # надписью «docker недоступен», хотя контейнер уже поднят.
            try:
                async with session_factory() as session:
                    server = await session.get(Server, server_id)
                    if server is not None:
                        await server_ops.run_check(session, server, settings)
            except Exception:  # noqa: BLE001 — best-effort, деплой уже успешен
                log.warning(
                    "post-deploy re-check failed for server %s", server_id,
                    exc_info=True,
                )
            return
        if state == "error":
            await alerts.maybe_alert(
                session_factory, settings,
                f"❌ Amnezia Control: развёртывание {tag.upper()} на «{label}» "
                f"завершилось ОШИБКОЙ. Откройте карточку сервера и лог деплоя.",
            )
            return


def spawn(app, server, tag: str) -> None:
    """Запускает фоновую слежку за деплоем (best-effort, не блокирует ответ)."""
    factory = getattr(app.state, "session_factory", None)
    if factory is None:
        return
    task = asyncio.create_task(
        _watch(
            server.host, server.ssh_port, server.ssh_user, tag, server.name,
            server.id, factory, get_settings(),
        )
    )
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)
