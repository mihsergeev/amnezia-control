"""Переиспользуемые операции над сервером: проверка по SSH и автонастройка."""

import json
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from app import sshops
from app.config import Settings
from app.models import Server
from app.sshkeys import ensure_panel_key, key_paths


async def run_check(session: AsyncSession, server: Server, settings: Settings) -> None:
    ensure_panel_key(settings.data_dir)
    key_path, _pub = key_paths(settings.data_dir)
    result = await sshops.check_server(
        server.host,
        server.ssh_port,
        server.ssh_user,
        key_path,
        settings.ssh_connect_timeout,
    )
    server.last_check_ok = result.ok
    server.last_check_at = datetime.now(timezone.utc)
    server.last_check_info = json.dumps(result.as_dict(), ensure_ascii=False)
    await session.commit()
    await session.refresh(server)


async def bootstrap_and_check(
    session: AsyncSession,
    server: Server,
    password: str,
    settings: Settings,
    become_password: str | None = None,
) -> tuple[bool, str]:
    """Заходит по паролю, ставит ключ панели, затем проверяет по ключу.

    Возвращает (успех, сообщение об ошибке).
    """
    public_key = ensure_panel_key(settings.data_dir)
    result = await sshops.bootstrap_server(
        server.host,
        server.ssh_port,
        server.ssh_user,
        password,
        public_key,
        settings.panel_ip,
        become_password,
        settings.ssh_connect_timeout,
    )
    if not result.ok:
        detail = result.error
        if result.output:
            detail = f"{detail}: {result.output}"
        return False, detail
    await run_check(session, server, settings)
    return True, ""
