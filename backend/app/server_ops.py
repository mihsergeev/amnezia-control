"""Переиспользуемые операции над сервером: проверка по SSH и автонастройка."""

import asyncio
import ipaddress
import json
from datetime import datetime, timedelta, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from app import geo, sshops
from app.config import Settings
from app.models import Server
from app.sshkeys import ensure_panel_key, key_paths

# как часто сборщик переспрашивает адрес выхода клиентов (кнопка «Проверить» - сразу)
EGRESS_TTL = timedelta(hours=1)


def egress_due(server: Server, now: datetime) -> bool:
    return server.egress_at is None or now - server.egress_at >= EGRESS_TTL


async def _host_addrs(host: str) -> set[str]:
    try:
        return {str(ipaddress.ip_address(host))}
    except ValueError:
        pass
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, None)
    except OSError:
        return set()
    return {i[4][0] for i in infos}


async def describe_egress(host: str, egress_ip: str) -> dict[str, str] | None:
    """Поля egress_* для сервера по адресу выхода с ноды.

    None - выход не определили (не трогаем прежнее значение); пустые поля -
    клиенты выходят с адреса самого сервера, схему показывать не нужно.
    """
    if not egress_ip:
        return None
    if egress_ip in await _host_addrs(host):
        return {"egress_ip": "", "egress_country": "", "egress_org": ""}
    country, org = await geo.ip_info(egress_ip)
    return {"egress_ip": egress_ip, "egress_country": country, "egress_org": org}


def apply_egress(server: Server, desc: dict[str, str] | None, now: datetime) -> None:
    server.egress_at = now
    if desc is not None:
        for k, v in desc.items():
            setattr(server, k, v)


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
    now = datetime.now(timezone.utc)
    server.last_check_ok = result.ok
    server.last_check_at = now
    server.last_check_info = json.dumps(result.as_dict(), ensure_ascii=False)
    if result.ok and result.amnezia_containers:
        egress = None
        try:
            async with sshops.connect(
                server.host, server.ssh_port, server.ssh_user, key_path,
                settings.ssh_connect_timeout,
            ) as conn:
                egress = await sshops.probe_egress(conn)
        except Exception:  # noqa: BLE001 — адрес выхода не критичен для проверки
            egress = None
        if egress is not None:
            apply_egress(server, await describe_egress(server.host, egress), now)
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
    key_path, _pub = key_paths(settings.data_dir)
    result = await sshops.bootstrap_server(
        server.host,
        server.ssh_port,
        server.ssh_user,
        password,
        public_key,
        settings.panel_ip,
        become_password,
        settings.ssh_connect_timeout,
        key_path=key_path,
    )
    if not result.ok:
        detail = result.error
        if result.output:
            detail = f"{detail}: {result.output}"
        return False, detail
    await run_check(session, server, settings)
    return True, ""
