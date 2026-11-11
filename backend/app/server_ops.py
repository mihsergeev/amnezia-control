"""Переиспользуемые операции над сервером: проверка по SSH и автонастройка."""

import asyncio
import ipaddress
import json
import re
from datetime import datetime, timedelta, timezone

from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app import cascade_alias, geo, sshops
from app.config import Settings
from app.models import Server
from app.sshkeys import ensure_panel_key, key_paths

# как часто сборщик переспрашивает адрес выхода клиентов (кнопка «Проверить» - сразу)
EGRESS_TTL = timedelta(hours=1)
ONBOARDING_NAME_PENDING = "onboarding_name_pending"
_CHECK_RESULT_FIELDS = (
    "name", "country", "last_check_ok", "last_check_at", "last_check_info",
    "egress_ip", "egress_country", "egress_org", "egress_at",
)
_CHECK_GUARD_FIELDS = ("host", "ssh_port", "ssh_user", "client_endpoint", *_CHECK_RESULT_FIELDS)


def egress_due(server: Server, now: datetime) -> bool:
    at = server.egress_at
    if at is None:
        return True
    # SQLite отдает дату без пояса; вычитание из aware падало, и сборщик
    # считал такую ноду офлайн
    if at.tzinfo is None:
        at = at.replace(tzinfo=timezone.utc)
    return now - at >= EGRESS_TTL


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


async def store_check_info(session: AsyncSession, server: Server, info: dict) -> None:
    """Persist runtime metadata with the endpoint's user label and geography.

    Every check writer uses this path. The runtime probe deliberately omits
    labels/geography; writing its raw output would erase those display fields.
    The caller owns the transaction.
    """
    info = dict(info)
    if cascade_alias.check_info(server).get(ONBOARDING_NAME_PENDING) is True:
        info[ONBOARDING_NAME_PENDING] = True
    peer = info.get("manual_cascade")
    if isinstance(peer, dict):
        peer = dict(peer)
        info["manual_cascade"] = peer
        peer.pop("exit_country", None)
        if cascade_alias._endpoint(server, info) is not None:
            previous = cascade_alias.check_info(server).get("manual_cascade", {})
            code = ""
            if isinstance(previous, dict) and previous.get("exit_host") == peer["exit_host"]:
                code = previous.get("exit_country", "")
            if not isinstance(code, str) or len(code) != 2 or not code.isascii() or not code.isalpha():
                code = await geo.country_code(peer["exit_host"])
            if isinstance(code, str) and len(code) == 2 and code.isascii() and code.isalpha():
                peer["exit_country"] = code.upper()
    server.last_check_info = json.dumps(await cascade_alias.merge(session, server, info), ensure_ascii=False)


async def run_check(session: AsyncSession, server: Server, settings: Settings) -> None:
    from app import debug_context

    current = server
    original = {field: getattr(current, field) for field in _CHECK_GUARD_FIELDS}
    # Network awaits must never flush a partially prepared observation or
    # overwrite a manual edit made while SSH/GeoIP/egress checks were running.
    server = Server(id=current.id, **original)
    ensure_panel_key(settings.data_dir)
    key_path, _pub = key_paths(settings.data_dir)
    result = await sshops.check_server(
        server.host,
        server.ssh_port,
        server.ssh_user,
        key_path,
        settings.ssh_connect_timeout,
    )
    if not result.ok:
        await debug_context.arecord(operation="ssh", server_id=server.id, stage="connect", text=result.error)
    now = datetime.now(timezone.utc)
    server.last_check_ok = result.ok
    server.last_check_at = now
    info = result.as_dict()
    if result.ok and cascade_alias.check_info(server).get(ONBOARDING_NAME_PENDING) is True:
        # Only new, unnamed wizard endpoints opt in. An existing label, even
        # one equal to an IP address, must never be renamed by a normal check.
        hostname = result.hostname.strip()
        if server.name == server.host and re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}", hostname):
            server.name = hostname
        previous = cascade_alias.check_info(server)
        previous.pop(ONBOARDING_NAME_PENDING, None)
        server.last_check_info = json.dumps(previous, ensure_ascii=False)
    await store_check_info(session, server, info)
    if result.ok and not server.country:
        server.country = geo.normalize_country_code(await geo.country_code(server.host))
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
    await session.execute(
        update(Server).where(
            Server.id == current.id,
            *(getattr(Server, field) == value for field, value in original.items()),
        ).values(**{field: getattr(server, field) for field in _CHECK_RESULT_FIELDS})
        .execution_options(synchronize_session=False)
    )
    await session.commit()
    await session.refresh(current)


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
