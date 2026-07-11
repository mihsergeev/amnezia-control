"""Авто-отзыв истёкших клиентов по сроку действия (ClientLimit.expires_at)."""

import asyncio
import logging
from datetime import datetime, timezone

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app import audit, awg, openvpn, sshops, xray
from app.config import Settings
from app.models import AwgConfig, AwgNote, ClientLimit, OvpnConfig, Server
from app.sshkeys import ensure_panel_key, key_paths

log = logging.getLogger("acontrol.expiry")


async def _revoke_ssh(server: Server, protocol: str, client_id: str, key_path, timeout):
    # жёсткий таймаут: без него зависший docker exec на одной ноде застопорил бы
    # весь последовательный проход expiry — остальные истёкшие не отозвались бы.
    async with asyncio.timeout(max(timeout * 4, 30)):
        await _revoke_ssh_inner(server, protocol, client_id, key_path, timeout)


async def _revoke_ssh_inner(
    server: Server, protocol: str, client_id: str, key_path, timeout
):
    async with sshops.connect(
        server.host, server.ssh_port, server.ssh_user, key_path, timeout
    ) as conn:
        if protocol == "awg":
            state = await awg.read_state(conn, server.host)
            await awg.revoke_client(conn, state.container, state.interface, client_id)
        elif protocol == "openvpn":
            container = await openvpn.detect_container(conn)
            await openvpn.revoke_client(conn, container, client_id)
        elif protocol == "xray":
            container = await xray.detect_container(conn)
            await xray.revoke_client(conn, container, client_id)


async def _cleanup_db(session: AsyncSession, server_id, protocol, client_id) -> None:
    if protocol == "awg":
        await session.execute(
            delete(AwgConfig).where(
                AwgConfig.server_id == server_id, AwgConfig.public_key == client_id
            )
        )
        await session.execute(
            delete(AwgNote).where(
                AwgNote.server_id == server_id, AwgNote.public_key == client_id
            )
        )
    elif protocol == "openvpn":
        await session.execute(
            delete(OvpnConfig).where(
                OvpnConfig.server_id == server_id, OvpnConfig.client_id == client_id
            )
        )
    await session.execute(
        delete(ClientLimit).where(
            ClientLimit.server_id == server_id,
            ClientLimit.protocol == protocol,
            ClientLimit.client_id == client_id,
        )
    )


async def expiry_once(
    session_factory: async_sessionmaker[AsyncSession], settings: Settings
) -> int:
    ensure_panel_key(settings.data_dir)
    key_path, _pub = key_paths(settings.data_dir)
    now = datetime.now(timezone.utc)
    async with session_factory() as session:
        expired = list(
            await session.scalars(
                select(ClientLimit).where(
                    ClientLimit.expires_at.is_not(None),
                    ClientLimit.expires_at < now,
                )
            )
        )
    revoked = 0
    for lim in expired:
        async with session_factory() as session:
            server = await session.get(Server, lim.server_id)
        if server is None:
            async with session_factory() as session:
                await session.execute(
                    delete(ClientLimit).where(ClientLimit.id == lim.id)
                )
                await session.commit()
            continue
        try:
            await _revoke_ssh(
                server, lim.protocol, lim.client_id, key_path,
                settings.ssh_connect_timeout,
            )
        except Exception:  # noqa: BLE001 — нода недоступна: оставим, повторим позже
            log.warning(
                "истёкший %s/%s: нода %s недоступна, отложил",
                lim.protocol, lim.client_id, server.name,
            )
            continue
        async with session_factory() as session:
            await _cleanup_db(session, lim.server_id, lim.protocol, lim.client_id)
            await audit.record(
                session, "система", f"{lim.protocol}_expired",
                server.name, lim.name or lim.client_id,
            )
        revoked += 1
    if revoked:
        log.info("авто-отзыв истёкших клиентов: %d", revoked)
    return revoked


async def expiry_loop(
    session_factory: async_sessionmaker[AsyncSession], settings: Settings
) -> None:
    if settings.expiry_interval <= 0:
        log.info("авто-отзыв по сроку выключен (expiry_interval=0)")
        return
    while True:
        try:
            await expiry_once(session_factory, settings)
        except Exception:  # noqa: BLE001 — цикл не должен падать
            log.exception("ошибка авто-отзыва по сроку")
        await asyncio.sleep(settings.expiry_interval)
