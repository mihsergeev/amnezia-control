"""User labels for manually installed peers, bound to the observed endpoint."""

import json

from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AppSetting, Server


def _key(server_id: int) -> str:
    return f"cascade_peer_alias_{server_id}"


def _endpoint(server: Server, info: dict) -> tuple[str, str, int] | None:
    peer = info.get("manual_cascade")
    if not isinstance(peer, dict):
        return None
    host, port = peer.get("exit_host"), peer.get("exit_port")
    if not isinstance(host, str) or not host or type(port) is not int or not 1 <= port <= 65535:
        return None
    return server.host.strip().lower(), host.strip().lower(), port


def check_info(server: Server) -> dict:
    try:
        info = json.loads(server.last_check_info or "{}")
    except (TypeError, ValueError):
        return {}
    return info if isinstance(info, dict) else {}


async def merge(session: AsyncSession, server: Server, info: dict) -> dict:
    """A renamed/reconfigured peer must never inherit the previous peer's label."""
    peer = info.get("manual_cascade")
    if isinstance(peer, dict):
        peer.pop("exit_name", None)
    endpoint = _endpoint(server, info)
    row = await session.get(AppSetting, _key(server.id))
    if endpoint is None or row is None:
        return info
    try:
        saved = json.loads(row.value)
        if not isinstance(saved, dict):
            return info
        if tuple(saved.get("endpoint", [])) != endpoint:
            return info
        name = saved.get("name")
        if isinstance(name, str) and name.strip() and len(name) <= 128:
            peer["exit_name"] = name
    except (TypeError, ValueError):
        pass
    return info


async def set_name(session: AsyncSession, server: Server, name: str) -> None:
    """Caller owns the transaction; labels do not alter remote configuration."""
    info = check_info(server)
    endpoint = _endpoint(server, info)
    if endpoint is None:
        raise ValueError("Сначала проверьте сервер с ручным каскадом")
    row = await session.get(AppSetting, _key(server.id))
    name = name.strip()
    if name:
        if row is None:
            row = AppSetting(key=_key(server.id))
            session.add(row)
        row.value = json.dumps({"endpoint": endpoint, "name": name}, ensure_ascii=False)
    elif row is not None:
        await session.delete(row)
    await session.flush()
    server.last_check_info = json.dumps(await merge(session, server, info), ensure_ascii=False)


async def remove(session: AsyncSession, server_id: int) -> None:
    row = await session.get(AppSetting, _key(server_id))
    if row is not None:
        await session.delete(row)
