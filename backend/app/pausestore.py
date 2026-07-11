"""Хранилище «поставленных на паузу» клиентов (снятых с сервера, но обратимо)."""

import json

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import PausedClient


async def list_paused(
    session: AsyncSession, server_id: int, protocol: str
) -> dict[str, dict]:
    """{client_id: {"name": str, "data": dict}} — все клиенты на паузе."""
    rows = await session.scalars(
        select(PausedClient).where(
            PausedClient.server_id == server_id,
            PausedClient.protocol == protocol,
        )
    )
    out: dict[str, dict] = {}
    for r in rows:
        try:
            data = json.loads(r.data or "{}")
        except (json.JSONDecodeError, ValueError):
            data = {}
        out[r.client_id] = {"name": r.name, "data": data}
    return out


async def add(
    session: AsyncSession, server_id: int, protocol: str,
    client_id: str, name: str, data: dict,
) -> None:
    await session.execute(
        delete(PausedClient).where(
            PausedClient.server_id == server_id,
            PausedClient.protocol == protocol,
            PausedClient.client_id == client_id,
        )
    )
    session.add(
        PausedClient(
            server_id=server_id, protocol=protocol, client_id=client_id,
            name=name, data=json.dumps(data, ensure_ascii=False),
        )
    )
    await session.commit()


async def pop(
    session: AsyncSession, server_id: int, protocol: str, client_id: str
) -> dict | None:
    """Возвращает {"name", "data"} и удаляет запись; None, если не на паузе."""
    row = await session.scalar(
        select(PausedClient).where(
            PausedClient.server_id == server_id,
            PausedClient.protocol == protocol,
            PausedClient.client_id == client_id,
        )
    )
    if row is None:
        return None
    try:
        data = json.loads(row.data or "{}")
    except (json.JSONDecodeError, ValueError):
        data = {}
    payload = {"name": row.name, "data": data}
    await session.delete(row)
    await session.commit()
    return payload


async def drop(
    session: AsyncSession, server_id: int, protocol: str, client_id: str
) -> None:
    """Удаляет запись о паузе без возврата (напр. при полном отзыве). Без commit."""
    await session.execute(
        delete(PausedClient).where(
            PausedClient.server_id == server_id,
            PausedClient.protocol == protocol,
            PausedClient.client_id == client_id,
        )
    )
