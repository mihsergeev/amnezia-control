"""Ограничения клиентов (срок действия) — хранение и чтение."""

from datetime import datetime

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import ClientLimit


async def set_limit(
    session: AsyncSession,
    server_id: int,
    protocol: str,
    client_id: str,
    name: str,
    expires_at: datetime | None,
) -> None:
    """Устанавливает срок (None → снимает ограничение)."""
    await session.execute(
        delete(ClientLimit).where(
            ClientLimit.server_id == server_id,
            ClientLimit.protocol == protocol,
            ClientLimit.client_id == client_id,
        )
    )
    if expires_at is not None:
        session.add(
            ClientLimit(
                server_id=server_id,
                protocol=protocol,
                client_id=client_id,
                name=name or "",
                expires_at=expires_at,
            )
        )
    await session.commit()


async def limits_map(
    session: AsyncSession, server_id: int, protocol: str
) -> dict[str, datetime | None]:
    rows = await session.execute(
        select(ClientLimit.client_id, ClientLimit.expires_at).where(
            ClientLimit.server_id == server_id,
            ClientLimit.protocol == protocol,
        )
    )
    return {cid: exp for cid, exp in rows.all()}


async def drop_limit(
    session: AsyncSession, server_id: int, protocol: str, client_id: str
) -> None:
    await session.execute(
        delete(ClientLimit).where(
            ClientLimit.server_id == server_id,
            ClientLimit.protocol == protocol,
            ClientLimit.client_id == client_id,
        )
    )
    await session.commit()
