"""Общие панельные заметки к клиентам любого протокола.

Хранятся в таблице awg_notes (историческое имя) с полем protocol; public_key —
это client_id клиента (awg-pubkey / xray-uuid / openvpn-cert-id)."""

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AwgNote


async def set_note(
    session: AsyncSession, server_id: int, protocol: str, client_id: str, note: str
) -> None:
    """Upsert заметки (пустая строка — удаляет). Коммитит сам."""
    await session.execute(
        delete(AwgNote).where(
            AwgNote.server_id == server_id,
            AwgNote.protocol == protocol,
            AwgNote.public_key == client_id,
        )
    )
    if note:
        session.add(
            AwgNote(
                server_id=server_id, protocol=protocol,
                public_key=client_id, note=note,
            )
        )
    await session.commit()


async def notes_map(
    session: AsyncSession, server_id: int, protocol: str
) -> dict[str, str]:
    rows = await session.execute(
        select(AwgNote.public_key, AwgNote.note).where(
            AwgNote.server_id == server_id, AwgNote.protocol == protocol,
        )
    )
    return {pk: n for pk, n in rows.all()}


async def clear_note(
    session: AsyncSession, server_id: int, protocol: str, client_id: str
) -> None:
    """Удаляет заметку (при отзыве). БЕЗ commit — коммитит вызывающий."""
    await session.execute(
        delete(AwgNote).where(
            AwgNote.server_id == server_id,
            AwgNote.protocol == protocol,
            AwgNote.public_key == client_id,
        )
    )
