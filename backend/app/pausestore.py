"""Хранилище «поставленных на паузу» клиентов (снятых с сервера, но обратимо)."""

import json
from datetime import timezone

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import ClientTrafficSample, PausedClient


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


async def paused_view(
    session: AsyncSession, server_id: int, protocol: str, paused: dict[str, dict], client_ids
) -> dict[str, dict]:
    """Трафик и последнее подключение клиентов на паузе: {client_id: {"rx", "tx",
    "seen"}}. Счетчики, снятые в момент паузы (AWG их запоминает), точнее всего;
    без них - история сборщика (last_traffic)."""
    out = await last_traffic(session, server_id, protocol, client_ids)
    for cid in client_ids:
        data = (paused.get(cid) or {}).get("data") or {}
        if "rx" in data:
            out[cid] = {"rx": data.get("rx") or 0, "tx": data.get("tx") or 0,
                        "seen": data.get("handshake") or out.get(cid, {}).get("seen")}
    return out


async def last_traffic(
    session: AsyncSession, server_id: int, protocol: str, client_ids
) -> dict[str, dict]:
    """Трафик и последняя активность клиентов на паузе по истории сборщика:
    {client_id: {"rx", "tx", "seen"}}. На паузе клиента на ноде нет, она
    отдает нули и "не подключался", а последний снимок сборщика - это счетчики
    на момент паузы. seen (unix-время) - снимок, где трафик последний раз вырос;
    None, если за хранимую историю он не менялся."""
    out: dict[str, dict] = {}
    for cid in client_ids:
        base = select(ClientTrafficSample).where(
            ClientTrafficSample.server_id == server_id,
            ClientTrafficSample.protocol == protocol,
            ClientTrafficSample.client_id == cid,
        )
        last = await session.scalar(base.order_by(ClientTrafficSample.ts.desc()).limit(1))
        if last is None:
            continue
        # последний снимок с другими счетчиками; первый после него - рост трафика
        before = await session.scalar(
            base.where(
                (ClientTrafficSample.rx != last.rx) | (ClientTrafficSample.tx != last.tx)
            ).order_by(ClientTrafficSample.ts.desc()).limit(1)
        )
        seen = None
        if before is not None:
            grew = await session.scalar(
                base.where(ClientTrafficSample.ts > before.ts)
                .order_by(ClientTrafficSample.ts).limit(1)
            )
            if grew is not None:
                ts = grew.ts if grew.ts.tzinfo else grew.ts.replace(tzinfo=timezone.utc)
                seen = int(ts.timestamp())
        out[cid] = {"rx": last.rx, "tx": last.tx, "seen": seen}
    return out


async def paused_ips(session: AsyncSession, server_id: int, protocol: str) -> set[str]:
    """Адреса клиентов AWG на паузе: их нет среди живых пиров, но выдавать их
    новым клиентам нельзя - возобновление вернет адрес прежнему."""
    paused = await list_paused(session, server_id, protocol)
    return {ip for rec in paused.values() if (ip := rec["data"].get("ip"))}


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
