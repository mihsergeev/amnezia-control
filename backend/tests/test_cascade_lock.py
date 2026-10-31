"""Создание каскада под блокировкой обеих нод.

Проверка "сервер уже в каскаде" шла до блокировки: двойной клик проходил ее
дважды и создавал два каскада на одной паре. А блокировки брались в порядке
вход, выход - встречные пары A-B и B-A ждали друг друга.
"""

import asyncio
from contextlib import asynccontextmanager

import httpx
from sqlalchemy import select

from app import cascadejob, nodelock
from app.api import cascades as cascades_api
from app.models import Cascade, Server


async def _servers(session_factory, n=2) -> list[int]:
    async with session_factory() as session:
        rows = [Server(name=f"vpn-{i}", host=f"203.0.113.{20 + i}", last_check_ok=True)
                for i in range(n)]
        session.add_all(rows)
        await session.commit()
        return [r.id for r in rows]


async def test_locked_pair_takes_locks_by_id(monkeypatch) -> None:
    order: list[int] = []

    @asynccontextmanager
    async def fake_locked(server):
        order.append(server.id)
        yield f"conn-{server.id}"

    monkeypatch.setattr(cascades_api, "_locked", fake_locked)
    entry, exit_ = Server(id=7, name="a", host="203.0.113.7"), Server(id=3, name="b", host="203.0.113.3")
    async with cascades_api._locked_pair(entry, exit_) as (ec, xc):
        assert (ec, xc) == ("conn-7", "conn-3")
    assert order == [3, 7]


async def test_double_click_creates_one_cascade(
    client: httpx.AsyncClient, auth_headers, session_factory, monkeypatch
) -> None:
    a, b = await _servers(session_factory)

    @asynccontextmanager
    async def fake_locked(server):
        # настоящая блокировка ноды; пауза внутри дает второму запросу дойти до нее
        async with nodelock.hold("cascade", server.id):
            await asyncio.sleep(0.05)
            yield object()

    async def addresses(conn, entry, exit_):
        return "203.0.113.20", "203.0.113.21"

    monkeypatch.setattr(cascades_api, "_locked", fake_locked)
    monkeypatch.setattr(cascades_api, "_addresses", addresses)
    monkeypatch.setattr(cascadejob, "spawn", lambda app, cid: None)

    body = {"entry_id": a, "exit_id": b, "transport": "gre"}
    r1, r2 = await asyncio.gather(
        client.post("/api/cascades", json=body, headers=auth_headers),
        client.post("/api/cascades", json=body, headers=auth_headers),
    )
    assert sorted([r1.status_code, r2.status_code]) == [202, 409]
    async with session_factory() as session:
        rows = (await session.execute(select(Cascade))).scalars().all()
    assert len(rows) == 1
