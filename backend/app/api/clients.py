"""Глобальный поиск клиентов по всему парку и массовый отзыв.

Зачем: когда человек уходит, его доступы обычно раскиданы по нескольким нодам и
протоколам, и обходить сервер за сервером вручную — долго и легко что-то забыть.
Здесь один запрос ищет по ВСЕМ серверам сразу, а вторым действием всё найденное
отзывается.

Поиск идёт по данным ПАНЕЛИ (кэш имён с нод, заметки, выданные конфиги), а не по
SSH: ходить в десяток нод на каждое нажатие клавиши недопустимо долго. Кэш имён
наполняет фоновый сборщик, поэтому в выдаче видны и клиенты, заведённые мимо
панели. Сам отзыв, разумеется, идёт на ноду — переиспользуем ту же логику, что и
авто-отзыв по сроку (app/expiry), чтобы поведение было ровно одинаковым.
"""

import asyncio
import logging

from fastapi import APIRouter, Query
from sqlalchemy import select

from app import audit, expiry, pausestore
from app.config import get_settings
from app.deps import CurrentUser, SessionDep
from app.models import AwgConfig, AwgNote, ClientName, OvpnConfig, Server
from app.schemas import (
    ClientSearchHit,
    RevokeBulkRequest,
    RevokeBulkResult,
    RevokeBulkResultItem,
)
from app.sshkeys import ensure_panel_key, key_paths

log = logging.getLogger("acontrol.clients")

router = APIRouter(prefix="/clients", tags=["clients"])

# Отзываем ноды ПАРАЛЛЕЛЬНО, но с потолком: массовая чистка по десятку серверов
# иначе растянулась бы на минуты, а без потолка — открыла бы столько SSH-сессий,
# сколько нашлось клиентов.
_MAX_PARALLEL_REVOKES = 5


def _key(server_id: int, protocol: str, client_id: str) -> tuple:
    return (server_id, protocol, client_id)


@router.get("/search", response_model=list[ClientSearchHit])
async def search_clients(
    _: CurrentUser,
    session: SessionDep,
    q: str = Query(min_length=2, description="Часть имени, заметки или ключа клиента"),
) -> list[ClientSearchHit]:
    """Ищет клиентов по всем серверам и протоколам: по имени, заметке и id/ключу."""
    needle = q.strip().lower()
    servers = {s.id: s for s in await session.scalars(select(Server))}
    hits: dict[tuple, dict] = {}

    def add(server_id: int, protocol: str, client_id: str, **fields) -> None:
        if server_id not in servers:
            return  # сервер удалён, а хвосты в таблицах остались
        k = _key(server_id, protocol, client_id)
        item = hits.setdefault(
            k,
            {
                "server_id": server_id,
                "server_name": servers[server_id].name,
                "protocol": protocol,
                "client_id": client_id,
                "name": "",
                "note": "",
                "has_config": False,
            },
        )
        for key, value in fields.items():
            if value:
                item[key] = value

    # имена с нод (кэш сборщика) — покрывают и клиентов, созданных мимо панели
    for row in await session.scalars(select(ClientName)):
        if needle in (row.name or "").lower() or needle in row.client_id.lower():
            add(row.server_id, row.protocol, row.client_id, name=row.name)
    # заметки панели
    for row in await session.scalars(select(AwgNote)):
        if needle in (row.note or "").lower():
            add(row.server_id, row.protocol, row.public_key, note=row.note)
    # выданные конфиги: имя хранится вместе с ними
    for row in await session.scalars(select(AwgConfig)):
        if needle in (row.name or "").lower() or needle in row.public_key.lower():
            add(row.server_id, "awg", row.public_key, name=row.name, has_config=True)
    for row in await session.scalars(select(OvpnConfig)):
        if needle in (row.name or "").lower() or needle in row.client_id.lower():
            add(row.server_id, "openvpn", row.client_id, name=row.name, has_config=True)

    # заметки хранятся без привязки к тому, жив ли клиент, поэтому сортируем
    # предсказуемо: сервер → протокол → имя
    return [
        ClientSearchHit(**item)
        for item in sorted(
            hits.values(),
            key=lambda i: (i["server_name"], i["protocol"], i["name"].lower()),
        )
    ]


@router.post("/revoke-bulk", response_model=RevokeBulkResult)
async def revoke_bulk(
    body: RevokeBulkRequest, user: CurrentUser, session: SessionDep
) -> RevokeBulkResult:
    """Отзывает перечисленных клиентов на их серверах.

    Каждый клиент обрабатывается независимо: недоступная нода не срывает всю
    операцию — по ней вернётся ошибка, остальные отзовутся. Ответ поимённый,
    чтобы было видно, что именно не удалось и где повторить.
    """
    settings = get_settings()
    ensure_panel_key(settings.data_dir)
    key_path, _pub = key_paths(settings.data_dir)
    servers = {s.id: s for s in await session.scalars(select(Server))}
    sem = asyncio.Semaphore(_MAX_PARALLEL_REVOKES)

    async def one(item) -> RevokeBulkResultItem:
        server = servers.get(item.server_id)
        if server is None:
            return RevokeBulkResultItem(
                server_id=item.server_id, server_name="", protocol=item.protocol,
                client_id=item.client_id, ok=False, error="сервер не найден в панели",
            )
        async with sem:
            try:
                await expiry.revoke_on_node(
                    server, item.protocol, item.client_id, key_path,
                    settings.ssh_connect_timeout,
                )
            except Exception as exc:  # noqa: BLE001 — нода недоступна и т.п.
                return RevokeBulkResultItem(
                    server_id=item.server_id, server_name=server.name,
                    protocol=item.protocol, client_id=item.client_id, ok=False,
                    error=str(exc) or type(exc).__name__,
                )
        return RevokeBulkResultItem(
            server_id=item.server_id, server_name=server.name,
            protocol=item.protocol, client_id=item.client_id, ok=True,
        )

    results = await asyncio.gather(*(one(i) for i in body.items))

    # чистим панельные данные только для успешно отозванных: если нода была
    # недоступна, клиент на ней остался, и стирать его следы в панели нельзя —
    # иначе он пропал бы из поиска и повторить отзыв стало бы нечем
    for res in results:
        if not res.ok:
            continue
        await expiry.cleanup_client_db(
            session, res.server_id, res.protocol, res.client_id
        )
        await pausestore.drop(session, res.server_id, res.protocol, res.client_id)
        await session.execute(
            ClientName.__table__.delete().where(
                ClientName.server_id == res.server_id,
                ClientName.protocol == res.protocol,
                ClientName.client_id == res.client_id,
            )
        )
    await session.commit()

    ok_count = sum(1 for r in results if r.ok)
    if ok_count:
        await audit.record(
            session, user.username, "clients_bulk_revoke",
            body.query or "", f"отозвано {ok_count} из {len(results)}",
        )
    return RevokeBulkResult(
        revoked=ok_count, failed=len(results) - ok_count, items=list(results)
    )
