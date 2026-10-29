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
import json
import logging

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import select

from app import audit, expiry, pausestore, protolabel
from app.config import get_settings
from app.deps import CurrentUser, SessionDep
from app.models import AwgConfig, AwgNote, ClientName, OvpnConfig, PausedClient, Server
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

# С какой длины запроса вообще пробуем искать по открытому ключу. Короткие
# запросы — это почти всегда имена, а случайные base64-ключи содержат любые
# короткие сочетания букв, что даёт ложные совпадения.
_MIN_KEY_QUERY = 8


def _key(server_id: int, protocol: str, client_id: str) -> tuple:
    return (server_id, protocol, client_id)


@router.get("/search", response_model=list[ClientSearchHit])
async def search_clients(
    _: CurrentUser,
    session: SessionDep,
    q: str = Query(default="", description="Часть имени, заметки или ключа клиента"),
    paused: bool = Query(default=False, description="Только клиенты на паузе"),
) -> list[ClientSearchHit]:
    """Ищет клиентов по всем серверам и протоколам: по имени, заметке и id/ключу.
    paused=true - все клиенты на паузе (q тогда необязателен и сужает список)."""
    raw = q.strip()
    if len(raw) < 2 and not paused:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT, "Запрос короче 2 символов"
        )
    needle = raw.lower()
    servers = {s.id: s for s in await session.scalars(select(Server))}
    hits: dict[tuple, dict] = {}

    def label_for(server_id: int, protocol: str) -> str:
        return protolabel.protocol_label(servers.get(server_id), protocol)

    def id_match(client_id: str) -> bool:
        """Совпадение по КЛЮЧУ — строго и с учётом регистра.

        Ключи это base64 из случайных байт, и регистронезависимый поиск по ним
        даёт ложные срабатывания: запрос «ifed» (фамилия) поймал чужого клиента,
        у которого в ключе оказалось «IfeD». В списке с преотмеченными строками
        это прямой путь отозвать доступ постороннему. Поэтому по ключу ищем
        как есть — с регистром — и только для запросов длиннее короткого имени.
        """
        return len(raw) >= _MIN_KEY_QUERY and raw in client_id

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
                "protocol_label": label_for(server_id, protocol),
                "name": "",
                "note": "",
                "has_config": False,
            },
        )
        for key, value in fields.items():
            if value:
                item[key] = value

    # клиенты на паузе: с ноды они сняты, но имя и время паузы есть в панели
    paused_rows = {
        _key(r.server_id, r.protocol, r.client_id): r
        for r in await session.scalars(select(PausedClient))
    }
    for k, row in paused_rows.items():
        if (paused and not needle) or needle in (row.name or "").lower() or id_match(
            row.client_id
        ):
            add(row.server_id, row.protocol, row.client_id, name=row.name)
    # в режиме "на паузе" остальные таблицы только дополняют найденных
    # (заметка, выданный конфиг, имя с ноды), новых клиентов не добавляют
    only = set(hits) if paused else None

    def want(server_id: int, protocol: str, client_id: str, *texts: str) -> bool:
        if only is not None:
            return _key(server_id, protocol, client_id) in only
        return any(needle in (t or "").lower() for t in texts) or id_match(client_id)

    # имена с нод (кэш сборщика) — покрывают и клиентов, созданных мимо панели
    for row in await session.scalars(select(ClientName)):
        if want(row.server_id, row.protocol, row.client_id, row.name):
            add(row.server_id, row.protocol, row.client_id, name=row.name)
    # заметки панели (по ключу их не ищем: ключ найдется по имени)
    for row in await session.scalars(select(AwgNote)):
        k = _key(row.server_id, row.protocol, row.public_key)
        if k in only if only is not None else needle in (row.note or "").lower():
            add(row.server_id, row.protocol, row.public_key, note=row.note)
    # выданные конфиги: имя хранится вместе с ними
    for row in await session.scalars(select(AwgConfig)):
        proto = row.protocol or "awg"
        if want(row.server_id, proto, row.public_key, row.name):
            add(row.server_id, proto, row.public_key, name=row.name, has_config=True)
    for row in await session.scalars(select(OvpnConfig)):
        if want(row.server_id, "openvpn", row.client_id, row.name):
            add(row.server_id, "openvpn", row.client_id, name=row.name, has_config=True)

    for k, item in hits.items():
        row = paused_rows.get(k)
        if row is not None:
            item["paused"] = True
            item["paused_at"] = row.paused_at

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

    # клиенты одного протокола на одной ноде отзываются за одно подключение:
    # раньше каждый открывал свое и ждал очереди на ноде, и отзыв десятка
    # клиентов с одного сервера тянулся минуту
    groups: dict[tuple[int, str], list[str]] = {}
    for item in body.items:
        ids = groups.setdefault((item.server_id, item.protocol), [])
        if item.client_id not in ids:
            ids.append(item.client_id)

    def result(sid, protocol, cid, error: str = "") -> RevokeBulkResultItem:
        server = servers.get(sid)
        return RevokeBulkResultItem(
            server_id=sid, server_name=server.name if server else "",
            protocol=protocol, client_id=cid, ok=not error, error=error,
        )

    def message(exc: Exception) -> str:
        return str(exc) or type(exc).__name__

    async def one_group(sid: int, protocol: str, ids: list[str]) -> list[RevokeBulkResultItem]:
        server = servers.get(sid)
        if server is None:
            return [result(sid, protocol, c, "сервер не найден в панели") for c in ids]
        async with sem:
            try:
                errors = await expiry.revoke_many_on_node(
                    server, protocol, ids, key_path, settings.ssh_connect_timeout,
                )
            except expiry.ProtocolGone:
                # протокола на ноде нет совсем - клиентов с ним тоже
                errors = {}
            except Exception as exc:  # noqa: BLE001 — нода недоступна и т.п.
                return [result(sid, protocol, c, message(exc)) for c in ids]
        return [
            result(sid, protocol, c, message(errors[c]) if c in errors else "")
            for c in ids
        ]

    results = [
        r
        for chunk in await asyncio.gather(
            *(one_group(sid, proto, ids) for (sid, proto), ids in groups.items())
        )
        for r in chunk
    ]

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
