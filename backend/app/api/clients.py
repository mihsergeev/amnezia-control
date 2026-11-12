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
from sqlalchemy.ext.asyncio import AsyncSession

from app import audit, bulk_issue_state, expiry, nodelock, pausestore, protolabel
from app.config import get_settings
from app.deps import CurrentUser, SessionDep
from app.metadata_schemas import BulkClientMetadataRequest, ClientMetadataRequest, metadata_identity
from app.models import AwgConfig, AwgNote, ClientName, NativeVpnConfig, OvpnConfig, PausedClient, Server
from app.schemas import (
    ClientSearchHit,
    RevokeBulkRequest,
    RevokeBulkResult,
    RevokeBulkResultItem,
)
from app.sshkeys import ensure_panel_key, key_paths

log = logging.getLogger("acontrol.clients")

router = APIRouter(prefix="/clients", tags=["clients"])
metadata_router = APIRouter(tags=["clients"])


async def _metadata_client_ids(server, protocol, client_ids, user, session):
    """Resolve all identities before any labels change; fetch node state at most once."""
    models = [(ClientName, ClientName.client_id), (PausedClient, PausedClient.client_id)]
    if protocol in ("awg", "awg3", "awglegacy"):
        models.append((AwgConfig, AwgConfig.public_key))
    elif protocol == "openvpn":
        models.append((OvpnConfig, OvpnConfig.client_id))
    elif protocol in ("wireguard", "openvpn-native"):
        models.append((NativeVpnConfig, NativeVpnConfig.client_id))
    requested = {metadata_identity(protocol, cid) for cid in client_ids}
    found = {}
    for model, key in models:
        query = select(key).where(model.server_id == server.id)
        if hasattr(model, "protocol"):
            query = query.where(model.protocol == protocol)
        if protocol != "xray":
            query = query.where(key.in_(requested))
        for cid in await session.scalars(query):
            identity = metadata_identity(protocol, cid)
            if identity in requested:
                found.setdefault(identity, cid)
        if found.keys() >= requested:
            break
    if found.keys() < requested:
        from app.api import awg, awg3, awg_legacy, native_vpn, openvpn, xray
        readers = {"awg": awg.get_awg, "awg3": awg3.get_awg3,
                   "awglegacy": awg_legacy.get_legacy, "openvpn": openvpn.get_openvpn,
                   "xray": xray.get_xray}
        try:
            if protocol in readers:
                state = await readers[protocol](server.id, user, session)
                ids = (getattr(c, "public_key", getattr(c, "client_id", None)) for c in state.clients)
            else:
                async with native_vpn.connection(server, protocol) as conn:
                    state = await native_vpn.native_vpn.state(conn, protocol, server.host)
                ids = (c.get("public_key", c.get("client_id")) for c in state["clients"])
        except Exception as exc:
            # Reader errors may contain SSH output. Grouping needs only a safe
            # failure category, never node output or configuration contents.
            failure = exc if isinstance(exc, HTTPException) else native_vpn.failure(exc)
            raise HTTPException(failure.status_code, "Не удалось проверить клиентов на ноде") from None
        for cid in ids:
            if cid is not None:
                identity = metadata_identity(protocol, cid)
                if identity in requested:
                    found.setdefault(identity, cid)
    if found.keys() < requested:
        raise HTTPException(404, "Клиент не найден")
    return client_ids


@metadata_router.post("/servers/{server_id}/client-metadata/bulk", status_code=204)
async def update_client_metadata_bulk(server_id: int, body: BulkClientMetadataRequest,
                                      user: CurrentUser, session: SessionDep):
    from app import client_metadata

    async with nodelock.hold(body.protocol, server_id):
        try:
            server = await session.get(Server, server_id)
            if server is None:
                raise HTTPException(404, "Сервер не найден")
            ids = await _metadata_client_ids(server, body.protocol, body.client_ids, user, session)
            await client_metadata.set_group(session, server_id, body.protocol, ids, body.group_name)
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        await audit.record(session, user.username, "clients_bulk_group",
                           f"server_id={server_id};protocol={body.protocol}", f"count={len(ids)}")


@metadata_router.post("/servers/{server_id}/client-metadata", status_code=204)
async def update_client_metadata(server_id: int, body: ClientMetadataRequest,
                                 _: CurrentUser, session: SessionDep):
    from app import client_metadata

    async with nodelock.hold(body.protocol, server_id):
        if await session.get(Server, server_id) is None:
            raise HTTPException(404, "Сервер не найден")
        protocol, cid = body.protocol, body.client_id
        models = [(ClientName, ClientName.client_id), (PausedClient, PausedClient.client_id)]
        if protocol in ("awg", "awg3", "awglegacy"):
            models.append((AwgConfig, AwgConfig.public_key))
        elif protocol == "openvpn":
            models.append((OvpnConfig, OvpnConfig.client_id))
        elif protocol in ("wireguard", "openvpn-native"):
            models.append((NativeVpnConfig, NativeVpnConfig.client_id))
        found = False
        for model, key in models:
            query = select(key).where(model.server_id == server_id, key == cid)
            if hasattr(model, "protocol"):
                query = query.where(model.protocol == protocol)
            if await session.scalar(query) is not None:
                found = True
                break
        if not found:
            # A newly issued Xray client may not have reached the collector yet;
            # external clients likewise have no stored profile. Read the node only.
            from app.api import awg, awg3, awg_legacy, native_vpn, openvpn, xray
            readers = {"awg": awg.get_awg, "awg3": awg3.get_awg3,
                       "awglegacy": awg_legacy.get_legacy, "openvpn": openvpn.get_openvpn,
                       "xray": xray.get_xray}
            if protocol in readers:
                state = await readers[protocol](server_id, _, session)
                clients = state.clients
                found = any(getattr(c, "public_key", getattr(c, "client_id", None)) == cid for c in clients)
            else:
                server = await session.get(Server, server_id)
                try:
                    async with native_vpn.connection(server, protocol) as conn:
                        state = await native_vpn.native_vpn.state(conn, protocol, server.host)
                except Exception as exc:
                    raise native_vpn.failure(exc) from None
                found = any(c.get("public_key", c.get("client_id")) == cid for c in state["clients"])
        if not found:
            raise HTTPException(404, "Клиент не найден")
        await client_metadata.set_labels(session, server_id, protocol, cid,
                                         body.group_name, body.device_name)
        await session.commit()

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

    # Сначала все сведения о клиентах, потом отбор, потом дополнение. Совпасть
    # может одно поле (заметка), а имя и выданный конфиг лежат в других
    # таблицах. Раньше дополнялись только таблицы, где совпал запрос, и
    # найденные по заметке клиенты выходили "без имени".
    # (сервер, протокол, клиент), поля, текст для поиска, искать ли по ключу
    rows: list[tuple[tuple[int, str, str], dict, str, bool]] = []
    # имена с нод (кэш сборщика) — покрывают и клиентов, созданных мимо панели
    for row in await session.scalars(select(ClientName)):
        rows.append(((row.server_id, row.protocol, row.client_id), {"name": row.name},
                     row.name, True))
    # заметки панели (по ключу их не ищем: ключ найдется по имени)
    for row in await session.scalars(select(AwgNote)):
        rows.append(((row.server_id, row.protocol, row.public_key), {"note": row.note},
                     row.note, False))
    # выданные конфиги: имя хранится вместе с ними. Берем только нужные
    # колонки - текст конфигов на каждый поиск из БД не тянем
    awg_cfg = select(AwgConfig.server_id, AwgConfig.protocol, AwgConfig.public_key,
                     AwgConfig.name)
    for sid, proto, pk, name in (await session.execute(awg_cfg)).all():
        rows.append(((sid, proto or "awg", pk), {"name": name, "has_config": True},
                     name, True))
    ovpn_cfg = select(OvpnConfig.server_id, OvpnConfig.client_id, OvpnConfig.name)
    for sid, cid, name in (await session.execute(ovpn_cfg)).all():
        rows.append(((sid, "openvpn", cid), {"name": name, "has_config": True}, name, True))
    native_cfg = select(NativeVpnConfig.server_id, NativeVpnConfig.protocol,
                        NativeVpnConfig.client_id, NativeVpnConfig.name)
    for sid, proto, cid, name in (await session.execute(native_cfg)).all():
        rows.append(((sid, proto, cid), {"name": name, "has_config": True}, name, True))

    for (sid, proto, cid), _fields, text, by_key in rows:
        if only is not None:
            continue  # режим "на паузе": новых клиентов не добавляем
        if needle in (text or "").lower() or (by_key and id_match(cid)):
            add(sid, proto, cid)
    for (sid, proto, cid), fields, _text, _by_key in rows:
        if _key(sid, proto, cid) in hits:
            add(sid, proto, cid, **fields)

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

    async def locked_group(sid: int, protocol: str, ids: list[str]) -> list[RevokeBulkResultItem]:
        server = servers.get(sid)
        if server is None:
            return [result(sid, protocol, c, "сервер не найден в панели") for c in ids]
        async with sem, nodelock.hold(protocol, sid):
            try:
                async with AsyncSession(bind=session.bind, expire_on_commit=False) as journal_session:
                    await bulk_issue_state.request_cancel(journal_session, sid, protocol, ids)
                errors = await expiry.revoke_many_on_node(
                    server, protocol, ids, key_path, settings.ssh_connect_timeout,
                )
            except expiry.ProtocolGone:
                # протокола на ноде нет совсем - клиентов с ним тоже
                errors = {}
            except Exception as exc:  # noqa: BLE001 — нода недоступна и т.п.
                return [result(sid, protocol, c, message(exc)) for c in ids]
            # The node must remain locked through metadata cleanup. Otherwise
            # a waiting resume can restore a revoked peer from its pause record.
            # Each parallel group owns its session: sharing the request session
            # among gather() tasks is not supported by SQLAlchemy.
            async with AsyncSession(bind=session.bind, expire_on_commit=False) as group_session:
                for cid in ids:
                    if cid in errors:
                        continue
                    await expiry.cleanup_client_db(group_session, sid, protocol, cid)
                    await pausestore.drop(group_session, sid, protocol, cid)
                    await group_session.execute(
                        ClientName.__table__.delete().where(
                            ClientName.server_id == sid,
                            ClientName.protocol == protocol,
                            ClientName.client_id == cid,
                        )
                    )
                await group_session.commit()
            return [
                result(sid, protocol, c, message(errors[c]) if c in errors else "")
                for c in ids
            ]

    async def one_group(sid: int, protocol: str, ids: list[str]) -> list[RevokeBulkResultItem]:
        try:
            return await locked_group(sid, protocol, ids)
        except Exception as exc:  # lock timeout or cleanup failure belongs to this group
            return [result(sid, protocol, c, message(exc)) for c in ids]

    results = [
        r
        for chunk in await asyncio.gather(
            *(one_group(sid, proto, ids) for (sid, proto), ids in groups.items())
        )
        for r in chunk
    ]

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
