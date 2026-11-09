import asyncio
import base64
import re
from contextlib import asynccontextmanager

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from app import (
    audit, awg, bulk_archive, bulk_issue_state, client_endpoint, deploy, expiry,
    native_vpn, nodelock, pausestore, sshops, wg_bulk, xray, xray_bulk,
)
from app.api.awg import _amnezia_link
from app.api.awg3 import _state as awg3_state
from app.bulk_schemas import ExportProtocol, ExportRequest, IssueProtocol, IssueRequest, IssueResult, PendingIssue, RevokeRequest
from app.config import get_settings
from app.deps import CurrentUser, SessionDep
from app.models import AuditLog, AwgConfig, BulkClientIssue, ClientName, NativeVpnConfig, OvpnConfig, Server
from app.schemas import RevokeBulkResult, RevokeBulkResultItem
from app.sshkeys import ensure_panel_key, key_paths

router = APIRouter(prefix="/servers/{server_id}/bulk-clients/{protocol}", tags=["bulk clients"])
_PRIVATE_HEADERS = {"Cache-Control": "no-store", "Pragma": "no-cache", "X-Content-Type-Options": "nosniff"}
_EXPORT_SLOTS = asyncio.Semaphore(2)


async def _server(session, server_id: int) -> Server:
    server = await session.get(Server, server_id)
    if server is None:
        raise HTTPException(404, "Сервер не найден")
    return server


@asynccontextmanager
async def _connection(server, protocol, *, write=False):
    settings = get_settings()
    ensure_panel_key(settings.data_dir)
    key_path, _ = key_paths(settings.data_dir)
    async with nodelock.connect(protocol, server.id, sshops.connect(
        server.host, server.ssh_port, server.ssh_user, key_path, settings.ssh_connect_timeout,
    )) as conn:
        if write:
            await deploy.ensure_idle(conn, tag=protocol)
        yield conn


async def _wg_state(conn, server, protocol):
    if protocol == "awg3":
        return await awg3_state(conn, server.host)
    return await native_vpn.wg_state(conn, server.host)


async def _xray_state(conn):
    container = await xray.detect_container(conn)
    return await xray_bulk.read(conn, container)


async def _reality_bits(conn, container):
    bits = await xray.read_server_bits(conn, container)
    public = bits["pub"]
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", public) or len(base64.urlsafe_b64decode(public + "=")) != 32 \
            or not re.fullmatch(r"(?:[a-fA-F0-9]{2}){0,8}", bits["short"]) or not bits["site"]:
        raise HTTPException(409, "Не удалось проверить параметры REALITY для клиентского профиля")
    return bits


def _match_request(operation, user_id, server_id, protocol, body):
    if operation is None:
        return
    if (operation.owner_id, operation.server_id, operation.protocol, operation.prefix, operation.count) \
            != (user_id, server_id, protocol, body.prefix, body.count):
        raise HTTPException(409, "Идентификатор уже использован для другой групповой выдачи")


def _result(operation) -> IssueResult:
    return IssueResult(items=[item for item in operation.items if not item.get("cancelled")],
                       cancelled=sum(bool(item.get("cancelled")) for item in operation.items))


@router.get("/issue/pending", response_model=PendingIssue | None)
async def pending_issue(server_id: int, protocol: IssueProtocol, user: CurrentUser,
                        session: SessionDep, response: Response) -> PendingIssue | None:
    response.headers.update(_PRIVATE_HEADERS)
    await _server(session, server_id)
    operation = next((row for row in await bulk_issue_state.pending(session, server_id, protocol)
                      if row.owner_id == user.id), None)
    if operation is None:
        return None
    return PendingIssue(request_id=operation.request_id, prefix=operation.prefix, count=operation.count,
                        client_ids=[item["client_id"] for item in operation.items if not item.get("cancelled")])


@router.post("/issue", response_model=IssueResult)
@nodelock.operation()
async def issue(server_id: int, protocol: IssueProtocol, body: IssueRequest,
                user: CurrentUser, session: SessionDep, response: Response) -> IssueResult:
    response.headers.update(_PRIVATE_HEADERS)
    server = await _server(session, server_id)
    request_id = str(body.request_id)
    username, user_id, server_name = user.username, user.id, server.name
    operation = await session.get(BulkClientIssue, request_id)
    _match_request(operation, user_id, server_id, protocol, body)
    if operation is not None and operation.complete:
        return _result(operation)
    if operation is not None and any(item.get("revoke_pending") for item in operation.items):
        raise HTTPException(409, "Сначала подтвердите отзыв выбранных профилей незавершенной группы")
    if operation is None and (await bulk_issue_state.pending(session, server_id, protocol)).first() is not None:
        raise HTTPException(409, "Сначала завершите или отмените предыдущую групповую выдачу")
    if operation is None and protocol != "xray":
        await client_endpoint.require_resolvable(server.client_endpoint)

    try:
        async with _connection(server, protocol, write=True) as conn:
            paused = await pausestore.list_paused(session, server_id, protocol)
            if protocol == "xray":
                state = await _xray_state(conn)
                bits = await _reality_bits(conn, state.container)
            else:
                interface = await _wg_state(conn, server, protocol)
                if protocol == "awg3" and not all(key in interface.params for key in ("RandomTrailers", "DisableCookies")):
                    raise HTTPException(409, "Групповая выдача требует AmneziaWG 3.1")
                state = await wg_bulk.read(conn, interface)
            if operation is None:
                if protocol == "xray":
                    planned = [item | {"server_key": bits["pub"]}
                               for item in xray_bulk.plan(state, paused, body.names())]
                else:
                    planned = await wg_bulk.plan(
                        conn, state, paused, body.names(), get_settings().awg_client_dns,
                        native=protocol == "wireguard",
                    )
                operation = BulkClientIssue(
                    request_id=request_id, server_id=server_id, protocol=protocol, owner_id=user_id,
                    prefix=body.prefix, count=body.count, items=planned, complete=False,
                )
                session.add(operation)
                session.add(AuditLog(username=username, action="clients_bulk_issue_start", target=server_name,
                                     detail=f"{protocol}: {body.count}, request {request_id}"))
                try:
                    # No node writes before this commit. Never generate another set of
                    # credentials for this request, even if the commit ACK was lost.
                    await session.commit()
                except IntegrityError:
                    await session.rollback()
                    operation = await session.get(BulkClientIssue, request_id)
                    _match_request(operation, user_id, server_id, protocol, body)
                    if operation is None:
                        raise HTTPException(409, "Сначала завершите или отмените предыдущую групповую выдачу") from None
                    if operation.complete:
                        return _result(operation)
                    raise HTTPException(409, "Запрос уже выполняется, повторите с тем же идентификатором") from None

            items = [item for item in operation.items if not item.get("cancelled")]
            active = [item for item in items if item["client_id"] not in paused]
            if protocol == "xray":
                if any(item["server_key"] != bits["pub"] for item in items):
                    raise HTTPException(409, "Публичный ключ REALITY изменился после подготовки группы")
                await xray_bulk.apply(conn, state, active)
            else:
                if any(item["client_id"] in paused and
                       paused[item["client_id"]]["data"].get("ip") != item["ip"] for item in items):
                    raise HTTPException(409, "Адрес клиента на паузе изменился после подготовки группы")
                await wg_bulk.apply(conn, state, paused, active)
    except HTTPException:
        raise
    except xray_bulk.ManagementUnavailable as exc:
        raise HTTPException(409, str(exc)) from None
    except (wg_bulk.PlanConflict, xray_bulk.PlanConflict) as exc:
        raise HTTPException(409, str(exc)) from None
    except Exception:
        await session.rollback()
        await audit.record(session, username, "clients_bulk_issue_pending", server_name,
                           f"{protocol}: запрос {request_id}")
        raise HTTPException(502, "Выдачу не удалось подтвердить. Повторите запрос с тем же идентификатором.") from None

    for item in items:
        if protocol == "awg3":
            session.add(AwgConfig(server_id=server_id, protocol=protocol,
                                  public_key=item["client_id"], name=item["name"], config=item["config"]))
        elif protocol == "wireguard":
            session.add(NativeVpnConfig(server_id=server_id, protocol=protocol,
                                        client_id=item["client_id"], name=item["name"], config=item["config"]))
    operation.items = [
        {key: item[key] for key in ("client_id", "name", "cancelled") if key in item}
        for item in operation.items
    ]
    operation.complete = True
    session.add(AuditLog(username=username, action="clients_bulk_issue", target=server_name,
                         detail=f"{protocol}: {len(items)} из {body.count}, запрос {request_id}"))
    try:
        await session.commit()
    except SQLAlchemyError:
        await session.rollback()
        raise HTTPException(503, "Не удалось подтвердить запись в панели. Повторите с тем же идентификатором.") from None
    return _result(operation)


async def _stored_profiles(server, protocol, session, ids):
    if protocol in ("awg", "awg3", "awglegacy"):
        model, key = AwgConfig, AwgConfig.public_key
    elif protocol == "openvpn":
        model, key = OvpnConfig, OvpnConfig.client_id
    else:
        model, key = NativeVpnConfig, NativeVpnConfig.client_id
    query = select(model).where(model.server_id == server.id, key.in_(ids))
    if model is not OvpnConfig:
        query = query.where(model.protocol == protocol)
    rows = await session.scalars(query)
    out = {}
    for row in rows:
        profile = bulk_archive.Profile(row.name)
        if model is OvpnConfig:
            profile.files["amnezia.txt"] = row.config_amnezia
            profile.qr["amnezia-qr"] = (row.config_amnezia, True)
        elif protocol == "openvpn-native":
            profile.files["client.ovpn"] = row.config
        else:
            # Same effective endpoint as the existing single download. All
            # other fields and the saved credentials remain byte-for-byte.
            config = client_endpoint.peer_config(row.config, server.client_endpoint)
            profile.files["client.conf"] = config
            if protocol == "wireguard":
                profile.qr["wireguard-qr"] = (config, False)
            else:
                try:
                    link = _amnezia_link(config, server)
                except (ValueError, awg.AwgError):
                    profile.warnings.append("amnezia_link_unavailable")
                else:
                    profile.files["amnezia.txt"] = link
                    profile.qr["amnezia-qr"] = (link, True)
        out[getattr(row, key.key)] = profile
    return out


async def _xray_profiles(server, ids):
    async with _connection(server, "xray") as conn:
        container = await xray.detect_container(conn)
        document, default, table = await xray._read_all(conn, container)
        bits = await _reality_bits(conn, container)
    current = {client.client_id: client.name for client in xray._clients_from_config(document, default, table)}
    flow = {row["id"]: row.get("flow", "") for row in xray._client_list(document) if isinstance(row, dict) and row.get("id")}
    # Only offer XHTTP where the same UUID is configured on the fallback.
    xhttp_ids = set()
    if bits.get("xhttp_path"):
        for inbound in xray._extra_vless(document):
            route = {"inbounds": [document["inbounds"][0], inbound]}
            if xray.xhttp_fallback_path(route) == bits["xhttp_path"]:
                xhttp_ids.update(row.get("id") for row in xray._vless_clients(inbound["settings"])
                                 if isinstance(row, dict))
    dns1, dns2 = awg.dns_pair(get_settings().awg_client_dns)
    out = {}
    for cid in ids:
        if cid not in current:
            continue
        variants = xray.client_configs(
            bits | {"flow": flow[cid], "xhttp_path": bits.get("xhttp_path") if cid in xhttp_ids else None},
            host=server.host, description=server.name, dns1=dns1, dns2=dns2,
            client_id=cid, name=current[cid],
        )
        profile = bulk_archive.Profile(current[cid])
        for variant in variants:
            key = variant["key"]
            profile.files[f"{key}.json"] = bulk_archive.xray_native_config(variant["amnezia"])
            if re.fullmatch(r"[A-Za-z0-9_-]+", cid):
                profile.files[f"{key}-vless.txt"] = variant["uri"]
                profile.qr[f"{key}-vless-qr"] = (variant["uri"], False)
            else:
                profile.warnings.append(f"{key}-vless: client_id_requires_native_config")
            profile.files[f"{key}-amnezia.txt"] = variant["amnezia"]
            profile.qr[f"{key}-amnezia-qr"] = (variant["amnezia"], True)
        out[cid] = profile
    return out


@router.post("/export")
async def export(server_id: int, protocol: ExportProtocol, body: ExportRequest,
                 user: CurrentUser, session: SessionDep) -> Response:
    server = await _server(session, server_id)
    try:
        async with _EXPORT_SLOTS:
            if protocol == "xray":
                profiles = await _xray_profiles(server, body.client_ids)
            else:
                profiles = await _stored_profiles(server, protocol, session, body.client_ids)
            content, exported = await asyncio.to_thread(bulk_archive.build, protocol, body.client_ids, profiles)
    except HTTPException:
        raise
    except bulk_archive.ArchiveTooLarge:
        raise HTTPException(413, "Архив превышает допустимый размер. Выберите меньше клиентов.") from None
    except Exception:
        raise HTTPException(502, "Не удалось собрать архив профилей") from None
    missing = len(body.client_ids) - exported
    await audit.record(session, user.username, "clients_bulk_export", server.name,
                       f"{protocol}: {exported} из {len(body.client_ids)}")
    return Response(content=content, media_type="application/zip", headers=_PRIVATE_HEADERS | {
        "Content-Disposition": f'attachment; filename="vpn-{protocol}-{server_id}.zip"',
        "X-Bulk-Exported": str(exported),
        "X-Bulk-Missing": str(missing),
    })


@router.post("/revoke", response_model=RevokeBulkResult)
@nodelock.operation()
async def revoke(server_id: int, protocol: IssueProtocol, body: RevokeRequest,
                 user: CurrentUser, session: SessionDep, response: Response) -> RevokeBulkResult:
    response.headers.update(_PRIVATE_HEADERS)
    server = await _server(session, server_id)
    username, server_name = user.username, server.name
    errors = {}
    ids = body.client_ids
    if protocol != "xray":
        for cid in ids:
            try:
                awg._safe_key(cid, "публичный ключ пира")
            except awg.AwgError:
                errors[cid] = "Некорректный публичный ключ"
    selected = [cid for cid in ids if cid not in errors]
    if selected:
        try:
            await bulk_issue_state.request_cancel(session, server_id, protocol, selected)
            async with _connection(server, protocol, write=True) as conn:
                if protocol == "xray":
                    errors.update(await xray_bulk.revoke(conn, await _xray_state(conn), selected))
                else:
                    interface = await _wg_state(conn, server, protocol)
                    await wg_bulk.revoke(conn, await wg_bulk.read(conn, interface), selected)
        except xray_bulk.ManagementUnavailable as exc:
            errors.update(dict.fromkeys(selected, str(exc)))
        except Exception:
            await session.rollback()
            errors.update(dict.fromkeys(selected, "Отзыв на сервере не подтвержден. Повторите выбранные профили."))
    done = [cid for cid in ids if cid not in errors]
    try:
        for cid in done:
            await expiry.cleanup_client_db(session, server_id, protocol, cid)
        if done:
            await session.execute(delete(ClientName).where(
                ClientName.server_id == server_id, ClientName.protocol == protocol, ClientName.client_id.in_(done),
            ))
        session.add(AuditLog(username=username, action="clients_bulk_revoke", target=server_name,
                             detail=f"{protocol}: {len(done)} из {len(ids)}"))
        await session.commit()
    except SQLAlchemyError:
        await session.rollback()
        errors.update(dict.fromkeys(done, "Запись в панели не подтверждена. Повторите выбранные профили."))
    return RevokeBulkResult(revoked=len(ids) - len(errors), failed=len(errors), items=[
        RevokeBulkResultItem(server_id=server_id, server_name=server_name, protocol=protocol,
                             client_id=cid, ok=cid not in errors, error=errors.get(cid, ""))
        for cid in ids
    ])
