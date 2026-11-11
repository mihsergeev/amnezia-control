"""Native VPN endpoints; no Amnezia export or implicit protocol conversion."""

import json
import re
from contextlib import asynccontextmanager

from fastapi import APIRouter, HTTPException, Request, status
from sqlalchemy import delete, select

from app import client_metadata, audit, bulk_issue_state, client_endpoint, deploy, deploywatch, expiry, limits, native_deploy, native_snapshots, native_vpn, nodelock, notes, pausestore, sshops
from app.config import get_settings
from app.deps import CurrentUser, SessionDep
from app.models import NativeVpnConfig, Server
from app.native_schemas import NativeClientRequest, NativeConfigResponse, NativeCreateRequest, NativeCreateResponse, NativeDeployRequest, NativeNoteRequest
from app.schemas import DeployStatusOut, SnapshotOut, SnapshotRestoreRequest
from app.sshkeys import ensure_panel_key, key_paths


async def server_or_404(session, server_id):
    server = await session.get(Server, server_id)
    if server is None:
        raise HTTPException(404, "Сервер не найден")
    return server


@asynccontextmanager
async def connection(server, protocol):
    settings = get_settings()
    ensure_panel_key(settings.data_dir)
    key, _ = key_paths(settings.data_dir)
    async with nodelock.connect(protocol, server.id, sshops.connect(
        server.host, server.ssh_port, server.ssh_user, key, settings.ssh_connect_timeout,
    )) as conn:
        yield conn


def failure(exc):
    if isinstance(exc, HTTPException):
        return exc
    if isinstance(exc, (ValueError,)):
        return HTTPException(400, str(exc))
    if isinstance(exc, (native_vpn.NativeNotDeployed, deploy.DeployBusy)):
        return HTTPException(409, str(exc))
    if isinstance(exc, LookupError):
        return HTTPException(404, str(exc))
    if isinstance(exc, native_vpn.NativeError):
        return HTTPException(502, str(exc))
    return HTTPException(502, "Не удалось выполнить операцию нативного VPN")


def identifier(protocol, body):
    value = body.public_key if protocol == "wireguard" else body.client_id
    if not value:
        raise HTTPException(422, "Не указан идентификатор клиента выбранного протокола")
    try:
        return native_vpn.client_id(protocol, value)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None


def export(protocol, name, config, cid):
    format_ = "wireguard" if protocol == "wireguard" else "openvpn"
    suffix = "conf" if protocol == "wireguard" else "ovpn"
    safe = re.sub(r"[^A-Za-z0-9_-]+", "_", name).strip("_")[:60] or "client"
    return {"config": config, "name": name, "format": format_, "filename": f"{safe}.{suffix}"}


async def store(session, server_id, protocol, cid, name, config):
    await session.execute(delete(NativeVpnConfig).where(
        NativeVpnConfig.server_id == server_id, NativeVpnConfig.protocol == protocol,
        NativeVpnConfig.client_id == cid))
    session.add(NativeVpnConfig(server_id=server_id, protocol=protocol,
                                client_id=cid, name=name, config=config))


async def snapshot(conn, session, server, protocol):
    listener = await native_vpn.metadata(conn, protocol)
    snapshot_id = await deploy.snapshot_config(conn, protocol)
    if snapshot_id is None:
        raise native_vpn.NativeError("Не удалось сохранить резервную копию нативного протокола")
    await native_snapshots.save(session, server, protocol, snapshot_id, listener)
    existing = await deploy.list_snapshots(conn, protocol)
    await native_snapshots.prune(session, server.id, protocol, [row["id"] for row in existing])
    return snapshot_id


def build_router(protocol: str) -> APIRouter:
    router = APIRouter(prefix=f"/servers/{{server_id}}/{protocol}", tags=[protocol])
    spec = native_deploy.SPECS[protocol]

    @router.get("")
    async def state(server_id: int, _: CurrentUser, session: SessionDep) -> dict:
        server = await server_or_404(session, server_id)
        try:
            async with connection(server, protocol) as conn:
                result = await native_vpn.state(conn, protocol, server.host)
                result["version"] = await native_vpn.version(conn, protocol)
        except Exception as exc:
            raise failure(exc) from None
        stored = set(await session.scalars(select(NativeVpnConfig.client_id).where(
            NativeVpnConfig.server_id == server_id, NativeVpnConfig.protocol == protocol)))
        note_map = await notes.notes_map(session, server_id, protocol)
        limit_map = await limits.limits_map(session, server_id, protocol)
        paused = await pausestore.list_paused(session, server_id, protocol)
        key = "public_key" if protocol == "wireguard" else "client_id"
        existing = {client[key] for client in result["clients"]}
        if protocol == "wireguard":
            history = await pausestore.paused_view(session, server_id, protocol, paused, set(paused) - existing)
            for cid, row in paused.items():
                if cid in existing:
                    continue
                previous = history.get(cid, {})
                result["clients"].append({"public_key": cid, "name": row["name"],
                    "address": row["data"].get("ip", "") + "/32", "endpoint": "",
                    "rx_bytes": previous.get("rx", 0), "tx_bytes": previous.get("tx", 0),
                    "latest_handshake": previous.get("seen")})
        for client in result["clients"]:
            cid = client[key]
            client.update(has_config=cid in stored, note=note_map.get(cid, ""),
                          expires_at=limit_map.get(cid), paused=cid in paused)
        await client_metadata.enrich(session, server_id, protocol, result["clients"])
        result["format"] = "wireguard" if protocol == "wireguard" else "openvpn"
        result["capabilities"] = {"native_config": True, "amnezia_export": False,
            "pause": True, "reissue": True, "notes": True, "limits": True,
            "history": True, "rename": True, "bulk": True, "update": True,
            "config_backups": True, "config_restore": protocol == "wireguard", "remove": True}
        return result

    @router.post("/clients", response_model=NativeCreateResponse, status_code=201)
    @nodelock.operation(protocol)
    async def create(server_id: int, body: NativeCreateRequest, user: CurrentUser, session: SessionDep):
        server = await server_or_404(session, server_id)
        endpoint = server.client_endpoint if protocol == "wireguard" else ""
        await client_endpoint.require_resolvable(endpoint)
        try:
            async with connection(server, protocol) as conn:
                await deploy.ensure_idle(conn, tag=protocol)
                reserved = await pausestore.paused_ips(session, server_id, protocol)
                client, config = await native_vpn.issue(conn, protocol, body.name, server.host,
                    body.dns or get_settings().awg_client_dns, reserved=reserved)
        except Exception as exc:
            raise failure(exc) from None
        cid = client["public_key" if protocol == "wireguard" else "client_id"]
        await store(session, server_id, protocol, cid, body.name, config)
        if body.note:
            await notes.set_note(session, server_id, protocol, cid, body.note)
        if body.expires_at:
            await limits.set_limit(session, server_id, protocol, cid, body.name, body.expires_at)
        await client_metadata.set_labels(session, server_id, protocol, cid, body.group_name, body.device_name)
        await session.commit()
        await audit.record(session, user.username, f"{protocol}_issue", server.name, body.name)
        config = client_endpoint.peer_config(config, endpoint)
        return export(protocol, body.name, config, cid) | {"client": client | {
            "has_config": True, "note": body.note, "expires_at": body.expires_at, "paused": False, "group_name": body.group_name, "device_name": body.device_name}}

    @router.post("/config", response_model=NativeConfigResponse)
    async def config(server_id: int, body: NativeClientRequest, _: CurrentUser, session: SessionDep):
        server = await server_or_404(session, server_id)
        cid = identifier(protocol, body)
        row = await session.scalar(select(NativeVpnConfig).where(
            NativeVpnConfig.server_id == server_id, NativeVpnConfig.protocol == protocol,
            NativeVpnConfig.client_id == cid))
        if row is None:
            raise HTTPException(404, "Профиль не сохранен в панели; перевыпустите клиента")
        endpoint = server.client_endpoint if protocol == "wireguard" else ""
        await client_endpoint.require_resolvable(endpoint)
        return export(protocol, row.name, client_endpoint.peer_config(row.config, endpoint), cid)

    @router.post("/note", status_code=204)
    async def note(server_id: int, body: NativeNoteRequest, _: CurrentUser, session: SessionDep):
        await server_or_404(session, server_id)
        await notes.set_note(session, server_id, protocol, identifier(protocol, body), body.note.strip())

    @router.post("/pause", status_code=204)
    @nodelock.operation(protocol)
    async def pause(server_id: int, body: NativeClientRequest, user: CurrentUser, session: SessionDep):
        server = await server_or_404(session, server_id)
        cid = identifier(protocol, body)
        if cid in await pausestore.list_paused(session, server_id, protocol):
            raise HTTPException(409, "Клиент уже на паузе")
        try:
            async with connection(server, protocol) as conn:
                await deploy.ensure_idle(conn, tag=protocol)
                current = await native_vpn.state(conn, protocol, server.host)
                key = "public_key" if protocol == "wireguard" else "client_id"
                target = next((value for value in current["clients"] if value[key] == cid), None)
                if target is None:
                    raise LookupError("Клиент не найден")
                data = await native_vpn.pause(conn, protocol, cid, server.host)
        except Exception as exc:
            raise failure(exc) from None
        await pausestore.add(session, server_id, protocol, cid, target["name"], data)
        await audit.record(session, user.username, f"{protocol}_pause", server.name, target["name"])

    @router.post("/resume", status_code=204)
    @nodelock.operation(protocol)
    async def resume(server_id: int, body: NativeClientRequest, user: CurrentUser, session: SessionDep):
        server = await server_or_404(session, server_id)
        cid = identifier(protocol, body)
        paused = (await pausestore.list_paused(session, server_id, protocol)).get(cid)
        if paused is None:
            raise HTTPException(404, "Клиент не на паузе")
        try:
            async with connection(server, protocol) as conn:
                await deploy.ensure_idle(conn, tag=protocol)
                await native_vpn.resume(conn, protocol, cid, paused["name"], paused["data"], server.host)
        except Exception as exc:
            raise failure(exc) from None
        await pausestore.drop(session, server_id, protocol, cid)
        await session.commit()
        await audit.record(session, user.username, f"{protocol}_resume", server.name, paused["name"])

    @router.post("/revoke", status_code=204)
    @nodelock.operation(protocol)
    async def revoke(server_id: int, body: NativeClientRequest, user: CurrentUser, session: SessionDep):
        server = await server_or_404(session, server_id)
        cid = identifier(protocol, body)
        try:
            async with connection(server, protocol) as conn:
                await deploy.ensure_idle(conn, tag=protocol)
                await bulk_issue_state.request_cancel(session, server_id, protocol, [cid])
                await native_vpn.revoke(conn, protocol, cid)
        except Exception as exc:
            raise failure(exc) from None
        await expiry.cleanup_client_db(session, server_id, protocol, cid)
        await notes.clear_note(session, server_id, protocol, cid)
        await session.commit()
        await audit.record(session, user.username, f"{protocol}_revoke", server.name, cid)

    @router.post("/reissue", response_model=NativeCreateResponse, status_code=201)
    @nodelock.operation(protocol)
    async def reissue(server_id: int, body: NativeClientRequest, user: CurrentUser, session: SessionDep):
        server = await server_or_404(session, server_id)
        endpoint = server.client_endpoint if protocol == "wireguard" else ""
        await client_endpoint.require_resolvable(endpoint)
        cid = identifier(protocol, body)
        if cid in await pausestore.list_paused(session, server_id, protocol):
            raise HTTPException(409, "Сначала возобновите клиента или отзовите его")
        old_labels = (await client_metadata.labels_map(session, server_id, protocol)).get(cid, {})
        old_note = (await notes.notes_map(session, server_id, protocol)).get(cid, "")
        old_limit = (await limits.limits_map(session, server_id, protocol)).get(cid)
        try:
            async with connection(server, protocol) as conn:
                await deploy.ensure_idle(conn, tag=protocol)
                current = await native_vpn.state(conn, protocol, server.host)
                key = "public_key" if protocol == "wireguard" else "client_id"
                target = next((value for value in current["clients"] if value[key] == cid), None)
                if target is None:
                    raise LookupError("Клиент не найден")
                await bulk_issue_state.request_cancel(session, server_id, protocol, [cid])
                client, text = await native_vpn.issue(conn, protocol, target["name"], server.host,
                    get_settings().awg_client_dns,
                    fixed_ip=target.get("address", "").split("/")[0] or None)
                await native_vpn.revoke(conn, protocol, cid)
        except Exception as exc:
            raise failure(exc) from None
        new_id = client["public_key" if protocol == "wireguard" else "client_id"]
        await expiry.cleanup_client_db(session, server_id, protocol, cid)
        await notes.clear_note(session, server_id, protocol, cid)
        await client_metadata.set_labels(session, server_id, protocol, new_id, **old_labels)
        await store(session, server_id, protocol, new_id, target["name"], text)
        if old_note:
            await notes.set_note(session, server_id, protocol, new_id, old_note)
        if old_limit:
            await limits.set_limit(session, server_id, protocol, new_id, target["name"], old_limit)
        await session.commit()
        await audit.record(session, user.username, f"{protocol}_reissue", server.name, target["name"])
        text = client_endpoint.peer_config(text, endpoint)
        return export(protocol, target["name"], text, new_id) | {"client": client | {
            "has_config": True, "note": old_note, "expires_at": old_limit, "paused": False, **old_labels}}

    async def install(server_id, body, user, session, request, updating=False):
        server = await server_or_404(session, server_id)
        try:
            async with connection(server, protocol) as conn:
                await deploy.ensure_idle(conn, tag=protocol)
                await native_vpn.deployment_prerequisites(conn)
                existing = await native_vpn.installed_metadata(conn, protocol)
                if updating and existing is None:
                    raise native_vpn.NativeNotDeployed("Нативный протокол не установлен на сервере")
                if existing:
                    if body.port is not None and body.port != existing["port"]:
                        raise HTTPException(409, "Смена порта существующего протокола требует отдельной настройки")
                    if "transport" in body.model_fields_set and body.transport != existing["transport"]:
                        raise HTTPException(409, "Смена транспорта существующего протокола требует отдельной настройки")
                    port, transport = existing["port"], existing["transport"]
                else:
                    port, transport = body.port or spec.port, body.transport
                if protocol == "wireguard" and transport != "udp":
                    raise HTTPException(422, "WireGuard работает только по UDP")
                owner = await deploy.port_owner(conn, port, transport, own=spec.container)
                if owner:
                    raise HTTPException(409, deploy.port_busy_detail(port, transport, owner, protocol))
                if existing:
                    try:
                        await native_vpn.detect(conn, protocol)
                    except native_vpn.NativeNotDeployed:
                        # A failed first installation may have initialized its
                        # owned data without ever creating a container.
                        pass
                    else:
                        await snapshot(conn, session, server, protocol)
                script = native_deploy.build_script(protocol, port, transport, get_settings().awg_client_dns)
                await deploy.launch(conn, script, tag=protocol)
        except Exception as exc:
            raise failure(exc) from None
        deploywatch.spawn(request.app, server, protocol)
        await audit.record(session, user.username, f"{protocol}_{'update' if updating else 'deploy'}", server.name)
        return {"started": True}

    @router.post("/deploy", status_code=202)
    @nodelock.operation(protocol)
    async def deploy_protocol(server_id: int, body: NativeDeployRequest, user: CurrentUser,
                              session: SessionDep, request: Request):
        return await install(server_id, body, user, session, request)

    @router.post("/update", status_code=202)
    @nodelock.operation(protocol)
    async def update_protocol(server_id: int, user: CurrentUser, session: SessionDep, request: Request):
        return await install(server_id, NativeDeployRequest(), user, session, request, True)

    @router.get("/deploy/status", response_model=DeployStatusOut)
    async def deployment_status(server_id: int, _: CurrentUser, session: SessionDep):
        server = await server_or_404(session, server_id)
        try:
            async with connection(server, protocol) as conn:
                return await deploy.read_status(conn, tag=protocol)
        except Exception as exc:
            raise failure(exc) from None

    @router.get("/version")
    async def protocol_version(server_id: int, _: CurrentUser, session: SessionDep):
        server = await server_or_404(session, server_id)
        try:
            async with connection(server, protocol) as conn:
                return {"version": await native_vpn.version(conn, protocol)}
        except Exception as exc:
            raise failure(exc) from None

    @router.get("/config-backups", response_model=list[SnapshotOut])
    async def backups(server_id: int, _: CurrentUser, session: SessionDep):
        server = await server_or_404(session, server_id)
        try:
            async with connection(server, protocol) as conn:
                return await deploy.list_snapshots(conn, protocol)
        except Exception as exc:
            raise failure(exc) from None

    @router.post("/config-restore", status_code=202)
    @nodelock.operation(protocol)
    async def restore(server_id: int, body: SnapshotRestoreRequest, user: CurrentUser, session: SessionDep):
        server = await server_or_404(session, server_id)
        if protocol == "openvpn-native":
            raise HTTPException(409, "Автоматическое восстановление PKI OpenVPN пока недоступно; резервные копии сохраняются")
        try:
            async with connection(server, protocol) as conn:
                await deploy.ensure_idle(conn, tag=protocol)
                manifest = await native_snapshots.load(session, server, protocol, body.id)
                current = await native_vpn.metadata(conn, protocol)
                if current != manifest["listener"]:
                    raise HTTPException(409, "Порт или транспорт снимка отличается от установленного протокола")
                before = await snapshot(conn, session, server, protocol)
                try:
                    if not await deploy.restore_snapshot(conn, protocol, body.id):
                        raise LookupError("Снимок не найден или поврежден")
                    await native_vpn.verify_wireguard_runtime(conn, server.host)
                    await native_snapshots.apply(session, server_id, protocol, manifest)
                    await session.commit()
                except Exception:
                    await session.rollback()
                    if not await deploy.restore_snapshot(conn, protocol, before):
                        raise native_vpn.NativeError("Восстановление не завершено; автоматический откат не подтвержден") from None
                    await native_vpn.verify_wireguard_runtime(conn, server.host)
                    raise
        except Exception as exc:
            raise failure(exc) from None
        await audit.record(session, user.username, f"{protocol}_config_restore", server.name, body.id)
        return {"started": True}

    return router


wireguard_router = build_router("wireguard")
openvpn_router = build_router("openvpn-native")
