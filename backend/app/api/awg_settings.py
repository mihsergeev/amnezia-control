"""Authenticated AWG settings with a durable compensating transaction."""

import asyncio
import ipaddress
import json
import shlex

from fastapi import APIRouter, HTTPException, Query, Response
from sqlalchemy import or_, select

from app import audit, awg, awg_settings as settings, bulk_issue_state, deploy, nodelock
from app.deps import CurrentUser, SessionDep
from app.models import AwgConfig, AwgSettingsChange, Cascade, PausedClient
from app.schemas import AwgSettingsRequest

router = APIRouter(prefix="/servers/{server_id}", tags=["awg-settings"])


def allowed(protocol):
    if protocol not in ("awg", "awg3"):
        raise HTTPException(404, "Настройки этого протокола недоступны")


async def state(conn, server, protocol):
    from app.api.awg3 import _state
    return await _state(conn, server.host) if protocol == "awg3" else await awg.read_state(conn, server.host)


async def _restore_db(session, change, *, new=False):
    which = "new" if new else "old"
    for item in change.payload.get("profiles", []):
        row = await session.get(AwgConfig, item["id"])
        if row is None:
            raise HTTPException(409, "Профиль исчез во время восстановления настроек")
        row.config = item[which]
    for item in change.payload.get("paused", []):
        row = await session.get(PausedClient, item["id"])
        if row is None:
            raise HTTPException(409, "Клиент на паузе исчез во время восстановления настроек")
        row.data = item[which]


async def _recover_one(conn, session, change):
    remote = await settings.remote_action(conn, change.id, "status")
    if change.phase == "applied" and remote in ("applied", "committed"):
        await settings.remote_action(conn, change.id, "finalize")
        change.phase = "done"
    elif remote in ("prepared", "changing", "applied", "rollback_failed", "rolledback"):
        await settings.remote_action(conn, change.id, "rollback")
        await _restore_db(session, change)
        change.phase = "rolledback"
    elif remote == "missing" and change.phase == "prepared":
        # Journal persisted before the remote prepare; nothing was changed.
        await _restore_db(session, change)
        change.phase = "rolledback"
    else:
        raise HTTPException(409, "Результат изменения настроек неизвестен; требуется восстановление операции " + change.id)
    # Drop duplicated secrets after a successful resolution. The remote backup
    # stays root-only for deliberate operational recovery.
    change.payload = {}
    await session.commit()


async def recover(server, session):
    """Called before AWG requests so a crash cannot export stale profiles."""
    from app.api.awg import _connect
    query = select(AwgSettingsChange).where(
        AwgSettingsChange.server_id == server.id,
        AwgSettingsChange.phase.in_(("prepared", "applied")),
    )
    # Avoid acquiring the AWG lock for unrelated protocol requests when there
    # is nothing to recover. Cross-protocol operations have their own order.
    if not (await session.scalars(query)).first():
        return
    async with nodelock.hold("awg", server.id):
        pending = (await session.scalars(query)).all()
        if pending:
            try:
                async with _connect(server) as conn:
                    for change in pending:
                        await _recover_one(conn, session, change)
            except Exception as exc:
                raise HTTPException(409, "Незавершенное изменение настроек AmneziaWG, результат неизвестен. Повторите после восстановления SSH") from exc


@router.get("/{protocol}/settings")
@nodelock.operation("awg")
async def get_settings(server_id: int, protocol: str, _: CurrentUser, session: SessionDep, response: Response):
    from app.api.awg import _connect, _get_or_404
    allowed(protocol)
    response.headers["Cache-Control"] = "no-store"
    server = await _get_or_404(server_id, session)
    async with _connect(server) as conn:
        current = await state(conn, server, protocol)
        conf = await awg.read_awg_conf(conn, current.container, current.interface)
        ver = settings.version(current.params)
        net = ipaddress.ip_interface(current.address).network
        return {"port": current.listen_port, "subnet": str(net), "server_address": current.address,
                "params": {k: current.params.get(k, "") for k in settings.keys(ver)},
                "version": ver, "supported_params": settings.keys(ver), "revision": settings.revision(conf)}


@router.get("/{protocol}/settings/defaults")
async def defaults(server_id: int, protocol: str, _: CurrentUser, session: SessionDep, response: Response,
                   protocol_version: str | None = Query(default=None, pattern=r"^(2\.0|3\.0|3\.1)$")):
    from app.api.awg import _get_or_404
    allowed(protocol)
    response.headers["Cache-Control"] = "no-store"
    await _get_or_404(server_id, session)
    ver = protocol_version or ("3.1" if protocol == "awg3" else "2.0")
    # The original AWG container can be upgraded to 3.x in place. Its API
    # protocol remains "awg"; the parameter version comes from the engine.
    if protocol == "awg3" and ver == "2.0":
        raise HTTPException(422, "Версия не соответствует протоколу")
    params = settings.generate_defaults(ver)
    return {"version": ver, "params": settings.validate_params(params, ver), "supported_params": settings.keys(ver)}


@router.put("/{protocol}/settings")
@nodelock.operation("cascade")
@nodelock.operation("awg")
async def update_settings(server_id: int, protocol: str, body: AwgSettingsRequest,
                          user: CurrentUser, session: SessionDep):
    from app.api.awg import _connect, _get_or_404
    allowed(protocol)
    if not body.acknowledge_disconnect:
        raise HTTPException(422, "Подтвердите отключение клиентов и необходимость обновить профили")
    server = await _get_or_404(server_id, session)
    cascade = await session.scalar(select(Cascade.id).where(or_(
        Cascade.entry_server_id == server_id, Cascade.exit_server_id == server_id)))
    if cascade:
        raise HTTPException(409, "Сервер участвует в каскаде. Изменение настроек AmneziaWG заблокировано до штатного отключения каскада")
    if list(await bulk_issue_state.pending(session, server_id, protocol)):
        raise HTTPException(409, "Завершите групповую выдачу клиентов перед изменением настроек")
    async with _connect(server) as conn:
        await deploy.ensure_idle(conn, tag=protocol)
        # External helpers are never adopted or rewritten by a settings edit.
        external = await conn.run("sudo -n test ! -e /opt/acontrol/cascade/config && sudo -n test ! -e /opt/acontrol/cascade-exit/config && sudo -n test ! -e /opt/acontrol/cascade-awg/node.env && sudo -n test ! -e /etc/systemd/system/acontrol-awg-link.service && sudo -n test ! -e /lib65/scripts/acontrol-awg-link/node.json && ! sudo -n docker inspect acontrol-awg-link >/dev/null 2>&1", check=False)
        if external.exit_status:
            raise HTTPException(409, "Обнаружен внешний каскад; изменение настроек заблокировано")
        current = await state(conn, server, protocol)
        conf = await awg.read_awg_conf(conn, current.container, current.interface)
        if settings.revision(conf) != body.revision:
            raise HTTPException(409, "Настройки изменились; перечитайте их перед сохранением")
        info = json.loads(await settings.checked(conn, "sudo -n docker inspect " + shlex.quote(current.container)))[0]
        image_info = json.loads(await settings.checked(conn, "sudo -n docker image inspect " + shlex.quote(info["Image"])))[0]
        host_dir = settings.managed(info, current.container, protocol, image_info)
        canonical = await settings.canonical_host(conn, info, host_dir, current.listen_port)
        settings.managed(info, current.container, protocol, image_info, canonical)
        ver = settings.version(current.params)
        port, subnet, address, params = await settings.choose(conn, body, ver, current.container, existing_address=current.address)
        net = ipaddress.ip_network(subnet)
        old_net = ipaddress.ip_interface(current.address).network
        server_ip = ipaddress.ip_interface(address).ip
        candidate = settings.replace_interface(conf, {"ListenPort": port, "Address": address, **params})
        changed_net = old_net != net
        if changed_net:
            candidate = settings.remap_peers(candidate, old_net, net, server_ip)
        elif any(c.address.split("/")[0] == str(server_ip) for c in current.clients):
            raise HTTPException(422, "Адрес интерфейса уже занят клиентом")
        profiles, paused = [], []
        for row in await session.scalars(select(AwgConfig).where(AwgConfig.server_id == server_id, AwgConfig.protocol == protocol)):
            iface, _peers = awg.parse_conf(row.config)
            old_ip = iface.get("Address", "").split("/")[0]
            ip = settings.remap_ip(old_ip, old_net, net, server_ip) if changed_net else old_ip
            if ip == str(server_ip):
                raise HTTPException(422, "Адрес интерфейса уже занят сохраненным профилем")
            updated = settings.refresh_profile(row.config, params, ip + "/32", port, subnet)
            profiles.append({"id": row.id, "old": row.config, "new": updated})
        for row in await session.scalars(select(PausedClient).where(PausedClient.server_id == server_id, PausedClient.protocol == protocol)):
            data = json.loads(row.data)
            old_ip = data.get("ip", "")
            data["ip"] = settings.remap_ip(old_ip, old_net, net, server_ip) if changed_net else old_ip
            if data["ip"] == str(server_ip):
                raise HTTPException(422, "Адрес интерфейса занят клиентом на паузе")
            paused.append({"id": row.id, "old": row.data, "new": json.dumps(data, ensure_ascii=False)})
        table = await awg._read_table(conn, current.container)
        if changed_net:
            for item in table:
                # Amnezia clientsTable normally contains clientId and userData.
                # Preserve unknown fields, updating only known IP metadata.
                for metadata in (item, item.get("userData", {})):
                    for key in ("ip", "address", "allowedIps"):
                        if metadata.get(key):
                            raw = metadata[key].split("/")[0]
                            metadata[key] = settings.remap_ip(raw, old_net, net, server_ip) + ("/32" if "/" in metadata[key] else "")
        if candidate == conf and not any(v["old"] != v["new"] for v in profiles):
            return {"changed": False, "profiles_refreshed": 0}
        token = settings.transaction_id()
        change = AwgSettingsChange(id=token, server_id=server_id, protocol=protocol,
                                   phase="prepared", payload={"profiles": profiles, "paused": paused})
        session.add(change)
        await session.commit()
        script = settings.runtime(token, current.container, host_dir, protocol, port, address,
                                  torrent_block=bool(server.torrent_block))
        try:
            await settings.install_runtime(conn, token, script)
            await settings.remote_action(conn, token, "prepare")
            target = f"/opt/acontrol/settings-backups/{token}"
            for name, content in (("candidate.conf", candidate), ("candidate.table", json.dumps(table, ensure_ascii=False) + "\n")):
                await settings.checked(conn, f"sudo -n install -m 600 /dev/stdin {target}/{name}", stdin=content)
            await settings.remote_action(conn, token, "apply")
            await _restore_db(session, change, new=True)
            change.phase = "applied"
            await session.commit()
            await settings.remote_action(conn, token, "finalize")
            change.phase, change.payload = "done", {}
            await session.commit()
        except BaseException as exc:
            # Compensate in this task while it still owns the node lock and
            # connection/session. A repeated cancellation may interrupt this;
            # the durable journal + watchdog then own recovery. Never leave a
            # shielded child using resources the handler is about to close.
            try:
                await session.rollback()
                change = await session.get(AwgSettingsChange, token)
                await _recover_one(conn, session, change)
            except BaseException as recovery_exc:
                if isinstance(recovery_exc, asyncio.CancelledError):
                    raise
                if isinstance(exc, asyncio.CancelledError):
                    raise exc
                raise HTTPException(502, "Результат изменения неизвестен. Резервная копия сохранена; повторный запрос выполнит восстановление операции " + token) from exc
            if isinstance(exc, asyncio.CancelledError):
                raise
            raise HTTPException(502, "Изменение не завершено; состояние восстановлено или сверено. Перечитайте настройки") from exc
    await audit.record(session, user.username, "awg_settings_update", server.name, protocol)
    return {"changed": True, "profiles_refreshed": len(profiles), "clients_require_refresh": True,
            "transaction_id": token}
