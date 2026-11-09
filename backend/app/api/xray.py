import asyncssh
from fastapi import APIRouter, HTTPException, Request, status
from sqlalchemy import delete

from app import audit, awg, bulk_issue_state, deploy, deploywatch, limits, nodelock, notes, pausestore, sshops, xray, xray_reality
from app.config import get_settings
from app.deps import CurrentUser, SessionDep
from app.models import ClientLimit, Server
from app.schemas import (
    ClientNoteRequest,
    DeployStatusOut,
    SnapshotOut,
    SnapshotRestoreRequest,
    XrayClientOut,
    XrayConfigRequest,
    XrayConfigResponse,
    XrayCreateRequest,
    XrayCreateResponse,
    XrayDeployRequest,
    XrayRevokeRequest,
    XrayStateOut,
    XrayVersionOut,
)
from app.sshkeys import ensure_panel_key, key_paths

router = APIRouter(prefix="/servers/{server_id}/xray", tags=["xray"])


async def _get_or_404(server_id: int, session: SessionDep) -> Server:
    server = await session.get(Server, server_id)
    if server is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Сервер не найден")
    return server


def _connect(server: Server):
    settings = get_settings()
    ensure_panel_key(settings.data_dir)
    key_path, _pub = key_paths(settings.data_dir)
    # одна операция на ноде за раз, см. nodelock
    return nodelock.connect("xray", server.id, sshops.connect(
        server.host, server.ssh_port, server.ssh_user, key_path,
        settings.ssh_connect_timeout,
    ))


def _dns_pair() -> tuple[str, str]:
    return awg.dns_pair(get_settings().awg_client_dns)


def _xray_error(exc: Exception) -> HTTPException:
    if isinstance(exc, HTTPException):
        return exc
    if isinstance(exc, deploy.DeployBusy):
        return HTTPException(status.HTTP_409_CONFLICT, str(exc))
    if isinstance(exc, xray.XrayNotDeployed):
        return HTTPException(status.HTTP_409_CONFLICT, str(exc))
    if isinstance(exc, xray_reality.RealityConflict):
        return HTTPException(status.HTTP_409_CONFLICT, str(exc))
    if isinstance(exc, xray_reality.RealityValidation):
        return HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc))
    if isinstance(exc, xray.XrayError):
        return HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc))
    if isinstance(exc, (asyncssh.Error, OSError)):
        return HTTPException(
            status.HTTP_502_BAD_GATEWAY, f"Ошибка SSH: {exc or type(exc).__name__}"
        )
    return HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, str(exc))


@router.get("", response_model=XrayStateOut)
async def get_xray(server_id: int, _: CurrentUser, session: SessionDep) -> XrayStateOut:
    server = await _get_or_404(server_id, session)
    try:
        async with _connect(server) as conn:
            container = await xray.detect_container(conn)
            clients, counters = await xray.read_clients_and_stats(conn, container)
            stats = xray.client_stats_by_id(clients, counters)
    except Exception as exc:  # noqa: BLE001
        raise _xray_error(exc) from exc
    lim = await limits.limits_map(session, server_id, "xray")
    note_map = await notes.notes_map(session, server_id, "xray")
    paused = await pausestore.list_paused(session, server_id, "xray")
    out = [
        {
            "client_id": c.client_id,
            "name": c.name,
            "creation_date": c.creation_date,
            "expires_at": lim.get(c.client_id),
            "note": note_map.get(c.client_id, ""),
            "rx_bytes": stats.get(c.client_id, {}).get("up", 0),
            "tx_bytes": stats.get(c.client_id, {}).get("down", 0),
            "paused": False,
        }
        for c in clients
    ]
    live = {c["client_id"] for c in out}
    # с ноды клиент на паузе снят: трафик - из истории панели
    last = await pausestore.last_traffic(session, server_id, "xray", set(paused) - live)
    for cid, p in paused.items():
        if cid in live:
            continue
        out.append({
            "client_id": cid, "name": p["name"], "creation_date": "",
            "expires_at": lim.get(cid), "note": note_map.get(cid, ""),
            "rx_bytes": last.get(cid, {}).get("rx", 0),
            "tx_bytes": last.get(cid, {}).get("tx", 0), "paused": True,
        })
    return XrayStateOut(container=container, clients=out)


@router.get("/reality", response_model=xray_reality.RealityState)
async def get_reality(server_id: int, _: CurrentUser, session: SessionDep) -> xray_reality.RealityState:
    server = await _get_or_404(server_id, session)
    try:
        async with _connect(server) as conn:
            container = await xray.detect_container(conn)
            return await xray_reality.read(conn, container)
    except Exception as exc:  # noqa: BLE001
        raise _xray_error(exc) from exc


@router.put("/reality", response_model=xray_reality.RealityState)
@nodelock.operation("xray")
async def update_reality(
    server_id: int, body: xray_reality.RealityUpdate, user: CurrentUser, session: SessionDep,
) -> xray_reality.RealityState:
    server = await _get_or_404(server_id, session)
    try:
        async with _connect(server) as conn:
            container = await xray.detect_container(conn)
            state, changed = await xray_reality.update(conn, container, body, server.host)
    except Exception as exc:  # noqa: BLE001
        raise _xray_error(exc) from exc
    if changed:
        await audit.record(session, user.username, "xray_reality_update", server.name)
    return state


@router.post("/note", status_code=status.HTTP_204_NO_CONTENT)
async def set_note(
    server_id: int, body: ClientNoteRequest, _: CurrentUser, session: SessionDep
) -> None:
    await _get_or_404(server_id, session)
    await notes.set_note(session, server_id, "xray", body.client_id, body.note.strip())


@router.post("/clients", response_model=XrayCreateResponse, status_code=201)
@nodelock.operation("xray")
async def create_client(
    server_id: int, body: XrayCreateRequest, user: CurrentUser, session: SessionDep
) -> XrayCreateResponse:
    server = await _get_or_404(server_id, session)
    dns1, dns2 = _dns_pair()
    try:
        async with _connect(server) as conn:
            container = await xray.detect_container(conn)
            client, configs = await xray.issue_client(
                conn, container, body.name, server.host, server.name, dns1, dns2,
            )
    except Exception as exc:  # noqa: BLE001
        raise _xray_error(exc) from exc
    if body.expires_at:
        await limits.set_limit(
            session, server_id, "xray", client.client_id, client.name,
            body.expires_at,
        )
    await audit.record(session, user.username, "xray_issue", server.name, body.name)
    return XrayCreateResponse(
        client=XrayClientOut(**client.__dict__, expires_at=body.expires_at),
        config_amnezia=configs[0]["amnezia"],
        configs=configs,
    )


@router.post("/config", response_model=XrayConfigResponse)
async def get_client_config(
    server_id: int, body: XrayConfigRequest, _: CurrentUser, session: SessionDep
) -> XrayConfigResponse:
    server = await _get_or_404(server_id, session)
    dns1, dns2 = _dns_pair()
    try:
        async with _connect(server) as conn:
            container = await xray.detect_container(conn)
            clients = await xray.read_clients(conn)
            match = next(
                (c for c in clients if c.client_id == body.client_id), None
            )
            if match is None:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "Клиент не найден")
            configs = await xray.build_client_link(
                conn, container, body.client_id,
                server.host, server.name, dns1, dns2, match.name,
            )
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise _xray_error(exc) from exc
    return XrayConfigResponse(
        config_amnezia=configs[0]["amnezia"], name=match.name, configs=configs,
    )


@router.post("/pause", status_code=status.HTTP_204_NO_CONTENT)
@nodelock.operation("xray")
async def pause_client(
    server_id: int, body: XrayRevokeRequest, user: CurrentUser, session: SessionDep
) -> None:
    """Пауза: убирает UUID с сервера (не сможет подключиться), запоминает его dict
    для возобновления без смены UUID."""
    server = await _get_or_404(server_id, session)
    name = ""
    try:
        async with _connect(server) as conn:
            container = await xray.detect_container(conn)
            clients = await xray.read_clients(conn)
            match = next(
                (c for c in clients if c.client_id == body.client_id), None
            )
            if match is None:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "Клиент не найден")
            name = match.name
            entry = await xray.pause_client(conn, container, body.client_id)
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise _xray_error(exc) from exc
    await pausestore.add(
        session, server_id, "xray", body.client_id, name, {"entry": entry}
    )
    await audit.record(
        session, user.username, "xray_pause", server.name, name or body.client_id
    )


@router.post("/resume", status_code=status.HTTP_204_NO_CONTENT)
@nodelock.operation("xray")
async def resume_client(
    server_id: int, body: XrayRevokeRequest, user: CurrentUser, session: SessionDep
) -> None:
    """Возобновление: возвращает клиента (тот же UUID) на сервер."""
    server = await _get_or_404(server_id, session)
    rec = (await pausestore.list_paused(session, server_id, "xray")).get(body.client_id)
    if rec is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Клиент не на паузе")
    entry = rec["data"].get("entry") or {"id": body.client_id, "flow": xray.FLOW}
    try:
        async with _connect(server) as conn:
            container = await xray.detect_container(conn)
            await xray.resume_client(conn, container, entry, rec["name"])
    except Exception as exc:  # noqa: BLE001
        raise _xray_error(exc) from exc
    await pausestore.drop(session, server_id, "xray", body.client_id)
    await session.commit()
    await audit.record(
        session, user.username, "xray_resume", server.name, rec["name"]
    )


@router.post("/revoke", status_code=status.HTTP_204_NO_CONTENT)
@nodelock.operation("xray")
async def revoke_client(
    server_id: int, body: XrayRevokeRequest, user: CurrentUser, session: SessionDep
) -> None:
    server = await _get_or_404(server_id, session)
    # Snapshot restore can put a paused UUID back into server.json. Revoke on
    # the node even when the panel still has the pause record, as AWG does.
    try:
        async with _connect(server) as conn:
            container = await xray.detect_container(conn)
            await bulk_issue_state.request_cancel(session, server_id, "xray", [body.client_id])
            await xray.revoke_client(conn, container, body.client_id)
    except Exception as exc:  # noqa: BLE001
        raise _xray_error(exc) from exc
    await bulk_issue_state.cancel_clients(session, server_id, "xray", [body.client_id])
    await pausestore.drop(session, server_id, "xray", body.client_id)
    await session.commit()
    await audit.record(
        session, user.username, "xray_revoke", server.name, body.client_id
    )
    await notes.clear_note(session, server_id, "xray", body.client_id)
    await session.execute(
        delete(ClientLimit).where(
            ClientLimit.server_id == server_id,
            ClientLimit.protocol == "xray",
            ClientLimit.client_id == body.client_id,
        )
    )
    await session.commit()


@router.post("/reissue", response_model=XrayCreateResponse, status_code=201)
@nodelock.operation("xray")
async def reissue_client(
    server_id: int, body: XrayRevokeRequest, user: CurrentUser, session: SessionDep
) -> XrayCreateResponse:
    """Перевыпуск: отзывает старый UUID и выдаёт новый с тем же именем/сроком."""
    server = await _get_or_404(server_id, session)
    dns1, dns2 = _dns_pair()
    old_exp = (await limits.limits_map(session, server_id, "xray")).get(body.client_id)
    old_note = (await notes.notes_map(session, server_id, "xray")).get(body.client_id, "")
    try:
        async with _connect(server) as conn:
            container = await xray.detect_container(conn)
            clients = await xray.read_clients(conn)
            target = next(
                (c for c in clients if c.client_id == body.client_id), None
            )
            if target is None:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "Клиент не найден")
            name = target.name if target.name and target.name != "—" else "client"
            await bulk_issue_state.request_cancel(session, server_id, "xray", [body.client_id])
            await xray.revoke_client(conn, container, body.client_id)
            await bulk_issue_state.cancel_clients(session, server_id, "xray", [body.client_id])
            await session.commit()
            client, configs = await xray.issue_client(
                conn, container, name, server.host, server.name, dns1, dns2,
            )
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise _xray_error(exc) from exc
    # переносим срок и заметку со старого UUID на новый
    await limits.drop_limit(session, server_id, "xray", body.client_id)
    await notes.set_note(session, server_id, "xray", body.client_id, "")
    if old_note:
        await notes.set_note(session, server_id, "xray", client.client_id, old_note)
    if old_exp:
        await limits.set_limit(
            session, server_id, "xray", client.client_id, client.name, old_exp
        )
    await audit.record(session, user.username, "xray_reissue", server.name, client.name)
    return XrayCreateResponse(
        client=XrayClientOut(**client.__dict__, expires_at=old_exp, note=old_note),
        config_amnezia=configs[0]["amnezia"],
        configs=configs,
    )


@router.post("/deploy", status_code=status.HTTP_202_ACCEPTED)
async def deploy_xray(
    server_id: int, body: XrayDeployRequest, user: CurrentUser, session: SessionDep,
    request: Request,
) -> dict:
    server = await _get_or_404(server_id, session)
    # закрепленная версия, а не последний релиз: см. xray.XRAY_RELEASE
    script = xray.build_deploy_script(
        body.port, body.site, dest=body.dest, require_fresh=bool(body.site or body.dest),
    )
    try:
        async with _connect(server) as conn:
            await deploy.ensure_idle(conn, tag="xray")
            # Порт проверяем до сборки образа и генерации ключей. Раньше установка
            # упиралась в него только на docker run: на ноде с панелью 443 держит
            # caddy, и XRay падал с "port is already allocated", оставляя мертвый
            # контейнер.
            bind_ip = await xray.deployment_bind_ip(conn, body.port)
            owner = await deploy.port_owner(
                conn, body.port, "tcp", own=xray.CONTAINER_NAME, bind_ip=bind_ip,
            )
            if owner:
                raise HTTPException(
                    status.HTTP_409_CONFLICT,
                    deploy.port_busy_detail(body.port, "tcp", owner, "XRay"),
                )
            # пре-оп бэкап: если разворачиваем поверх существующего — снимем конфиг
            await deploy.snapshot_all(conn, "xray")
            await deploy.launch(conn, script, tag="xray")
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise _xray_error(exc) from exc
    deploywatch.spawn(request.app, server, "xray")
    await audit.record(
        session, user.username, "xray_deploy", server.name, f"port {body.port}"
    )
    return {"started": True}


@router.get("/deploy/status", response_model=DeployStatusOut)
async def deploy_status(
    server_id: int, _: CurrentUser, session: SessionDep
) -> DeployStatusOut:
    server = await _get_or_404(server_id, session)
    try:
        async with _connect(server) as conn:
            result = await deploy.read_status(conn, tag="xray")
    except Exception as exc:  # noqa: BLE001
        raise _xray_error(exc) from exc
    return DeployStatusOut(**result)


@router.get("/config-backups", response_model=list[SnapshotOut])
async def config_backups(
    server_id: int, _: CurrentUser, session: SessionDep
) -> list[SnapshotOut]:
    server = await _get_or_404(server_id, session)
    try:
        async with _connect(server) as conn:
            snaps = await deploy.list_snapshots(conn, "xray")
    except Exception as exc:  # noqa: BLE001
        raise _xray_error(exc) from exc
    return [SnapshotOut(**s) for s in snaps]


@router.post("/config-restore", status_code=status.HTTP_202_ACCEPTED)
async def config_restore(
    server_id: int, body: SnapshotRestoreRequest, user: CurrentUser, session: SessionDep
) -> dict:
    server = await _get_or_404(server_id, session)
    try:
        async with _connect(server) as conn:
            # снимок текущего состояния ДО отката — сам откат тоже обратим
            await deploy.snapshot_config(conn, "xray")
            ok = await deploy.restore_snapshot(conn, "xray", body.id)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        raise _xray_error(exc) from exc
    if not ok:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, "Снимок не найден или повреждён"
        )
    await audit.record(
        session, user.username, "xray_config_restore", server.name, body.id
    )
    return {"started": True}


@router.get("/version", response_model=XrayVersionOut)
async def xray_version(
    server_id: int, _: CurrentUser, session: SessionDep
) -> XrayVersionOut:
    server = await _get_or_404(server_id, session)
    try:
        async with _connect(server) as conn:
            container = await xray.detect_container(conn)
            current = await xray.node_version(conn, container)
    except Exception as exc:  # noqa: BLE001
        raise _xray_error(exc) from exc
    # "обновление" - только до закрепленной версии и только вверх. Нода, на
    # которой уже стоит что-то новее (поставили руками), не зовется обновлять:
    # переустановка вернет ее на закрепленную
    target = xray.XRAY_RELEASE.lstrip("v")
    return XrayVersionOut(
        deployed=current is not None,
        current_version=current,
        latest_version=target,
        latest_updated="",
        update_available=bool(
            current and xray.version_tuple(current) < xray.version_tuple(target)
        ),
    )


@router.post("/update", status_code=status.HTTP_202_ACCEPTED)
async def update_xray(
    server_id: int, user: CurrentUser, session: SessionDep, request: Request
) -> dict:
    server = await _get_or_404(server_id, session)
    release = xray.XRAY_RELEASE
    try:
        async with _connect(server) as conn:
            await deploy.ensure_idle(conn, tag="xray")
            container = await xray.detect_container(conn)
            if container != xray.CONTAINER_NAME:
                raise HTTPException(status.HTTP_409_CONFLICT, "Обновление требует контейнер с именем amnezia-xray.")
            bits = await xray.read_server_bits(conn, container)
            await deploy.snapshot_config(conn, "xray")
            staged_stats = await xray.stage_update_stats(conn, container)
            try:
                script = xray.build_deploy_script(
                    bits["port"], bits["site"], release, preserve_port=True,
                    staged_stats=staged_stats,
                )
                await deploy.launch(conn, script, tag="xray")
            except Exception:
                if staged_stats is not None:
                    await xray.discard_staged_stats(conn, staged_stats[0])
                raise
    except Exception as exc:  # noqa: BLE001
        raise _xray_error(exc) from exc
    deploywatch.spawn(request.app, server, "xray")
    await audit.record(
        session, user.username, "xray_update", server.name, release
    )
    return {"started": True}
