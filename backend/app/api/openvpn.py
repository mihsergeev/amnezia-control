import asyncssh
from fastapi import APIRouter, HTTPException, status
from sqlalchemy import delete, select

from app import audit, awg, deploy, limits, openvpn, sshops
from app.config import get_settings
from app.deps import CurrentUser, SessionDep
from app.models import ClientLimit, OvpnConfig, Server
from app.schemas import (
    DeployStatusOut,
    OvpnClientOut,
    OvpnConfigRequest,
    OvpnConfigResponse,
    OvpnCreateRequest,
    OvpnCreateResponse,
    OvpnDeployRequest,
    OvpnReissueRequest,
    OvpnRevokeRequest,
    OvpnStateOut,
    SnapshotOut,
    SnapshotRestoreRequest,
)
from app.sshkeys import ensure_panel_key, key_paths

router = APIRouter(prefix="/servers/{server_id}/openvpn", tags=["openvpn"])


async def _get_or_404(server_id: int, session: SessionDep) -> Server:
    server = await session.get(Server, server_id)
    if server is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Сервер не найден")
    return server


def _connect(server: Server):
    settings = get_settings()
    ensure_panel_key(settings.data_dir)
    key_path, _pub = key_paths(settings.data_dir)
    return sshops.connect(
        server.host, server.ssh_port, server.ssh_user, key_path,
        settings.ssh_connect_timeout,
    )


def _dns_pair() -> tuple[str, str]:
    return awg.dns_pair(get_settings().awg_client_dns)


def _ovpn_error(exc: Exception) -> HTTPException:
    if isinstance(exc, openvpn.OpenVpnError):
        return HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc))
    if isinstance(exc, (asyncssh.Error, OSError)):
        return HTTPException(
            status.HTTP_502_BAD_GATEWAY, f"Ошибка SSH: {exc or type(exc).__name__}"
        )
    return HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, str(exc))


async def _store_config(session, server_id, client_id, name, link) -> None:
    await session.execute(
        delete(OvpnConfig).where(
            OvpnConfig.server_id == server_id, OvpnConfig.client_id == client_id
        )
    )
    session.add(
        OvpnConfig(
            server_id=server_id, client_id=client_id, name=name, config_amnezia=link
        )
    )
    await session.commit()


@router.get("", response_model=OvpnStateOut)
async def get_openvpn(
    server_id: int, _: CurrentUser, session: SessionDep
) -> OvpnStateOut:
    server = await _get_or_404(server_id, session)
    try:
        async with _connect(server) as conn:
            container = await openvpn.detect_container(conn)
            clients = await openvpn.read_clients(conn)
    except openvpn.OpenVpnError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc)) from exc
    except (asyncssh.Error, OSError) as exc:
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY, f"Ошибка SSH: {exc or type(exc).__name__}"
        ) from exc

    stored = set(
        (
            await session.scalars(
                select(OvpnConfig.client_id).where(OvpnConfig.server_id == server_id)
            )
        ).all()
    )
    lim = await limits.limits_map(session, server_id, "openvpn")
    return OvpnStateOut(
        container=container,
        clients=[
            c.__dict__
            | {
                "has_config": c.client_id in stored,
                "expires_at": lim.get(c.client_id),
            }
            for c in clients
        ],
    )


@router.post("/clients", response_model=OvpnCreateResponse, status_code=201)
async def create_client(
    server_id: int, body: OvpnCreateRequest, user: CurrentUser, session: SessionDep
) -> OvpnCreateResponse:
    server = await _get_or_404(server_id, session)
    dns1, dns2 = _dns_pair()
    try:
        async with _connect(server) as conn:
            container = await openvpn.detect_container(conn)
            client, link = await openvpn.issue_client(
                conn, container, body.name, server.host, server.name, dns1, dns2,
            )
    except Exception as exc:  # noqa: BLE001
        raise _ovpn_error(exc) from exc
    await _store_config(session, server_id, client.client_id, client.name, link)
    if body.expires_at:
        await limits.set_limit(
            session, server_id, "openvpn", client.client_id, client.name,
            body.expires_at,
        )
    await audit.record(session, user.username, "openvpn_issue", server.name, body.name)
    return OvpnCreateResponse(
        client=OvpnClientOut(
            **client.__dict__, has_config=True, expires_at=body.expires_at
        ),
        config_amnezia=link,
    )


@router.post("/reissue", response_model=OvpnCreateResponse, status_code=201)
async def reissue_client(
    server_id: int, body: OvpnReissueRequest, user: CurrentUser, session: SessionDep
) -> OvpnCreateResponse:
    server = await _get_or_404(server_id, session)
    dns1, dns2 = _dns_pair()
    old_exp = (await limits.limits_map(session, server_id, "openvpn")).get(
        body.client_id
    )
    if "/" in body.client_id or ".." in body.client_id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "некорректный clientId")
    try:
        async with _connect(server) as conn:
            container = await openvpn.detect_container(conn)
            clients = await openvpn.read_clients(conn)
            old = next(
                (c for c in clients if c.client_id == body.client_id), None
            )
            if old is None:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "Клиент не найден")
            name = old.name if old.name and old.name != "—" else "client"
            client, link = await openvpn.reissue_client(
                conn, container, body.client_id, name,
                server.host, server.name, dns1, dns2,
            )
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise _ovpn_error(exc) from exc
    await session.execute(
        delete(OvpnConfig).where(
            OvpnConfig.server_id == server_id,
            OvpnConfig.client_id == body.client_id,
        )
    )
    await _store_config(session, server_id, client.client_id, client.name, link)
    # переносим срок действия со старого clientId на новый (id меняется при перевыпуске)
    await limits.drop_limit(session, server_id, "openvpn", body.client_id)
    if old_exp:
        await limits.set_limit(
            session, server_id, "openvpn", client.client_id, client.name, old_exp
        )
    await audit.record(
        session, user.username, "openvpn_reissue", server.name, client.name
    )
    return OvpnCreateResponse(
        client=OvpnClientOut(
            **client.__dict__, has_config=True, expires_at=old_exp
        ),
        config_amnezia=link,
    )


@router.post("/config", response_model=OvpnConfigResponse)
async def get_client_config(
    server_id: int, body: OvpnConfigRequest, _: CurrentUser, session: SessionDep
) -> OvpnConfigResponse:
    await _get_or_404(server_id, session)
    row = await session.scalar(
        select(OvpnConfig).where(
            OvpnConfig.server_id == server_id,
            OvpnConfig.client_id == body.client_id,
        )
    )
    if row is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            "Конфиг не сохранён в панели (клиент создан не через неё) — перевыпустите",
        )
    return OvpnConfigResponse(config_amnezia=row.config_amnezia, name=row.name)


@router.post("/revoke", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_client(
    server_id: int, body: OvpnRevokeRequest, user: CurrentUser, session: SessionDep
) -> None:
    server = await _get_or_404(server_id, session)
    try:
        async with _connect(server) as conn:
            container = await openvpn.detect_container(conn)
            await openvpn.revoke_client(conn, container, body.client_id)
    except Exception as exc:  # noqa: BLE001
        raise _ovpn_error(exc) from exc
    await audit.record(
        session, user.username, "openvpn_revoke", server.name, body.client_id
    )
    await session.execute(
        delete(OvpnConfig).where(
            OvpnConfig.server_id == server_id,
            OvpnConfig.client_id == body.client_id,
        )
    )
    await session.execute(
        delete(ClientLimit).where(
            ClientLimit.server_id == server_id,
            ClientLimit.protocol == "openvpn",
            ClientLimit.client_id == body.client_id,
        )
    )
    await session.commit()


@router.post("/deploy", status_code=status.HTTP_202_ACCEPTED)
async def deploy_openvpn(
    server_id: int, body: OvpnDeployRequest, user: CurrentUser, session: SessionDep
) -> dict:
    server = await _get_or_404(server_id, session)
    script = openvpn.build_deploy_script(body.port, body.site, server.host)
    try:
        async with _connect(server) as conn:
            # снимок конфига ДО (пере)развёртывания — для отката
            await deploy.snapshot_config(conn, "openvpn")
            await deploy.launch(conn, script, tag="openvpn")
    except Exception as exc:  # noqa: BLE001
        raise _ovpn_error(exc) from exc
    await audit.record(
        session, user.username, "openvpn_deploy", server.name, f"port {body.port}"
    )
    return {"started": True}


@router.get("/deploy/status", response_model=DeployStatusOut)
async def deploy_status(
    server_id: int, _: CurrentUser, session: SessionDep
) -> DeployStatusOut:
    server = await _get_or_404(server_id, session)
    try:
        async with _connect(server) as conn:
            result = await deploy.read_status(conn, tag="openvpn")
    except Exception as exc:  # noqa: BLE001
        raise _ovpn_error(exc) from exc
    return DeployStatusOut(**result)


@router.get("/config-backups", response_model=list[SnapshotOut])
async def config_backups(
    server_id: int, _: CurrentUser, session: SessionDep
) -> list[SnapshotOut]:
    server = await _get_or_404(server_id, session)
    try:
        async with _connect(server) as conn:
            snaps = await deploy.list_snapshots(conn, "openvpn")
    except Exception as exc:  # noqa: BLE001
        raise _ovpn_error(exc) from exc
    return [SnapshotOut(**s) for s in snaps]


@router.post("/config-restore", status_code=status.HTTP_202_ACCEPTED)
async def config_restore(
    server_id: int, body: SnapshotRestoreRequest, user: CurrentUser, session: SessionDep
) -> dict:
    server = await _get_or_404(server_id, session)
    try:
        async with _connect(server) as conn:
            ok = await deploy.restore_snapshot(conn, "openvpn", body.id)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        raise _ovpn_error(exc) from exc
    if not ok:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Снимок не найден на ноде")
    await audit.record(
        session, user.username, "openvpn_config_restore", server.name, body.id
    )
    return {"started": True}