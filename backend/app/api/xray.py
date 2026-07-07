import asyncssh
import httpx
from fastapi import APIRouter, HTTPException, status
from sqlalchemy import delete

from app import audit, awg, deploy, limits, sshops, xray
from app.config import get_settings
from app.deps import CurrentUser, SessionDep
from app.models import ClientLimit, Server
from app.schemas import (
    DeployStatusOut,
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
    return sshops.connect(
        server.host, server.ssh_port, server.ssh_user, key_path,
        settings.ssh_connect_timeout,
    )


def _dns_pair() -> tuple[str, str]:
    return awg.dns_pair(get_settings().awg_client_dns)


def _xray_error(exc: Exception) -> HTTPException:
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
            clients = await xray.read_clients(conn)
    except Exception as exc:  # noqa: BLE001
        raise _xray_error(exc) from exc
    lim = await limits.limits_map(session, server_id, "xray")
    return XrayStateOut(
        container=container,
        clients=[
            c.__dict__ | {"expires_at": lim.get(c.client_id)} for c in clients
        ],
    )


@router.post("/clients", response_model=XrayCreateResponse, status_code=201)
async def create_client(
    server_id: int, body: XrayCreateRequest, user: CurrentUser, session: SessionDep
) -> XrayCreateResponse:
    server = await _get_or_404(server_id, session)
    dns1, dns2 = _dns_pair()
    try:
        async with _connect(server) as conn:
            container = await xray.detect_container(conn)
            client, link = await xray.issue_client(
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
        config_amnezia=link,
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
            link = await xray.build_client_link(
                conn, container, body.client_id,
                server.host, server.name, dns1, dns2,
            )
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise _xray_error(exc) from exc
    return XrayConfigResponse(config_amnezia=link, name=match.name)


@router.post("/revoke", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_client(
    server_id: int, body: XrayRevokeRequest, user: CurrentUser, session: SessionDep
) -> None:
    server = await _get_or_404(server_id, session)
    try:
        async with _connect(server) as conn:
            container = await xray.detect_container(conn)
            await xray.revoke_client(conn, container, body.client_id)
    except Exception as exc:  # noqa: BLE001
        raise _xray_error(exc) from exc
    await audit.record(
        session, user.username, "xray_revoke", server.name, body.client_id
    )
    await session.execute(
        delete(ClientLimit).where(
            ClientLimit.server_id == server_id,
            ClientLimit.protocol == "xray",
            ClientLimit.client_id == body.client_id,
        )
    )
    await session.commit()


@router.post("/deploy", status_code=status.HTTP_202_ACCEPTED)
async def deploy_xray(
    server_id: int, body: XrayDeployRequest, user: CurrentUser, session: SessionDep
) -> dict:
    server = await _get_or_404(server_id, session)
    script = xray.build_deploy_script(body.port, body.site)
    try:
        async with _connect(server) as conn:
            await deploy.launch(conn, script)
    except Exception as exc:  # noqa: BLE001
        raise _xray_error(exc) from exc
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
            result = await deploy.read_status(conn)
    except Exception as exc:  # noqa: BLE001
        raise _xray_error(exc) from exc
    return DeployStatusOut(**result)


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
    try:
        latest = await xray.latest_release()
    except (httpx.HTTPError, ValueError) as exc:
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY, f"Не удалось запросить GitHub: {exc}"
        ) from exc
    return XrayVersionOut(
        deployed=current is not None,
        current_version=current,
        latest_version=latest["version"] or None,
        latest_updated=latest["updated"],
        update_available=bool(
            current and latest["version"] and current != latest["version"]
        ),
    )


@router.post("/update", status_code=status.HTTP_202_ACCEPTED)
async def update_xray(
    server_id: int, user: CurrentUser, session: SessionDep
) -> dict:
    server = await _get_or_404(server_id, session)
    try:
        latest = await xray.latest_release()
    except (httpx.HTTPError, ValueError) as exc:
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY, f"Не удалось запросить GitHub: {exc}"
        ) from exc
    try:
        async with _connect(server) as conn:
            container = await xray.detect_container(conn)
            bits = await xray.read_server_bits(conn, container)
            script = xray.build_deploy_script(bits["port"], bits["site"], latest["tag"])
            await deploy.launch(conn, script)
    except Exception as exc:  # noqa: BLE001
        raise _xray_error(exc) from exc
    await audit.record(
        session, user.username, "xray_update", server.name, latest["tag"]
    )
    return {"started": True}
