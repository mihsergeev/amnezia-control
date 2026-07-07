from fastapi import APIRouter, HTTPException, status
from sqlalchemy import delete as sa_delete
from sqlalchemy import select

from app import audit, limits, server_ops, sshops
from app.config import get_settings
from app.deps import CurrentUser, SessionDep
from app.models import (
    AwgConfig,
    AwgNote,
    ClientLimit,
    ClientTrafficSample,
    NodeMetric,
    Server,
    ServerStatus,
)
from app.schemas import (
    BootstrapRequest,
    DeleteServerResult,
    ServerCreate,
    ServerOut,
    ServerUpdate,
    SetLimitRequest,
    SetupScriptOut,
)
from app.sshkeys import ensure_panel_key, key_paths

router = APIRouter(prefix="/servers", tags=["servers"])


async def _get_or_404(server_id: int, session: SessionDep) -> Server:
    server = await session.get(Server, server_id)
    if server is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Сервер не найден")
    return server


@router.get("", response_model=list[ServerOut])
async def list_servers(_: CurrentUser, session: SessionDep) -> list[Server]:
    result = await session.scalars(select(Server).order_by(Server.id))
    return list(result)


@router.post("", response_model=ServerOut, status_code=status.HTTP_201_CREATED)
async def create_server(
    body: ServerCreate, user: CurrentUser, session: SessionDep
) -> Server:
    server = Server(**body.model_dump())
    session.add(server)
    await session.commit()
    await session.refresh(server)
    await audit.record(session, user.username, "server_create", server.name, server.host)
    return server


@router.get("/{server_id}", response_model=ServerOut)
async def get_server(server_id: int, _: CurrentUser, session: SessionDep) -> Server:
    return await _get_or_404(server_id, session)


@router.patch("/{server_id}", response_model=ServerOut)
async def update_server(
    server_id: int, body: ServerUpdate, _: CurrentUser, session: SessionDep
) -> Server:
    server = await _get_or_404(server_id, session)
    for field, value in body.model_dump(exclude_unset=True).items():
        setattr(server, field, value)
    await session.commit()
    await session.refresh(server)
    return server


@router.delete("/{server_id}", response_model=DeleteServerResult)
async def delete_server(
    server_id: int,
    user: CurrentUser,
    session: SessionDep,
    remove_key: bool = False,
) -> DeleteServerResult:
    server = await _get_or_404(server_id, session)
    result = DeleteServerResult()
    server_name = server.name

    if remove_key:
        settings = get_settings()
        public_key = ensure_panel_key(settings.data_dir)
        key_path, _pub = key_paths(settings.data_dir)
        try:
            async with sshops.connect(
                server.host, server.ssh_port, server.ssh_user, key_path,
                settings.ssh_connect_timeout,
            ) as conn:
                await sshops.remove_authorized_key(conn, public_key)
            result.key_removed = True
            result.message = "Ключ панели убран с сервера."
        except Exception as exc:  # noqa: BLE001 — удаление из панели важнее
            result.key_removed = False
            result.message = (
                f"Сервер убран из панели, но снять ключ не удалось "
                f"(сервер недоступен?): {exc or type(exc).__name__}"
            )

    # чистим панельные хвосты (на сам сервер не влияет)
    await session.execute(sa_delete(AwgConfig).where(AwgConfig.server_id == server_id))
    await session.execute(sa_delete(AwgNote).where(AwgNote.server_id == server_id))
    await session.execute(
        sa_delete(ClientLimit).where(ClientLimit.server_id == server_id)
    )
    await session.execute(
        sa_delete(NodeMetric).where(NodeMetric.server_id == server_id)
    )
    await session.execute(
        sa_delete(ServerStatus).where(ServerStatus.server_id == server_id)
    )
    await session.execute(
        sa_delete(ClientTrafficSample).where(
            ClientTrafficSample.server_id == server_id
        )
    )
    await session.delete(server)
    await session.commit()
    await audit.record(
        session, user.username, "server_delete", server_name,
        "ключ снят" if remove_key else "",
    )
    return result


@router.get("/{server_id}/setup-script", response_model=SetupScriptOut)
async def setup_script(
    server_id: int, _: CurrentUser, session: SessionDep
) -> SetupScriptOut:
    server = await _get_or_404(server_id, session)
    settings = get_settings()
    public_key = ensure_panel_key(settings.data_dir)
    script = sshops.build_setup_script(
        public_key, server.ssh_user, server.ssh_port, settings.panel_ip
    )
    return SetupScriptOut(script=script, panel_public_key=public_key)


@router.post("/{server_id}/check", response_model=ServerOut)
async def check_server(
    server_id: int, _: CurrentUser, session: SessionDep
) -> Server:
    server = await _get_or_404(server_id, session)
    await server_ops.run_check(session, server, get_settings())
    return server


@router.post("/{server_id}/limit", status_code=status.HTTP_204_NO_CONTENT)
async def set_limit(
    server_id: int, body: SetLimitRequest, user: CurrentUser, session: SessionDep
) -> None:
    server = await _get_or_404(server_id, session)
    await limits.set_limit(
        session, server_id, body.protocol, body.client_id, body.name, body.expires_at,
    )
    action = "limit_set" if body.expires_at else "limit_clear"
    detail = f"{body.protocol}: {body.name or body.client_id}"
    if body.expires_at:
        detail += f" → {body.expires_at.isoformat()}"
    await audit.record(session, user.username, action, server.name, detail)


@router.post("/{server_id}/bootstrap", response_model=ServerOut)
async def bootstrap_server(
    server_id: int, body: BootstrapRequest, _: CurrentUser, session: SessionDep
) -> Server:
    server = await _get_or_404(server_id, session)
    ok, error = await server_ops.bootstrap_and_check(
        session, server, body.password, get_settings(), body.become_password
    )
    if not ok:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, error)
    return server
