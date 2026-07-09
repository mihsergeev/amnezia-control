import asyncssh
import httpx
from fastapi import APIRouter, HTTPException, status
from sqlalchemy import delete, select

from app import audit, awg, deploy, limits, sshops
from app.config import get_settings
from app.deps import CurrentUser, SessionDep
from app.models import AwgConfig, AwgNote, ClientLimit, Server
from app.schemas import (
    AwgStateOut,
    ConfigTextResponse,
    CreateClientRequest,
    CreateClientResponse,
    DeployRequest,
    DeployStatusOut,
    NoteRequest,
    PublicKeyRequest,
    RevokeClientRequest,
    VersionOut,
)
from app.sshkeys import ensure_panel_key, key_paths

router = APIRouter(prefix="/servers/{server_id}/awg", tags=["awg"])


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


def _ssh_error(exc: Exception) -> HTTPException:
    if isinstance(exc, awg.AwgError):
        return HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc))
    if isinstance(exc, (asyncssh.Error, OSError)):
        return HTTPException(
            status.HTTP_502_BAD_GATEWAY, f"Ошибка SSH: {exc or type(exc).__name__}"
        )
    return HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, str(exc))


async def _store_config(session, server_id, public_key, name, config) -> None:
    await session.execute(
        delete(AwgConfig).where(
            AwgConfig.server_id == server_id, AwgConfig.public_key == public_key
        )
    )
    session.add(
        AwgConfig(
            server_id=server_id, public_key=public_key, name=name, config=config
        )
    )
    await session.commit()


async def _set_note(session, server_id, public_key, note) -> None:
    await session.execute(
        delete(AwgNote).where(
            AwgNote.server_id == server_id, AwgNote.public_key == public_key
        )
    )
    if note:
        session.add(
            AwgNote(server_id=server_id, public_key=public_key, note=note)
        )
    await session.commit()


async def _notes_map(session, server_id) -> dict[str, str]:
    rows = await session.execute(
        select(AwgNote.public_key, AwgNote.note).where(AwgNote.server_id == server_id)
    )
    return {pub: note for pub, note in rows.all()}


def _amnezia_link(config: str, server: Server) -> str:
    dns1, dns2 = awg.dns_pair(get_settings().awg_client_dns)
    return awg.build_amnezia_link(config, server.host, server.name, dns1, dns2)


@router.get("", response_model=AwgStateOut)
async def get_awg(server_id: int, _: CurrentUser, session: SessionDep) -> AwgStateOut:
    server = await _get_or_404(server_id, session)
    try:
        async with _connect(server) as conn:
            state = await awg.read_state(conn, server.host)
    except Exception as exc:  # noqa: BLE001
        raise _ssh_error(exc) from exc

    stored = set(
        (
            await session.scalars(
                select(AwgConfig.public_key).where(AwgConfig.server_id == server_id)
            )
        ).all()
    )
    notes = await _notes_map(session, server_id)
    lim = await limits.limits_map(session, server_id, "awg")
    clients = []
    for c in state.clients:
        item = c.__dict__ | {
            "has_config": c.public_key in stored,
            "note": notes.get(c.public_key, ""),
            "expires_at": lim.get(c.public_key),
        }
        clients.append(item)
    return AwgStateOut(
        container=state.container,
        interface=state.interface,
        listen_port=state.listen_port,
        server_public_key=state.server_public_key,
        endpoint=state.endpoint,
        address=state.address,
        clients=clients,
    )


@router.post("/clients", response_model=CreateClientResponse, status_code=201)
async def create_client(
    server_id: int,
    body: CreateClientRequest,
    user: CurrentUser,
    session: SessionDep,
) -> CreateClientResponse:
    server = await _get_or_404(server_id, session)
    dns = body.dns or get_settings().awg_client_dns
    try:
        async with _connect(server) as conn:
            state = await awg.read_state(conn, server.host)
            client, config = await awg.create_client(conn, state, body.name, dns)
    except Exception as exc:  # noqa: BLE001
        raise _ssh_error(exc) from exc
    await _store_config(session, server_id, client.public_key, client.name, config)
    if body.note:
        await _set_note(session, server_id, client.public_key, body.note)
    if body.expires_at:
        await limits.set_limit(
            session, server_id, "awg", client.public_key, client.name, body.expires_at
        )
    await audit.record(session, user.username, "awg_issue", server.name, body.name)
    return CreateClientResponse(
        client=client.__dict__
        | {"has_config": True, "note": body.note, "expires_at": body.expires_at},
        config=config,
        config_amnezia=_amnezia_link(config, server),
    )


@router.post("/note", status_code=status.HTTP_204_NO_CONTENT)
async def set_note(
    server_id: int,
    body: NoteRequest,
    _: CurrentUser,
    session: SessionDep,
) -> None:
    await _get_or_404(server_id, session)
    await _set_note(session, server_id, body.public_key, body.note.strip())


@router.post("/config", response_model=ConfigTextResponse)
async def get_stored_config(
    server_id: int,
    body: PublicKeyRequest,
    _: CurrentUser,
    session: SessionDep,
) -> ConfigTextResponse:
    server = await _get_or_404(server_id, session)
    row = await session.scalar(
        select(AwgConfig).where(
            AwgConfig.server_id == server_id,
            AwgConfig.public_key == body.public_key,
        )
    )
    if row is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            "Конфиг не сохранён в панели (клиент создан не через неё) — перевыпустите",
        )
    return ConfigTextResponse(
        config=row.config,
        config_amnezia=_amnezia_link(row.config, server),
        name=row.name,
    )


@router.post("/reissue", response_model=CreateClientResponse, status_code=201)
async def reissue_client(
    server_id: int,
    body: PublicKeyRequest,
    user: CurrentUser,
    session: SessionDep,
) -> CreateClientResponse:
    server = await _get_or_404(server_id, session)
    dns = get_settings().awg_client_dns
    old_note = (await _notes_map(session, server_id)).get(body.public_key, "")
    old_exp = (await limits.limits_map(session, server_id, "awg")).get(body.public_key)
    try:
        async with _connect(server) as conn:
            state = await awg.read_state(conn, server.host)
            target = next(
                (c for c in state.clients if c.public_key == body.public_key), None
            )
            if target is None:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "Клиент не найден")
            name = target.name if target.name and target.name != "—" else "client"
            fixed_ip = target.address.split("/")[0] if target.address else None
            # снимаем старого пира и выдаём новый ключ на тот же адрес/имя
            await awg.revoke_client(
                conn, state.container, state.interface, body.public_key
            )
            client, config = await awg.create_client(
                conn, state, name, dns, fixed_ip=fixed_ip
            )
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise _ssh_error(exc) from exc
    await session.execute(
        delete(AwgConfig).where(
            AwgConfig.server_id == server_id,
            AwgConfig.public_key == body.public_key,
        )
    )
    await _store_config(session, server_id, client.public_key, client.name, config)
    # переносим заметку со старого ключа на новый
    await _set_note(session, server_id, body.public_key, "")
    if old_note:
        await _set_note(session, server_id, client.public_key, old_note)
    # переносим срок действия со старого ключа на новый
    await limits.drop_limit(session, server_id, "awg", body.public_key)
    if old_exp:
        await limits.set_limit(
            session, server_id, "awg", client.public_key, client.name, old_exp
        )
    await audit.record(session, user.username, "awg_reissue", server.name, client.name)
    return CreateClientResponse(
        client=client.__dict__
        | {"has_config": True, "note": old_note, "expires_at": old_exp},
        config=config,
        config_amnezia=_amnezia_link(config, server),
    )


@router.post("/deploy", status_code=status.HTTP_202_ACCEPTED)
async def deploy_awg(
    server_id: int, body: DeployRequest, user: CurrentUser, session: SessionDep
) -> dict:
    server = await _get_or_404(server_id, session)
    cfg = deploy.generate_server_config(body.port)
    script = deploy.build_script("deploy", body.port, cfg)
    try:
        async with _connect(server) as conn:
            await deploy.launch(conn, script, tag="awg")
    except Exception as exc:  # noqa: BLE001
        raise _ssh_error(exc) from exc
    await audit.record(
        session, user.username, "awg_deploy", server.name, f"port {body.port}"
    )
    return {"started": True}


@router.post("/update", status_code=status.HTTP_202_ACCEPTED)
async def update_awg(
    server_id: int, user: CurrentUser, session: SessionDep
) -> dict:
    server = await _get_or_404(server_id, session)
    # config уже есть на ноде и сохраняется; cfg тут не используется
    cfg = deploy.generate_server_config(47180)
    script = deploy.build_script("update", 47180, cfg)
    try:
        async with _connect(server) as conn:
            await deploy.launch(conn, script, tag="awg")
    except Exception as exc:  # noqa: BLE001
        raise _ssh_error(exc) from exc
    await audit.record(session, user.username, "awg_update", server.name)
    return {"started": True}


@router.get("/deploy/status", response_model=DeployStatusOut)
async def deploy_status(
    server_id: int, _: CurrentUser, session: SessionDep
) -> DeployStatusOut:
    server = await _get_or_404(server_id, session)
    try:
        async with _connect(server) as conn:
            result = await deploy.read_status(conn, tag="awg")
    except Exception as exc:  # noqa: BLE001
        raise _ssh_error(exc) from exc
    return DeployStatusOut(**result)


@router.get("/version", response_model=VersionOut)
async def awg_version(
    server_id: int, _: CurrentUser, session: SessionDep
) -> VersionOut:
    server = await _get_or_404(server_id, session)
    try:
        async with _connect(server) as conn:
            current_digest = await deploy.node_base_digest(conn)
            awg_go = await deploy.node_awg_go_version(conn)
    except Exception as exc:  # noqa: BLE001
        raise _ssh_error(exc) from exc
    try:
        hub = await deploy.hub_info()
    except (httpx.HTTPError, ValueError) as exc:
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY, f"Не удалось запросить Docker Hub: {exc}"
        ) from exc
    current_version = (
        hub["digest_to_version"].get(current_digest) if current_digest else None
    )
    return VersionOut(
        deployed=current_digest is not None,
        current_version=current_version,
        current_awg_go=awg_go,
        latest_version=hub["latest_version"],
        latest_updated=hub["latest_updated"],
        update_available=bool(current_digest) and current_digest != hub["latest_digest"],
    )


@router.post("/revoke", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_client(
    server_id: int,
    body: RevokeClientRequest,
    user: CurrentUser,
    session: SessionDep,
) -> None:
    server = await _get_or_404(server_id, session)
    try:
        async with _connect(server) as conn:
            state = await awg.read_state(conn, server.host)
            await awg.revoke_client(
                conn, state.container, state.interface, body.public_key
            )
    except Exception as exc:  # noqa: BLE001
        raise _ssh_error(exc) from exc
    await audit.record(
        session, user.username, "awg_revoke", server.name, body.public_key
    )
    await session.execute(
        delete(AwgConfig).where(
            AwgConfig.server_id == server_id,
            AwgConfig.public_key == body.public_key,
        )
    )
    await session.execute(
        delete(AwgNote).where(
            AwgNote.server_id == server_id,
            AwgNote.public_key == body.public_key,
        )
    )
    await session.execute(
        delete(ClientLimit).where(
            ClientLimit.server_id == server_id,
            ClientLimit.protocol == "awg",
            ClientLimit.client_id == body.public_key,
        )
    )
    await session.commit()
