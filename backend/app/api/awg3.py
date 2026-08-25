"""Управление AmneziaWG 3.x (сейчас 3.1) — третья версия протокола как ОТДЕЛЬНЫЙ
протокол рядом с 2.0 (amnezia-awg2) и legacy (wg0), как их развели между собой.

У 3.x свой контейнер (amnezia-awg3), свой порт, своя подсеть (10.8.3.0/24) и свой
каталог конфига, поэтому обе версии спокойно живут на одной ноде и операции над
одной не задевают клиентов другой.

Метаданные (заметки, сроки, пауза) — под protocol="awg3". Конфиги клиентов лежат
в общей таблице awg_configs: пары ключей глобально уникальны, коллизий нет.
"""

from fastapi import APIRouter, HTTPException, Request, status
from sqlalchemy import delete, select

from app import audit, awg, deploy, deploywatch, limits, notes, pausestore
from app.api.awg import (
    _amnezia_link,
    _connect,
    _get_or_404,
    _ssh_error,
    _store_config,
)
from app.config import get_settings
from app.deps import CurrentUser, SessionDep
from app.models import AwgConfig
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
    SnapshotOut,
    SnapshotRestoreRequest,
)

router = APIRouter(prefix="/servers/{server_id}/awg3", tags=["awg3"])

# метаданные клиентов 3.x — под своим протоколом, чтобы не смешивать с 2.0
PROTO = "awg3"


async def _state(conn, host: str):
    """Состояние контейнера 3.x. 409, если он на сервере не развёрнут."""
    names = await deploy.awg3_containers(conn)
    if not names:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "AmneziaWG 3.1 на сервере не развёрнут — сначала разверните его.",
        )
    return await awg.read_state(conn, host, container=names[0])


async def _set_note(session, server_id: int, pk: str, note: str) -> None:
    await notes.set_note(session, server_id, PROTO, pk, note)


@router.get("", response_model=AwgStateOut)
async def get_awg3(
    server_id: int, _: CurrentUser, session: SessionDep
) -> AwgStateOut:
    server = await _get_or_404(server_id, session)
    try:
        async with _connect(server) as conn:
            state = await _state(conn, server.host)
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise _ssh_error(exc) from exc

    stored = set(
        (
            await session.scalars(
                select(AwgConfig.public_key).where(AwgConfig.server_id == server_id)
            )
        ).all()
    )
    notes_by_pk = await notes.notes_map(session, server_id, PROTO)
    lim = await limits.limits_map(session, server_id, PROTO)
    paused = await pausestore.list_paused(session, server_id, PROTO)
    clients = [
        c.__dict__
        | {
            "has_config": c.public_key in stored,
            "note": notes_by_pk.get(c.public_key, ""),
            "expires_at": lim.get(c.public_key),
            "paused": False,
        }
        for c in state.clients
    ]
    live = {c["public_key"] for c in clients}
    for cid, p in paused.items():
        if cid in live:
            continue
        ip = p["data"].get("ip", "")
        clients.append({
            "name": p["name"], "public_key": cid,
            "address": f"{ip}/32" if ip else "",
            "latest_handshake": None, "rx_bytes": 0, "tx_bytes": 0, "endpoint": "",
            "has_config": cid in stored, "note": notes_by_pk.get(cid, ""),
            "expires_at": lim.get(cid), "paused": True,
        })
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
    server_id: int, body: CreateClientRequest, user: CurrentUser, session: SessionDep
) -> CreateClientResponse:
    server = await _get_or_404(server_id, session)
    dns = body.dns or get_settings().awg_client_dns
    try:
        async with _connect(server) as conn:
            state = await _state(conn, server.host)
            client, config = await awg.create_client(conn, state, body.name, dns)
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise _ssh_error(exc) from exc
    await _store_config(session, server_id, client.public_key, client.name, config)
    if body.note:
        await _set_note(session, server_id, client.public_key, body.note)
    if body.expires_at:
        await limits.set_limit(
            session, server_id, PROTO, client.public_key, client.name, body.expires_at
        )
    await audit.record(session, user.username, "awg3_issue", server.name, body.name)
    return CreateClientResponse(
        client=client.__dict__
        | {"has_config": True, "note": body.note, "expires_at": body.expires_at},
        config=config,
        config_amnezia=_amnezia_link(config, server, protocol_version=deploy.AWG3_PROTOCOL_VERSION),
    )


@router.post("/note", status_code=status.HTTP_204_NO_CONTENT)
async def set_note(
    server_id: int, body: NoteRequest, _: CurrentUser, session: SessionDep
) -> None:
    await _get_or_404(server_id, session)
    await _set_note(session, server_id, body.public_key, body.note.strip())


@router.post("/config", response_model=ConfigTextResponse)
async def get_stored_config(
    server_id: int, body: PublicKeyRequest, _: CurrentUser, session: SessionDep
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
        config_amnezia=_amnezia_link(row.config, server, protocol_version=deploy.AWG3_PROTOCOL_VERSION),
        name=row.name,
    )


@router.post("/reissue", response_model=CreateClientResponse, status_code=201)
async def reissue_client(
    server_id: int, body: PublicKeyRequest, user: CurrentUser, session: SessionDep
) -> CreateClientResponse:
    """Перевыпуск с сохранением имени и IP: старый ключ отзывается, выдаётся новый."""
    server = await _get_or_404(server_id, session)
    dns = get_settings().awg_client_dns
    note = (await notes.notes_map(session, server_id, PROTO)).get(body.public_key, "")
    try:
        async with _connect(server) as conn:
            state = await _state(conn, server.host)
            target = next(
                (c for c in state.clients if c.public_key == body.public_key), None
            )
            if target is None:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "Клиент не найден")
            name = target.name
            ip = target.address.split("/")[0]
            await awg.revoke_client(
                conn, state.container, state.interface, body.public_key
            )
            state = await _state(conn, server.host)
            client, config = await awg.create_client(
                conn, state, name, dns, fixed_ip=ip or None
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
    if note:
        await _set_note(session, server_id, client.public_key, note)
    await notes.set_note(session, server_id, PROTO, body.public_key, "")
    await audit.record(session, user.username, "awg3_reissue", server.name, name)
    return CreateClientResponse(
        client=client.__dict__ | {"has_config": True, "note": note},
        config=config,
        config_amnezia=_amnezia_link(config, server, protocol_version=deploy.AWG3_PROTOCOL_VERSION),
    )


@router.post("/pause", status_code=status.HTTP_204_NO_CONTENT)
async def pause_client(
    server_id: int, body: PublicKeyRequest, user: CurrentUser, session: SessionDep
) -> None:
    server = await _get_or_404(server_id, session)
    try:
        async with _connect(server) as conn:
            state = await _state(conn, server.host)
            target = next(
                (c for c in state.clients if c.public_key == body.public_key), None
            )
            if target is None:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "Клиент не найден")
            name = target.name
            data = await awg.pause_client(conn, state, body.public_key)
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise _ssh_error(exc) from exc
    await pausestore.add(session, server_id, PROTO, body.public_key, name, data)
    await audit.record(
        session, user.username, "awg3_pause", server.name, name or body.public_key
    )


@router.post("/resume", status_code=status.HTTP_204_NO_CONTENT)
async def resume_client(
    server_id: int, body: PublicKeyRequest, user: CurrentUser, session: SessionDep
) -> None:
    server = await _get_or_404(server_id, session)
    rec = (await pausestore.list_paused(session, server_id, PROTO)).get(body.public_key)
    if rec is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Клиент не на паузе")
    try:
        async with _connect(server) as conn:
            state = await _state(conn, server.host)
            await awg.resume_client(
                conn, state, body.public_key, rec["name"], rec["data"].get("ip", "")
            )
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise _ssh_error(exc) from exc
    await pausestore.drop(session, server_id, PROTO, body.public_key)
    await session.commit()
    await audit.record(session, user.username, "awg3_resume", server.name, rec["name"])


@router.post("/revoke", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_client(
    server_id: int, body: RevokeClientRequest, user: CurrentUser, session: SessionDep
) -> None:
    server = await _get_or_404(server_id, session)
    is_paused = body.public_key in await pausestore.list_paused(
        session, server_id, PROTO
    )
    if not is_paused:
        try:
            async with _connect(server) as conn:
                state = await _state(conn, server.host)
                await awg.revoke_client(
                    conn, state.container, state.interface, body.public_key
                )
        except HTTPException:
            raise
        except Exception as exc:  # noqa: BLE001
            raise _ssh_error(exc) from exc
    await audit.record(
        session, user.username, "awg3_revoke", server.name, body.public_key
    )
    await pausestore.drop(session, server_id, PROTO, body.public_key)
    await session.execute(
        delete(AwgConfig).where(
            AwgConfig.server_id == server_id,
            AwgConfig.public_key == body.public_key,
        )
    )
    await limits.drop_limit(session, server_id, PROTO, body.public_key)
    await session.commit()


@router.post("/deploy", status_code=status.HTTP_202_ACCEPTED)
async def deploy_awg3(
    server_id: int, body: DeployRequest, user: CurrentUser, session: SessionDep,
    request: Request,
) -> dict:
    """Разворачивает AmneziaWG 3.1. Движок и тулзы собираются на ноде из
    исходников по закреплённым тегам — готового образа с бинарями 3.0 пока нет,
    поэтому первая сборка занимает несколько минут."""
    server = await _get_or_404(server_id, session)
    cfg = deploy.generate_server_config_v3(body.port)
    script = deploy.build_script_v3("deploy", body.port, cfg)
    try:
        async with _connect(server) as conn:
            # Порт занят ЧУЖИМ контейнером — отказываемся: скрипт деплоя сносит
            # того, кто держит целевой порт (так он заменяет свой же при
            # пересборке), и рабочий протокол на этом порту погиб бы вместе с
            # клиентами. Лучше явная ошибка, чем «успешный» деплой ценой чужого.
            busy = await deploy.container_on_port(
                conn, body.port, exclude=deploy.CONTAINER_V3
            )
            if busy:
                raise HTTPException(
                    status.HTTP_409_CONFLICT,
                    f"Порт {body.port} уже занят контейнером «{busy}». "
                    "Выберите другой порт для AmneziaWG 3.0 — иначе развёртывание "
                    "снесло бы работающий контейнер вместе с его клиентами.",
                )
            # Пре-оп бэкап ВСЕХ протоколов AmneziaWG на ноде (2.0/legacy и, если
            # уже есть, 3.0) — точка отката на случай, если что-то пойдёт не так.
            await deploy.snapshot_all(conn, "awg")
            await deploy.snapshot_all(conn, PROTO)
            await deploy.launch(conn, script, tag=PROTO)
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise _ssh_error(exc) from exc
    deploywatch.spawn(request.app, server, PROTO)
    await audit.record(
        session, user.username, "awg3_deploy", server.name, f"port {body.port}"
    )
    return {"started": True}


@router.post("/update", status_code=status.HTTP_202_ACCEPTED)
async def update_awg3(
    server_id: int, user: CurrentUser, session: SessionDep, request: Request
) -> dict:
    """Пересборка образа 3.x из тех же закреплённых тегов. Конфиг и клиенты
    сохраняются (скрипт не перезаписывает существующий awg0.conf)."""
    server = await _get_or_404(server_id, session)
    cfg = deploy.generate_server_config_v3(47300)
    script = deploy.build_script_v3("update", 47300, cfg)
    try:
        async with _connect(server) as conn:
            await deploy.snapshot_all(conn, PROTO)
            await deploy.launch(conn, script, tag=PROTO)
    except Exception as exc:  # noqa: BLE001
        raise _ssh_error(exc) from exc
    deploywatch.spawn(request.app, server, PROTO)
    await audit.record(session, user.username, "awg3_update", server.name)
    return {"started": True}


@router.get("/deploy/status", response_model=DeployStatusOut)
async def deploy_status(
    server_id: int, _: CurrentUser, session: SessionDep
) -> DeployStatusOut:
    server = await _get_or_404(server_id, session)
    try:
        async with _connect(server) as conn:
            result = await deploy.read_status(conn, tag=PROTO)
    except Exception as exc:  # noqa: BLE001
        raise _ssh_error(exc) from exc
    return DeployStatusOut(**result)


@router.get("/config-backups", response_model=list[SnapshotOut])
async def config_backups(
    server_id: int, _: CurrentUser, session: SessionDep
) -> list[SnapshotOut]:
    """Снимки конфига 3.x на ноде (снимаются перед каждой пересборкой) — для отката."""
    server = await _get_or_404(server_id, session)
    try:
        async with _connect(server) as conn:
            snaps = await deploy.list_snapshots(conn, PROTO)
    except Exception as exc:  # noqa: BLE001
        raise _ssh_error(exc) from exc
    return [SnapshotOut(**s) for s in snaps]


@router.post("/config-restore", status_code=status.HTTP_202_ACCEPTED)
async def config_restore(
    server_id: int, body: SnapshotRestoreRequest, user: CurrentUser, session: SessionDep
) -> dict:
    """Откат конфига 3.x к снимку (возвращает клиентов и ключи из снимка)."""
    server = await _get_or_404(server_id, session)
    try:
        async with _connect(server) as conn:
            # пре-оп бэкап: снимок текущего состояния ДО отката — откат тоже обратим
            await deploy.snapshot_all(conn, PROTO)
            ok = await deploy.restore_snapshot(conn, PROTO, body.id)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        raise _ssh_error(exc) from exc
    if not ok:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Снимок не найден или повреждён")
    await audit.record(
        session, user.username, "awg3_config_restore", server.name, body.id
    )
    return {"restored": True}
