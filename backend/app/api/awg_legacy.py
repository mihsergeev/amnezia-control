"""Управление СТАРЫМ AmneziaWG (legacy, интерфейс wg0) на сервере, где рядом
стоит новый AmneziaWG (awg0). Панель НЕ пересобирает legacy-контейнер (его ставила
Amnezia на ядерном движке amnezia-wg) — только клиентские операции: выдать /
перевыпустить / отозвать / пауза. Ни deploy, ни update, ни adopt здесь нет.

Метаданные (заметки, сроки, пауза) хранятся под protocol="awglegacy" — отдельно от
нового awg. Конфиги клиентов лежат в общей таблице awg_configs: пары ключей
глобально уникальны, так что коллизий между legacy и новым нет."""

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import delete, select

from app import audit, awg, limits, notes, pausestore
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
    NoteRequest,
    PublicKeyRequest,
    RevokeClientRequest,
)

router = APIRouter(prefix="/servers/{server_id}/awg-legacy", tags=["awg-legacy"])

# метаданные legacy-клиентов — под своим протоколом, чтобы не смешивать с новым awg
PROTO = "awglegacy"


async def _legacy_state(conn, host: str):
    """Состояние legacy-контейнера (wg0). 409, если его на сервере нет."""
    cont = (await awg.detect_awg_containers(conn))["legacy"]
    if not cont:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "Старый AmneziaWG (legacy) на сервере не найден.",
        )
    return await awg.read_state(conn, host, container=cont)


async def _set_note(session, server_id: int, pk: str, note: str) -> None:
    await notes.set_note(session, server_id, PROTO, pk, note)


@router.get("", response_model=AwgStateOut)
async def get_legacy(
    server_id: int, _: CurrentUser, session: SessionDep
) -> AwgStateOut:
    server = await _get_or_404(server_id, session)
    try:
        async with _connect(server) as conn:
            state = await _legacy_state(conn, server.host)
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
    clients = []
    for c in state.clients:
        clients.append(
            c.__dict__ | {
                "has_config": c.public_key in stored,
                "note": notes_by_pk.get(c.public_key, ""),
                "expires_at": lim.get(c.public_key),
                "paused": False,
            }
        )
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
            state = await _legacy_state(conn, server.host)
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
    await audit.record(session, user.username, "awglegacy_issue", server.name, body.name)
    return CreateClientResponse(
        client=client.__dict__
        | {"has_config": True, "note": body.note, "expires_at": body.expires_at},
        config=config,
        config_amnezia=_amnezia_link(config, server),
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
        config_amnezia=_amnezia_link(row.config, server),
        name=row.name,
    )


@router.post("/reissue", response_model=CreateClientResponse, status_code=201)
async def reissue_client(
    server_id: int, body: PublicKeyRequest, user: CurrentUser, session: SessionDep
) -> CreateClientResponse:
    server = await _get_or_404(server_id, session)
    dns = get_settings().awg_client_dns
    old_note = (await notes.notes_map(session, server_id, PROTO)).get(body.public_key, "")
    old_exp = (await limits.limits_map(session, server_id, PROTO)).get(body.public_key)
    try:
        async with _connect(server) as conn:
            state = await _legacy_state(conn, server.host)
            target = next(
                (c for c in state.clients if c.public_key == body.public_key), None
            )
            if target is None:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "Клиент не найден")
            name = target.name if target.name and target.name != "—" else "client"
            fixed_ip = target.address.split("/")[0] if target.address else None
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
    await _set_note(session, server_id, body.public_key, "")
    if old_note:
        await _set_note(session, server_id, client.public_key, old_note)
    await limits.drop_limit(session, server_id, PROTO, body.public_key)
    if old_exp:
        await limits.set_limit(
            session, server_id, PROTO, client.public_key, client.name, old_exp
        )
    await audit.record(
        session, user.username, "awglegacy_reissue", server.name, client.name
    )
    return CreateClientResponse(
        client=client.__dict__
        | {"has_config": True, "note": old_note, "expires_at": old_exp},
        config=config,
        config_amnezia=_amnezia_link(config, server),
    )


@router.post("/pause", status_code=status.HTTP_204_NO_CONTENT)
async def pause_client(
    server_id: int, body: PublicKeyRequest, user: CurrentUser, session: SessionDep
) -> None:
    server = await _get_or_404(server_id, session)
    try:
        async with _connect(server) as conn:
            state = await _legacy_state(conn, server.host)
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
        session, user.username, "awglegacy_pause", server.name, name or body.public_key
    )


@router.post("/resume", status_code=status.HTTP_204_NO_CONTENT)
async def resume_client(
    server_id: int, body: PublicKeyRequest, user: CurrentUser, session: SessionDep
) -> None:
    server = await _get_or_404(server_id, session)
    paused = await pausestore.list_paused(session, server_id, PROTO)
    rec = paused.get(body.public_key)
    if rec is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Клиент не на паузе")
    try:
        async with _connect(server) as conn:
            state = await _legacy_state(conn, server.host)
            await awg.resume_client(
                conn, state, body.public_key, rec["name"], rec["data"].get("ip", "")
            )
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise _ssh_error(exc) from exc
    await pausestore.drop(session, server_id, PROTO, body.public_key)
    await session.commit()
    await audit.record(session, user.username, "awglegacy_resume", server.name, rec["name"])


@router.post("/revoke", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_client(
    server_id: int, body: RevokeClientRequest, user: CurrentUser, session: SessionDep
) -> None:
    server = await _get_or_404(server_id, session)
    is_paused = body.public_key in await pausestore.list_paused(session, server_id, PROTO)
    if not is_paused:
        try:
            async with _connect(server) as conn:
                state = await _legacy_state(conn, server.host)
                await awg.revoke_client(
                    conn, state.container, state.interface, body.public_key
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
    await limits.drop_limit(session, server_id, PROTO, body.public_key)
    await _set_note(session, server_id, body.public_key, "")
    await pausestore.drop(session, server_id, PROTO, body.public_key)
    await session.commit()
    await audit.record(
        session, user.username, "awglegacy_revoke", server.name, body.public_key
    )
