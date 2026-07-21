"""Интеграционный API v1 — стабильный контракт для внешних систем.

Отдельный контур от UI-эндпойнтов намеренно: те заточены под фронт и меняются
вместе с ним, а здесь контракт versioned и ломать его нельзя. Аутентификация —
API-ключ в заголовке `X-API-Key` (см. app/apikeys.py), НЕ пользовательский JWT.

Права ключа узкие: клиентские операции AmneziaWG + чтение списка серверов.
Развернуть/удалить сервер, сменить настройки или забрать full-access ключом
НЕЛЬЗЯ — это осталось под пользовательским JWT.

Идентификатор клиента — его WireGuard public key. Он base64 и содержит «/», «+»,
«=», поэтому передаётся ПАРАМЕТРОМ ЗАПРОСА (url-encoded), а не в пути: в пути
слэш из ключа развалил бы маршрут.
"""

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import delete, select

from app import audit, awg, limits, pausestore
from app.api.awg import (
    _amnezia_link,
    _connect,
    _get_or_404,
    _set_note,
    _ssh_error,
    _store_config,
    build_client_list,
)
from app.config import get_settings
from app.deps import ApiClient, SessionDep
from app.models import AwgConfig, Server
from app.schemas import (
    AwgClientOut,
    ConfigTextResponse,
    CreateClientRequest,
    CreateClientResponse,
    V1ServerOut,
)

router = APIRouter(prefix="/v1", tags=["integration-v1"])

_PK = Query(
    ...,
    min_length=1,
    description="WireGuard public key клиента (url-encoded: «/» → %2F, «+» → %2B, «=» → %3D)",
)


def _actor(client) -> str:
    """Кто в журнале аудита: имя ключа, чтобы действия интеграции были отличимы."""
    return f"apikey:{client.name}"


@router.get("/servers", response_model=list[V1ServerOut], summary="Список серверов")
async def list_servers(_: ApiClient, session: SessionDep) -> list[Server]:
    """Серверы панели. `last_check_ok` — результат последней проверки доступности
    (`null` — ещё не проверялся)."""
    rows = await session.scalars(select(Server).order_by(Server.position, Server.id))
    return list(rows)


@router.get(
    "/servers/{server_id}/clients",
    response_model=list[AwgClientOut],
    summary="Список клиентов AmneziaWG",
)
async def list_clients(
    server_id: int, _: ApiClient, session: SessionDep
) -> list[dict]:
    """Живые пиры ноды + клиенты на паузе. `has_config=true` — конфиг сохранён в
    панели и его можно забрать через `/clients/config`."""
    server = await _get_or_404(server_id, session)
    try:
        async with _connect(server) as conn:
            state = await awg.read_state(conn, server.host)
    except Exception as exc:  # noqa: BLE001
        raise _ssh_error(exc) from exc
    return await build_client_list(session, server_id, state)


@router.post(
    "/servers/{server_id}/clients",
    response_model=CreateClientResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Выдать клиента (создать конфиг)",
)
async def issue_client(
    server_id: int,
    body: CreateClientRequest,
    client: ApiClient,
    session: SessionDep,
) -> CreateClientResponse:
    """Создаёт пира на ноде и возвращает конфиг: `config` — текст .conf,
    `config_amnezia` — ссылка `vpn://` для приложения AmneziaVPN. Конфиг
    сохраняется в панели, поэтому его можно забрать повторно."""
    server = await _get_or_404(server_id, session)
    dns = body.dns or get_settings().awg_client_dns
    try:
        async with _connect(server) as conn:
            state = await awg.read_state(conn, server.host)
            created, config = await awg.create_client(conn, state, body.name, dns)
    except Exception as exc:  # noqa: BLE001
        raise _ssh_error(exc) from exc
    await _store_config(session, server_id, created.public_key, created.name, config)
    if body.note:
        await _set_note(session, server_id, created.public_key, body.note)
    if body.expires_at:
        await limits.set_limit(
            session, server_id, "awg", created.public_key, created.name, body.expires_at
        )
    await audit.record(session, _actor(client), "awg_issue", server.name, body.name)
    return CreateClientResponse(
        client=created.__dict__
        | {"has_config": True, "note": body.note, "expires_at": body.expires_at},
        config=config,
        config_amnezia=_amnezia_link(config, server),
    )


@router.get(
    "/servers/{server_id}/clients/config",
    response_model=ConfigTextResponse,
    summary="Забрать выданный конфиг",
)
async def get_config(
    server_id: int,
    _: ApiClient,
    session: SessionDep,
    public_key: str = _PK,
) -> ConfigTextResponse:
    """404, если конфиг в панели не сохранён (клиент заведён мимо неё) — тогда
    его текст восстановить нельзя, нужен перевыпуск."""
    server = await _get_or_404(server_id, session)
    row = await session.scalar(
        select(AwgConfig).where(
            AwgConfig.server_id == server_id, AwgConfig.public_key == public_key
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


@router.delete(
    "/servers/{server_id}/clients",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Отозвать клиента",
)
async def revoke_client(
    server_id: int,
    client: ApiClient,
    session: SessionDep,
    public_key: str = _PK,
) -> None:
    """Снимает пира с ноды и чистит его данные в панели. Идемпотентно: повторный
    вызов на уже отозванном клиенте тоже вернёт 204."""
    server = await _get_or_404(server_id, session)
    # клиент на паузе уже снят с ноды — SSH не нужен, чистим только БД
    is_paused = public_key in await pausestore.list_paused(session, server_id, "awg")
    if not is_paused:
        try:
            async with _connect(server) as conn:
                state = await awg.read_state(conn, server.host)
                await awg.revoke_client(
                    conn, state.container, state.interface, public_key
                )
        except Exception as exc:  # noqa: BLE001
            raise _ssh_error(exc) from exc
    await audit.record(session, _actor(client), "awg_revoke", server.name, public_key)
    await pausestore.drop(session, server_id, "awg", public_key)
    await session.execute(
        delete(AwgConfig).where(
            AwgConfig.server_id == server_id, AwgConfig.public_key == public_key
        )
    )
    await limits.drop_limit(session, server_id, "awg", public_key)
    await session.commit()


@router.post(
    "/servers/{server_id}/clients/pause",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Приостановить клиента",
)
async def pause_client(
    server_id: int,
    client: ApiClient,
    session: SessionDep,
    public_key: str = _PK,
) -> None:
    """Снимает пира с ноды, запомнив его IP: подключиться он не сможет, но
    возобновляется тем же ключом без перевыпуска конфига."""
    server = await _get_or_404(server_id, session)
    try:
        async with _connect(server) as conn:
            state = await awg.read_state(conn, server.host)
            target = next(
                (c for c in state.clients if c.public_key == public_key), None
            )
            if target is None:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "Клиент не найден")
            name = target.name
            data = await awg.pause_client(conn, state, public_key)
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise _ssh_error(exc) from exc
    await pausestore.add(session, server_id, "awg", public_key, name, data)
    await audit.record(
        session, _actor(client), "awg_pause", server.name, name or public_key
    )


@router.post(
    "/servers/{server_id}/clients/resume",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Возобновить клиента",
)
async def resume_client(
    server_id: int,
    client: ApiClient,
    session: SessionDep,
    public_key: str = _PK,
) -> None:
    """Возвращает пира на ноду с прежними ключом и IP — выданный ранее конфиг
    продолжает работать."""
    server = await _get_or_404(server_id, session)
    paused = await pausestore.list_paused(session, server_id, "awg")
    rec = paused.get(public_key)
    if rec is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Клиент не на паузе")
    try:
        async with _connect(server) as conn:
            state = await awg.read_state(conn, server.host)
            await awg.resume_client(
                conn, state, public_key, rec["name"], rec["data"].get("ip", "")
            )
    except Exception as exc:  # noqa: BLE001
        raise _ssh_error(exc) from exc
    await pausestore.drop(session, server_id, "awg", public_key)
    await session.commit()
    await audit.record(session, _actor(client), "awg_resume", server.name, rec["name"])
