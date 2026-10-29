from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import delete as sa_delete
from sqlalchemy import func, select

from app import audit, cascadejob, egresscheck, geo, limits, nodelock, server_ops, sshops, torrent
from app.config import get_settings
from app.db import Base
from app.deps import CurrentUser, SessionDep
from app.models import Cascade, Server, TorrentHit
from app.schemas import (
    BootstrapRequest,
    DeleteServerResult,
    EgressCheckOut,
    ReorderRequest,
    ServerCreate,
    ServerOut,
    ServerUpdate,
    SetLimitRequest,
    SetupScriptOut,
    TorrentClientOut,
    TorrentOut,
)
from app.sshkeys import ensure_panel_key, key_paths

router = APIRouter(prefix="/servers", tags=["servers"])


def _server_scoped_models() -> list:
    """Все модели с колонкой server_id — «панельные хвосты» сервера, которые надо
    удалить вместе с ним. Автоматически подхватывает новые таблицы, чтобы при
    добавлении модели секреты/кэши не оставались сиротами (ранее так забыли
    OvpnConfig с приватным ключом клиента)."""
    models = []
    for mapper in Base.registry.mappers:
        model = mapper.class_
        if model is Server:
            continue
        if "server_id" in model.__table__.columns:
            models.append(model)
    return models


async def _get_or_404(server_id: int, session: SessionDep) -> Server:
    server = await session.get(Server, server_id)
    if server is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Сервер не найден")
    return server


@router.get("", response_model=list[ServerOut])
async def list_servers(_: CurrentUser, session: SessionDep) -> list[Server]:
    result = await session.scalars(
        select(Server).order_by(Server.position, Server.id)
    )
    return list(result)


@router.post("", response_model=ServerOut, status_code=status.HTTP_201_CREATED)
async def create_server(
    body: ServerCreate, user: CurrentUser, session: SessionDep
) -> Server:
    # новый сервер — в конец списка
    max_pos = await session.scalar(select(func.max(Server.position)))
    server = Server(**body.model_dump(), position=(max_pos or 0) + 1)
    session.add(server)
    await session.commit()
    await session.refresh(server)
    await audit.record(session, user.username, "server_create", server.name, server.host)
    return server


@router.post("/order", status_code=status.HTTP_204_NO_CONTENT)
async def reorder_servers(
    body: ReorderRequest, _: CurrentUser, session: SessionDep
) -> None:
    """Сохраняет ручной порядок карточек: position = индекс в присланном списке,
    заодно фиксирует группу каждого сервера (drag-and-drop между группами).
    Порядок групп при выводе выводится из позиций (по минимальной в группе)."""
    servers = {s.id: s for s in await session.scalars(select(Server))}
    for i, item in enumerate(body.order):
        s = servers.get(item.id)
        if s is not None:
            s.position = i
            s.group_name = item.group_name
    await session.commit()


@router.get("/{server_id}", response_model=ServerOut)
async def get_server(server_id: int, _: CurrentUser, session: SessionDep) -> Server:
    return await _get_or_404(server_id, session)


@router.patch("/{server_id}", response_model=ServerOut)
async def update_server(
    server_id: int, body: ServerUpdate, user: CurrentUser, session: SessionDep
) -> Server:
    server = await _get_or_404(server_id, session)
    changes = body.model_dump(exclude_unset=True)
    # None в булевых настройках - "не менять", колонка без NULL
    for field in ("torrent_block", "torrent_autopause"):
        if field in changes and changes[field] is None:
            changes.pop(field)
    block_changed = (
        "torrent_block" in changes and changes["torrent_block"] != server.torrent_block
    )
    torrent_changed = block_changed or (
        "torrent_autopause" in changes
        and changes["torrent_autopause"] != server.torrent_autopause
    )
    for field, value in changes.items():
        setattr(server, field, value)
    await session.commit()
    await session.refresh(server)
    if torrent_changed:
        await audit.record(
            session, user.username, "server_torrent", server.name,
            f"block={server.torrent_block} autopause={server.torrent_autopause}",
        )
    if block_changed:
        # правила на ноде сразу, а не через цикл коллектора
        torrent.spawn_apply(server, get_settings())
    return server


@router.get("/{server_id}/torrent", response_model=TorrentOut)
async def server_torrent(server_id: int, _: CurrentUser, session: SessionDep) -> TorrentOut:
    """Клиенты, у которых ловили торренты, и состояние правил на ноде."""
    await _get_or_404(server_id, session)
    rows = await session.scalars(
        select(TorrentHit)
        .where(TorrentHit.server_id == server_id)
        .order_by(TorrentHit.last_seen.desc())
    )
    st = torrent.status(server_id) or {}
    return TorrentOut(
        active=st.get("ok"), checked_at=st.get("at"), error=st.get("error", ""),
        clients=[TorrentClientOut.model_validate(r) for r in rows],
    )


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

    # чистим ВСЕ панельные хвосты сервера (конфиги с секретами, заметки, сроки,
    # паузы, кэши имён, метрики) — на сам сервер не влияет
    for model in _server_scoped_models():
        await session.execute(
            sa_delete(model).where(model.server_id == server_id)
        )
    # каскад с этим сервером теряет смысл; на нодах остается как есть
    await session.execute(
        sa_delete(Cascade).where(
            (Cascade.entry_server_id == server_id) | (Cascade.exit_server_id == server_id)
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
    try:
        script = sshops.build_setup_script(
            public_key, server.ssh_user, server.ssh_port, settings.panel_ip
        )
    except ValueError as exc:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"{exc}. Исправьте имя пользователя в карточке сервера.",
        ) from exc
    return SetupScriptOut(script=script, panel_public_key=public_key)


@router.post("/{server_id}/check", response_model=ServerOut)
async def check_server(
    server_id: int, _: CurrentUser, session: SessionDep
) -> Server:
    server = await _get_or_404(server_id, session)
    await server_ops.run_check(session, server, get_settings())
    return server


@router.post("/{server_id}/egress-check", response_model=EgressCheckOut)
async def egress_check(server_id: int, _: CurrentUser, session: SessionDep) -> EgressCheckOut:
    """Откуда выходят клиенты и открываются ли сайты - путем трафика клиентов."""
    server = await _get_or_404(server_id, session)
    try:
        async with nodelock.connect("egress", server.id, cascadejob.connect(server)) as conn:
            r = await conn.run(egresscheck.build_command(server.country), check=False, timeout=90)
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"Сервер не ответил: {exc}") from exc
    res = egresscheck.parse(r.stdout if isinstance(r.stdout, str) else "")
    country = org = ""
    now = datetime.now(timezone.utc)
    if res["egress"]:
        country, org = await geo.ip_info(res["egress"])
        server_ops.apply_egress(
            server, await server_ops.describe_egress(server.host, res["egress"]), now
        )
        await session.commit()
    return EgressCheckOut(
        error=res["error"], container=res["container"], egress=res["egress"],
        egress_country=country, egress_org=org, local=res["local"],
        sites=res["sites"], checked_at=now,
    )


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
