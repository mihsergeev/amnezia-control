import json
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request, Response, status
from sqlalchemy import delete as sa_delete
from sqlalchemy import func, select, update as sa_update

from app import audit, bulk_issue_state, cascade_alias, cascade_http, cascadejob, client_endpoint, egresscheck, geo, limits, native_snapshots, nodelock, server_ops, ssh_access, ssh_policy, sshops, torrent
from app.config import get_settings
from app.db import Base
from app.deps import CurrentUser, SessionDep
from app.models import Cascade, NodeMetric, Server, ServerStatus, SshAccessChange, TorrentHit
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
    SshAccessFields,
    SshAccessApply,
    TorrentClientOut,
    TorrentOut,
)
from app.sshkeys import ensure_panel_key, jump_key_path, key_paths

router = APIRouter(prefix="/servers", tags=["servers"])


@router.post("/{server_id}/site-check", response_model=cascade_http.SiteCheckOut)
async def check_server_sites(server_id: int, body: cascade_http.SiteCheck, _: CurrentUser, session: SessionDep):
    server = await _get_or_404(server_id, session)
    return await cascade_http.diagnose(session, server, body, get_settings())


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
    server.ssh_access_pending = bool(await session.scalar(select(SshAccessChange.id).where(SshAccessChange.server_id == server_id, SshAccessChange.phase.in_(ssh_access.ACTIVE)).limit(1)))
    return server


@router.get("", response_model=list[ServerOut])
async def list_servers(_: CurrentUser, session: SessionDep) -> list[Server]:
    result = await session.scalars(
        select(Server).order_by(Server.position, Server.id)
    )
    servers = list(result)
    pending = set(await session.scalars(select(SshAccessChange.server_id).where(SshAccessChange.phase.in_(ssh_access.ACTIVE))))
    for server in servers:
        server.ssh_access_pending = server.id in pending
    return servers


def _same_ssh_policy(server: Server, requested: ServerCreate) -> bool:
    if any(getattr(server, field) != getattr(requested, field)
           for field in ssh_access.ACCESS_FIELDS if field != "ssh_source_ips"):
        return False
    if requested.ssh_source_mode != "custom":
        return True
    if not isinstance(server.ssh_source_ips, list):
        return False
    try:
        saved_sources = ssh_policy.normalize_sources(server.ssh_source_ips)
    except ValueError:
        return False
    return set(saved_sources) == set(requested.ssh_source_ips)


@router.post("", response_model=ServerOut, status_code=status.HTTP_201_CREATED, responses={200: {"model": ServerOut}})
@bulk_issue_state.guard()
@ssh_access.serialized
async def create_server(
    body: ServerCreate, response: Response, user: CurrentUser, session: SessionDep,
    reuse_ssh_endpoint: bool = False,
    name_from_hostname: bool = False,
) -> Server:
    await client_endpoint.require_resolvable(body.client_endpoint)
    async with nodelock.hold("server-registration", 0):
        if reuse_ssh_endpoint:
            matches = list(await session.scalars(select(Server).where(
                func.lower(Server.host) == body.host.lower(),
                Server.ssh_port == body.ssh_port,
                Server.ssh_user == body.ssh_user,
            ).limit(2)))
            if len(matches) > 1:
                raise HTTPException(status.HTTP_409_CONFLICT, "В панели несколько записей с этим адресом SSH. Выберите сервер в панели.")
            if matches:
                existing = matches[0]
                if not _same_ssh_policy(existing, body):
                    raise HTTPException(
                        status.HTTP_409_CONFLICT,
                        "Сервер с этим адресом уже сохранен с другими настройками SSH. Измените доступ в карточке сервера или выберите существующую запись.",
                    )
                response.status_code = status.HTTP_200_OK
                return existing
        # новый сервер — в конец списка
        max_pos = await session.scalar(select(func.max(Server.position)))
        server = Server(**body.model_dump(), position=(max_pos or 0) + 1)
        checked = await ssh_access.candidate(session, server, {})
        server.ssh_jump_server = checked.ssh_jump_server
        try:
            ssh_policy.sources(checked, get_settings().panel_ip)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        server.country = body.country_override
        if reuse_ssh_endpoint and name_from_hostname:
            server.last_check_info = json.dumps({server_ops.ONBOARDING_NAME_PENDING: True})
        session.add(server)
        await session.flush()
        jump_key_path(key_paths(get_settings().data_dir)[0], server.id).unlink(missing_ok=True)
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
@bulk_issue_state.guard()
@ssh_access.serialized
@nodelock.operation("awg")
async def update_server(
    server_id: int, body: ServerUpdate, user: CurrentUser, session: SessionDep, request: Request
) -> Server:
    server = await _get_or_404(server_id, session)
    changes = body.model_dump(exclude_unset=True)
    await ssh_access.require_idle(session, server.id)
    # A normal metadata save never edits live authorization or rewrites a route.
    if any(field in changes and changes[field] != getattr(server, field) for field in ssh_access.ACCESS_FIELDS):
        raise HTTPException(409, "Изменение доступа SSH требует предпросмотра и применения с проверкой соединения")
    ssh_endpoint_changed = any(field in changes and changes[field] != getattr(server, field) for field in ("host", "ssh_port", "ssh_user"))
    # SSH repair and metadata edits must remain available while the old
    # endpoint is unreachable. Only an actual policy mutation needs recovery;
    # the UI sends unchanged policy fields along with its full form.
    if any(changes.get(field) is not None and changes[field] != getattr(server, field)
           for field in ("torrent_block", "torrent_autopause")):
        from app.api.awg_settings import recover
        await recover(server, session)
    if "client_endpoint" in changes and changes["client_endpoint"] != server.client_endpoint:
        await client_endpoint.require_resolvable(changes["client_endpoint"])
    host_changed = "host" in changes and changes["host"] != server.host
    manual_exit_name = changes.pop("manual_exit_name", None)
    if manual_exit_name is not None:
        # Bind to the current SSH target, not an endpoint cached for an old host.
        if host_changed:
            raise HTTPException(status.HTTP_409_CONFLICT, "После смены адреса сначала проверьте сервер")
        try:
            await cascade_alias.set_name(session, server, manual_exit_name)
        except ValueError as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    # None в булевых настройках - "не менять", колонка без NULL
    for field in ("torrent_block", "torrent_autopause", "alerts_enabled"):
        if field in changes and changes[field] is None:
            changes.pop(field)
    block_changed = (
        "torrent_block" in changes and changes["torrent_block"] != server.torrent_block
    )
    torrent_changed = block_changed or (
        "torrent_autopause" in changes
        and changes["torrent_autopause"] != server.torrent_autopause
    )
    alerts_changed = (
        "alerts_enabled" in changes
        and changes["alerts_enabled"] != server.alerts_enabled
    )
    country_override_changed = (
        "country_override" in changes and changes["country_override"] != server.country_override
    )
    for field, value in changes.items():
        setattr(server, field, value)
    if ssh_endpoint_changed:
        info = cascade_alias.check_info(server)
        info["ssh_route_pending"] = True
        info["error"] = "Адрес SSH изменен. Подготовьте промежуточный доступ при необходимости и проверьте подключение"
        server.last_check_info = json.dumps(info, ensure_ascii=False)
        server.last_check_ok = None
    if country_override_changed:
        # Clearing the override also clears its cached value. A subsequent
        # successful observation discovers the automatic country again.
        server.country = server.country_override
    elif host_changed and not server.country_override:
        server.country = ""
    if any(field in changes for field in ("name", "host", "ssh_port", "ssh_user")):
        info = cascade_alias.check_info(server)
        if info.pop(server_ops.ONBOARDING_NAME_PENDING, None) is not None:
            server.last_check_info = json.dumps(info, ensure_ascii=False)
    if host_changed:
        await cascade_alias.remove(session, server_id)
        info = cascade_alias.check_info(server)
        info.pop("manual_cascade", None)
        info.pop("cascade_link", None)
        server.last_check_info = json.dumps(info, ensure_ascii=False)
    if alerts_changed:
        cascades = await session.scalars(
            select(Cascade).where(
                (Cascade.entry_server_id == server_id)
                | (Cascade.exit_server_id == server_id)
            )
        )
        for cascade in cascades:
            result = json.loads(cascade.result or "{}")
            result.pop("health", None)
            cascade.result = json.dumps(result)
        # После включения наблюдаем с чистого состояния: иначе мог прийти
        # ложный "снова онлайн" по аварии, о которой раньше не уведомляли.
        status_row = await session.get(ServerStatus, server_id)
        if status_row is not None:
            status_row.online = True
            status_row.changed_at = datetime.now(timezone.utc)
            status_row.down_since = None
            status_row.availability_alerts = None
            status_row.drop_alerted = False
            status_row.drop_alerted_at = None
        metric = await session.get(NodeMetric, server_id)
        if metric is not None:
            metric.disk_alerted = False
        await session.execute(
            sa_update(TorrentHit)
            .where(TorrentHit.server_id == server_id)
            .values(alerted_at=None)
        )
    await session.commit()
    await session.refresh(server)
    if manual_exit_name is not None:
        await audit.record(session, user.username, "cascade_peer_name", server.name, manual_exit_name.strip())
    if torrent_changed:
        await audit.record(
            session, user.username, "server_torrent", server.name,
            f"block={server.torrent_block} autopause={server.torrent_autopause}",
        )
    if alerts_changed:
        await audit.record(
            session, user.username, "server_alerts", server.name,
            "enabled" if server.alerts_enabled else "disabled",
        )
    if block_changed:
        # правила на ноде сразу, а не через цикл коллектора
        torrent.spawn_apply(server, get_settings(), request.app.state.session_factory)
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
@bulk_issue_state.guard()
@ssh_access.serialized
async def delete_server(
    server_id: int,
    user: CurrentUser,
    session: SessionDep,
    remove_key: bool = False,
) -> DeleteServerResult:
    # Wait for bulk operations to commit before deleting their server-scoped records.
    async with (
        nodelock.hold("awg", server_id),
        nodelock.hold("wireguard", server_id),
        nodelock.hold("xray", server_id),
        nodelock.hold("openvpn", server_id),
        nodelock.hold("openvpn-native", server_id),
    ):
        return await _delete_server(server_id, user, session, remove_key)


async def _delete_server(
    server_id: int, user: CurrentUser, session: SessionDep, remove_key: bool
) -> DeleteServerResult:
    server = await _get_or_404(server_id, session)
    await ssh_access.require_idle(session, server.id, deleting=True)
    if await session.scalar(select(Server.id).where(Server.ssh_jump_server_id == server_id).limit(1)):
        raise HTTPException(409, "Сервер используется как промежуточная SSH-нода")
    from app.api.awg_settings import recover
    await recover(server, session)
    result = DeleteServerResult()
    server_name = server.name

    if remove_key:
        settings = get_settings()
        public_key = ensure_panel_key(settings.data_dir)
        key_path, _pub = key_paths(settings.data_dir)
        try:
            async with sshops.connect(
                server.host, server.ssh_port, server.ssh_user, key_path,
                settings.ssh_connect_timeout, **sshops.route_options(server)
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

    retired_warning = await ssh_access.retire_jump(server, get_settings())
    if retired_warning:
        result.message = (result.message + " " + retired_warning).strip()

    # чистим ВСЕ панельные хвосты сервера (конфиги с секретами, заметки, сроки,
    # паузы, кэши имён, метрики) — на сам сервер не влияет
    for model in _server_scoped_models():
        await session.execute(
            sa_delete(model).where(model.server_id == server_id)
        )
    # каскад с этим сервером теряет смысл; на нодах остается как есть
    await cascade_alias.remove(session, server_id)
    await session.execute(
        sa_delete(Cascade).where(
            (Cascade.entry_server_id == server_id) | (Cascade.exit_server_id == server_id)
        )
    )
    await native_snapshots.delete_server(session, server_id)
    await session.delete(server)
    await session.commit()
    # SQLite IDs can be reused: a new node must never inherit a deleted node's
    # forwarding identity. Retirement failures are reported before discarding it.
    jump_key_path(key_paths(get_settings().data_dir)[0], server_id).unlink(missing_ok=True)
    await audit.record(
        session, user.username, "server_delete", server_name,
        ("ключ снят. " if remove_key else "") + retired_warning,
    )
    return result


@router.get("/{server_id}/setup-script", response_model=SetupScriptOut)
async def setup_script(
    server_id: int, _: CurrentUser, session: SessionDep
) -> SetupScriptOut:
    server = await _get_or_404(server_id, session)
    settings = get_settings()
    await ssh_access.require_idle(session, server.id)
    public_key = ensure_panel_key(settings.data_dir)
    try:
        script = sshops.build_setup_script(
            public_key, server.ssh_user, server.ssh_port, settings.panel_ip,
            source_ips=ssh_policy.sources(server, settings.panel_ip), firewall_mode=server.ssh_firewall_mode,
        )
    except ValueError as exc:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"{exc}. Проверьте настройки SSH в карточке сервера.",
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
@bulk_issue_state.guard()
@ssh_access.serialized
async def bootstrap_server(
    server_id: int, body: BootstrapRequest, _: CurrentUser, session: SessionDep
) -> Server:
    server = await _get_or_404(server_id, session)
    await ssh_access.require_idle(session, server.id)
    ok, error = await server_ops.bootstrap_and_check(
        session, server, body.password, get_settings(), body.become_password
    )
    if not ok:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, error)
    return server


@router.post("/{server_id}/ssh-access/preview")
async def preview_ssh_access(server_id: int, body: SshAccessFields, _: CurrentUser, session: SessionDep):
    server = await _get_or_404(server_id, session)
    return await ssh_access.preview(session, server, body.model_dump(), get_settings())


@router.post("/{server_id}/ssh-access/apply", response_model=ServerOut)
async def apply_ssh_access(server_id: int, body: SshAccessApply, _: CurrentUser, session: SessionDep):
    return await ssh_access.apply(session, await _get_or_404(server_id, session), body.token, get_settings())


@router.post("/{server_id}/ssh-access/prepare", response_model=ServerOut)
@bulk_issue_state.guard()
@ssh_access.serialized
async def prepare_ssh_access(server_id: int, _: CurrentUser, session: SessionDep):
    server = await _get_or_404(server_id, session)
    await ssh_access.require_idle(session, server.id)
    await ssh_access.prepare_jump(session, server, get_settings())
    try:
        await ssh_access.verify(server, get_settings())
    except Exception as exc:
        raise HTTPException(409, f"Промежуточный доступ подготовлен, но вход на целевой сервер не подтвержден: {exc}") from exc
    await server_ops.run_check(session, server, get_settings())
    return server


@router.post("/{server_id}/ssh-access/recover", response_model=ServerOut)
async def recover_ssh_access(server_id: int, _: CurrentUser, session: SessionDep):
    server = await _get_or_404(server_id, session)
    await ssh_access.recover(session, get_settings(), server.id)
    await ssh_access.require_idle(session, server.id)
    await session.refresh(server)
    server.ssh_access_pending = False
    return server
