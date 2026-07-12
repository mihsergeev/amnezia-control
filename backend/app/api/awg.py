import asyncssh
import httpx
from fastapi import APIRouter, HTTPException, Request, status
from sqlalchemy import delete, select

from app import audit, awg, deploy, deploywatch, limits, notes, pausestore, sshops
from app.config import get_settings
from app.deps import CurrentUser, SessionDep
from app.models import AwgConfig, ClientLimit, Server
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


async def _guard_foreign_awg(conn) -> None:
    """Не даём разворачивать/пересобирать AmneziaWG, если на ноде уже есть
    контейнер, собранный не панелью (иначе создастся параллельный пустой
    контейнер, а клиенты останутся на старом — как было в инциденте 10.07)."""
    foreign = await deploy.foreign_awg_container(conn)
    if foreign:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"На сервере есть контейнер AmneziaWG «{foreign}», собранный не "
            "панелью. Пересборка создала бы параллельный пустой контейнер, а "
            "текущие клиенты остались бы на старом. Операция отменена.",
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
    await notes.set_note(session, server_id, "awg", public_key, note)


async def _notes_map(session, server_id) -> dict[str, str]:
    return await notes.notes_map(session, server_id, "awg")


def _amnezia_link(config: str, server: Server) -> str:
    dns1, dns2 = awg.dns_pair(get_settings().awg_client_dns)
    return awg.build_amnezia_link(config, server.host, server.name, dns1, dns2)


@router.get("", response_model=AwgStateOut)
async def get_awg(server_id: int, _: CurrentUser, session: SessionDep) -> AwgStateOut:
    server = await _get_or_404(server_id, session)
    try:
        async with _connect(server) as conn:
            conts = await awg.detect_awg_containers(conn)
            main_cont = conts["new"] or conts["legacy"]
            state = await awg.read_state(conn, server.host, container=main_cont)
    except Exception as exc:  # noqa: BLE001
        raise _ssh_error(exc) from exc
    # legacy показываем отдельной секцией только если он ЕСТЬ РЯДОМ с новым;
    # legacy-only сервер остаётся обычной AWG-секцией (обратная совместимость)
    legacy_container = conts["legacy"] if conts["new"] else None

    stored = set(
        (
            await session.scalars(
                select(AwgConfig.public_key).where(AwgConfig.server_id == server_id)
            )
        ).all()
    )
    notes_by_pk = await _notes_map(session, server_id)
    lim = await limits.limits_map(session, server_id, "awg")
    paused = await pausestore.list_paused(session, server_id, "awg")
    clients = []
    for c in state.clients:
        item = c.__dict__ | {
            "has_config": c.public_key in stored,
            "note": notes_by_pk.get(c.public_key, ""),
            "expires_at": lim.get(c.public_key),
            "paused": False,
        }
        clients.append(item)
    # клиенты на паузе: их нет в живом конфиге — показываем из хранилища
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
        legacy_container=legacy_container,
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
    server_id: int, body: DeployRequest, user: CurrentUser, session: SessionDep,
    request: Request,
) -> dict:
    server = await _get_or_404(server_id, session)
    cfg = deploy.generate_server_config(body.port)
    script = deploy.build_script("deploy", body.port, cfg)
    try:
        async with _connect(server) as conn:
            await _guard_foreign_awg(conn)
            # пре-оп бэкап: если разворачиваем поверх существующего панельного
            # контейнера — снимем его конфиг до пересоздания
            await deploy.snapshot_all(conn, "awg")
            await deploy.launch(conn, script, tag="awg")
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise _ssh_error(exc) from exc
    deploywatch.spawn(request.app, server, "awg")
    await audit.record(
        session, user.username, "awg_deploy", server.name, f"port {body.port}"
    )
    return {"started": True}


@router.post("/update", status_code=status.HTTP_202_ACCEPTED)
async def update_awg(
    server_id: int, user: CurrentUser, session: SessionDep, request: Request
) -> dict:
    server = await _get_or_404(server_id, session)
    # config уже есть на ноде и сохраняется; cfg тут не используется
    cfg = deploy.generate_server_config(47180)
    script = deploy.build_script("update", 47180, cfg)
    try:
        async with _connect(server) as conn:
            await _guard_foreign_awg(conn)
            # пре-оп бэкап: снимок КАЖДОГО awg-контейнера ДО пересборки — для отката
            await deploy.snapshot_all(conn, "awg")
            await deploy.launch(conn, script, tag="awg")
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise _ssh_error(exc) from exc
    deploywatch.spawn(request.app, server, "awg")
    await audit.record(session, user.username, "awg_update", server.name)
    return {"started": True}


@router.post("/adopt", status_code=status.HTTP_202_ACCEPTED)
async def adopt_awg(
    server_id: int, user: CurrentUser, session: SessionDep, request: Request
) -> dict:
    """Берёт под управление панели AmneziaWG, собранный НЕ панелью.

    Перечитывает конфиг из клиентского контейнера (amnezia-awg), сохраняет его
    порт/ключи на хост-маунт и заменяет контейнер панельным (amnezia-awg2) — так,
    что клиенты остаются рабочими (те же ключи и порт), а версия/обновление/
    пересборка становятся доступны. Снимок конфига снимается ДО — для отката."""
    server = await _get_or_404(server_id, session)
    # cfg — запасной конфиг: используется только если из живого контейнера почему-то
    # ничего не считалось (тогда сервер поднимется как новый). Порт возьмётся из
    # реального awg0.conf внутри build_script.
    cfg = deploy.generate_server_config(47180)
    script = deploy.build_script("adopt", 47180, cfg)
    try:
        async with _connect(server) as conn:
            foreign_list = await deploy.foreign_awg_containers(conn)
            if not foreign_list:
                raise HTTPException(
                    status.HTTP_409_CONFLICT,
                    "Внешний контейнер AmneziaWG на сервере не найден — брать под "
                    "управление нечего.",
                )
            # СТРАХОВКА: снимок КАЖДОГО чужого awg-контейнера ДО любых изменений —
            # чтобы второй протокол (напр. legacy рядом с awg2) не пропал без снимка,
            # как в инциденте ru-be 12.07. Снимки идут в config-backups (откат).
            for cont in foreign_list:
                await deploy.snapshot_config(conn, "awg", container=cont)
            # Панель пока управляет ОДНИМ awg-контейнером на сервер. Если их два
            # (legacy + awg2) — не берём молча один, снеся второй: отказываем, но
            # оба уже в снимках. Пользователь убирает лишний в Amnezia и повторяет.
            if len(foreign_list) > 1:
                raise HTTPException(
                    status.HTTP_409_CONFLICT,
                    "На сервере несколько контейнеров AmneziaWG "
                    f"({', '.join(foreign_list)}) — вероятно, Legacy и awg2 сразу. "
                    "Панель управляет одним и не станет забирать один, останавливая "
                    "другой. Конфиги обоих сохранены в «Бэкапы конфига». Оставьте "
                    "один протокол на сервере и повторите взятие под управление.",
                )
            foreign = foreign_list[0]
            # ВАЖНО: переносим только настоящий AmneziaWG (awg0.conf). Клиентский
            # plain-WireGuard (wg0.conf) несовместим — его перенос затёр бы конфиг
            # и потерял клиентов. Такой контейнер не трогаем.
            if not await deploy.awg_adoptable(conn, foreign):
                raise HTTPException(
                    status.HTTP_409_CONFLICT,
                    f"Контейнер «{foreign}» не является AmneziaWG-совместимым "
                    "(нет awg0.conf — вероятно, это обычный WireGuard). "
                    "Автоперенос под управление невозможен без потери клиентов.",
                )
            await deploy.launch(conn, script, tag="awg")
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise _ssh_error(exc) from exc
    deploywatch.spawn(request.app, server, "awg")
    await audit.record(session, user.username, "awg_adopt", server.name, foreign)
    return {"started": True}


@router.get("/config-backups", response_model=list[SnapshotOut])
async def config_backups(
    server_id: int, _: CurrentUser, session: SessionDep
) -> list[SnapshotOut]:
    """Снимки awg-конфига на ноде (делаются перед каждой пересборкой) — для отката."""
    server = await _get_or_404(server_id, session)
    try:
        async with _connect(server) as conn:
            snaps = await deploy.list_snapshots(conn, "awg")
    except Exception as exc:  # noqa: BLE001
        raise _ssh_error(exc) from exc
    return [SnapshotOut(**s) for s in snaps]


@router.post("/config-restore", status_code=status.HTTP_202_ACCEPTED)
async def config_restore(
    server_id: int, body: SnapshotRestoreRequest, user: CurrentUser, session: SessionDep
) -> dict:
    """Откат awg-конфига к снимку (возвращает клиентов и ключи из снимка)."""
    server = await _get_or_404(server_id, session)
    try:
        async with _connect(server) as conn:
            # пре-оп бэкап: снимок текущего состояния ДО отката — сам откат тоже обратим
            await deploy.snapshot_all(conn, "awg")
            ok = await deploy.restore_snapshot(conn, "awg", body.id)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        raise _ssh_error(exc) from exc
    if not ok:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, "Снимок не найден или повреждён"
        )
    await audit.record(
        session, user.username, "awg_config_restore", server.name, body.id
    )
    return {"restored": True}


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
            foreign = await deploy.foreign_awg_container(conn)
            adoptable = bool(foreign) and await deploy.awg_adoptable(conn, foreign)
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
        foreign_container=foreign,
        adoptable=adoptable,
    )


@router.post("/pause", status_code=status.HTTP_204_NO_CONTENT)
async def pause_client(
    server_id: int, body: PublicKeyRequest, user: CurrentUser, session: SessionDep
) -> None:
    """Пауза: снимает пира с сервера (не сможет подключиться), но запоминает IP,
    чтобы возобновить того же клиента без пересоздания."""
    server = await _get_or_404(server_id, session)
    try:
        async with _connect(server) as conn:
            state = await awg.read_state(conn, server.host)
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
    await pausestore.add(session, server_id, "awg", body.public_key, name, data)
    await audit.record(
        session, user.username, "awg_pause", server.name, name or body.public_key
    )


@router.post("/resume", status_code=status.HTTP_204_NO_CONTENT)
async def resume_client(
    server_id: int, body: PublicKeyRequest, user: CurrentUser, session: SessionDep
) -> None:
    """Возобновление: возвращает пира на сервер с прежними ключом/IP."""
    server = await _get_or_404(server_id, session)
    paused = await pausestore.list_paused(session, server_id, "awg")
    rec = paused.get(body.public_key)
    if rec is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Клиент не на паузе")
    try:
        async with _connect(server) as conn:
            state = await awg.read_state(conn, server.host)
            await awg.resume_client(
                conn, state, body.public_key, rec["name"], rec["data"].get("ip", "")
            )
    except Exception as exc:  # noqa: BLE001
        raise _ssh_error(exc) from exc
    await pausestore.drop(session, server_id, "awg", body.public_key)
    await session.commit()
    await audit.record(
        session, user.username, "awg_resume", server.name, rec["name"]
    )


@router.post("/revoke", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_client(
    server_id: int,
    body: RevokeClientRequest,
    user: CurrentUser,
    session: SessionDep,
) -> None:
    server = await _get_or_404(server_id, session)
    # клиент на паузе уже снят с сервера — SSH-удаление не нужно, только чистим БД
    is_paused = body.public_key in await pausestore.list_paused(session, server_id, "awg")
    if not is_paused:
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
    await pausestore.drop(session, server_id, "awg", body.public_key)
    await session.execute(
        delete(AwgConfig).where(
            AwgConfig.server_id == server_id,
            AwgConfig.public_key == body.public_key,
        )
    )
    await notes.clear_note(session, server_id, "awg", body.public_key)
    await session.execute(
        delete(ClientLimit).where(
            ClientLimit.server_id == server_id,
            ClientLimit.protocol == "awg",
            ClientLimit.client_id == body.public_key,
        )
    )
    await session.commit()
