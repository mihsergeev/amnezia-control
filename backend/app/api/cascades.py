"""Каскады из двух серверов: проверка канала, установка, проверка и разборка
(см. app/cascade.py и app/cascadejob.py)."""

import asyncio
import hashlib
import inspect
import json
import secrets
from contextlib import asynccontextmanager, nullcontext
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Annotated
from uuid import UUID

import asyncssh
from fastapi import APIRouter, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select

from app import (
    audit, cascade, cascade_awg, cascade_exit, cascade_http, cascade_lock, cascade_observations,
    cascade_probe, cascade_progress, cascade_recovery, cascadejob, deploy, geo, nodelock, server_ops,
)
from app.cascade_routes import (
    Route, RoutePreview, RoutePreviewOut, RouteUpdate, preview_destinations, update_script,
)
from app.conflict import conflict
from app.config import get_settings
from app import debug_context
from app.deps import CurrentUser, SessionDep
from app.models import Cascade, Server
from app.schemas import (
    CascadeCheckOut,
    CascadeCreate,
    CascadeInstall,
    CascadeOut,
    CascadePair,
    CascadeProbeOut,
    CascadeTransportProbe,
    CascadeTransportProbeOut,
    CascadeTransportProgressOut,
)

router = APIRouter(prefix="/cascades", tags=["cascades"])


@router.post("/routes/preview", response_model=RoutePreviewOut)
async def preview_routes(body: RoutePreview, _: CurrentUser) -> RoutePreviewOut:
    return preview_destinations(body.destinations)


@router.post("/{cascade_id}/routes/http-check", response_model=cascade_http.SiteCheckOut)
async def check_route_sites(cascade_id: int, body: cascade_http.CascadeSiteCheck, _: CurrentUser, session: SessionDep):
    current = await _get_or_404(cascade_id, session)
    if current.status != "ready" or cascadejob.running(current.id):
        raise HTTPException(409, "Проверка доступна после установки каскада")
    server_id = current.entry_server_id if body.via == "entry" else current.exit_server_id
    server = await session.get(Server, server_id)
    if server is None:
        raise HTTPException(404, "Сервер не найден")
    return await cascade_http.diagnose(session, server, body, get_settings(), cascade=current, via=body.via)


# последняя проверка канала по паре (вход, выход): ее показывает карточка
_last_probe: dict[tuple[int, int], dict] = {}


def _check_local_install(cascade_id: int) -> None:
    if cascadejob.running(cascade_id):
        raise conflict(
            "cascade_install_running", "Панель еще устанавливает каскад. Дождитесь завершения.",
            cascade_id=cascade_id,
        )


def _pair_operation(handler):
    signature = inspect.signature(handler)

    @wraps(handler)
    async def wrapped(*args, **kwargs):
        values = signature.bind(*args, **kwargs).arguments
        session = values["session"]
        cid = values["cascade_id"]
        row = await _get_or_404(cid, session)
        _check_local_install(cid)
        pair = row.entry_server_id, row.exit_server_id
        identity = row.created_at, json.loads(row.params or "{}").get("runtime_owner")
        first, second = sorted(pair)
        async with nodelock.hold("cascade", first), nodelock.hold("cascade", second):
            current = await session.get(Cascade, cid, populate_existing=True)
            if current is None or (current.entry_server_id, current.exit_server_id) != pair or (
                current.created_at, json.loads(current.params or "{}").get("runtime_owner")
            ) != identity:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "Каскад не найден")
            _check_local_install(cid)
            return await handler(*args, **kwargs)
    return wrapped


def _ssh_error(exc: Exception) -> HTTPException:
    if isinstance(exc, HTTPException):
        return exc
    if isinstance(exc, (asyncssh.Error, OSError, TimeoutError)):
        return HTTPException(
            status.HTTP_502_BAD_GATEWAY, f"Ошибка SSH: {exc or type(exc).__name__}"
        )
    return HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, str(exc))


def _locked(server: Server):
    return nodelock.connect("cascade", server.id, cascadejob.connect(server))


@asynccontextmanager
async def _locked_pair(entry: Server, exit_: Server, on_connect=None):
    """Обе ноды под блокировкой, всегда в порядке id: встречные пары A-B и B-A,
    взятые как вход-выход, ждали бы друг друга. Отдает (вход, выход)."""
    first, second = sorted((entry, exit_), key=lambda s: s.id)
    def report(server, stage, status):
        if on_connect:
            on_connect("entry" if server.id == entry.id else "exit", stage, status)

    report(first, "connecting", "running")
    async with _locked(first) as c1:
        report(first, "queued", "pending")
        report(second, "connecting", "running")
        async with _locked(second) as c2:
            report(second, "queued", "pending")
            conns = {first.id: c1, second.id: c2}
            yield conns[entry.id], conns[exit_.id]


async def _ipv4(host: str) -> str:
    for addr in sorted(await server_ops._host_addrs(host)):
        if ":" not in addr:
            return addr
    return ""


def _out(c: Cascade, entry: Server | None = None) -> CascadeOut:
    params = json.loads(c.params or "{}")
    result = json.loads(c.result or "{}")
    prog = cascadejob.progress(c.id)
    # на какой стороне упала установка - и после рестарта панели, когда хода в памяти нет
    phase = prog.get("phase", "") or (result.get("failed_phase", "") if c.status == "error" else "")
    encryption = cascade.encryption_result({
        "encryption": result.get("encryption", "unknown"),
        "encrypted": {True: "yes", False: "no"}.get(result.get("encrypted"), ""),
    })
    if c.transport == "gre" and entry is not None and entry.last_check_at:
        checked = entry.last_check_at.replace(tzinfo=timezone.utc) if entry.last_check_at.tzinfo is None else entry.last_check_at
        age = datetime.now(timezone.utc) - checked
        if timedelta(0) <= age <= timedelta(minutes=5):
            try:
                info = json.loads(entry.last_check_info or "{}")
                link = info.get("cascade_link", {}) if isinstance(info, dict) else {}
            except (ValueError, TypeError):
                link = {}
            if isinstance(link, dict) and link.get("transport") == "awg" and isinstance(link.get("encrypted"), bool):
                encryption = {"encryption": "awg", "encrypted": link["encrypted"]}
    return CascadeOut(
        id=c.id,
        entry_server_id=c.entry_server_id,
        exit_server_id=c.exit_server_id,
        transport=c.transport,
        status=c.status,
        error=c.error,
        phase=phase,
        log=prog.get("log", ""),
        progress=prog.get("sides", {}),
        entry_ip=params.get("entry_ip", ""),
        entry_country=params.get("entry_country", ""),
        exit_ip=params.get("exit_ip", ""),
        routes=params.get("routes", []),
        entry_port=params.get("entry_port"),
        exit_port=params.get("exit_port"),
        **encryption,
        probe=json.loads(c.probe or "{}"),
        result=result,
        created_at=c.created_at,
    )


async def _settle(session, c: Cascade) -> None:
    """Установка «идет», а задачи нет - панель перезапустили посреди установки."""
    if c.status == "installing" and not cascadejob.running(c.id):
        c.status = "error"
        c.error = "установка прервана перезапуском панели, запустите ее еще раз"
        await session.commit()


async def _get_or_404(cascade_id: int, session) -> Cascade:
    c = await session.get(Cascade, cascade_id)
    if c is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Каскад не найден")
    return c


async def _pair(body: CascadePair, session) -> tuple[Server, Server]:
    if body.entry_id == body.exit_id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Вход и выход - один сервер")
    entry = await session.get(Server, body.entry_id)
    exit_ = await session.get(Server, body.exit_id)
    if entry is None or exit_ is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Сервер не найден")
    await _ensure_free(session, entry, exit_)
    for side, s in (("entry", entry), ("exit", exit_)):
        if s.last_check_ok is not True:
            raise conflict(
                "cascade_server_offline",
                f"«{s.name}» не на связи: проверьте сервер и повторите",
                server_id=s.id, side=side,
            )
    return entry, exit_


async def _ensure_free(session, entry: Server, exit_: Server) -> None:
    rows = list(await session.scalars(select(Cascade)))
    if any(c.entry_server_id in (entry.id, exit_.id) or c.exit_server_id == entry.id for c in rows):
        raise conflict("cascade_role_in_use", "Сервер уже входит в каскад", server_id=entry.id)
    entry_addrs = await server_ops._host_addrs(entry.host)
    exit_addrs = await server_ops._host_addrs(exit_.host)
    if entry.host == exit_.host or entry_addrs & exit_addrs:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Вход и выход указывают на один сервер")
    # Separate inventory IDs must not bypass node locks or reserve the same
    # physical exit's ports independently.
    ids = {sid for c in rows for sid in (c.entry_server_id, c.exit_server_id)}
    for node in await session.scalars(select(Server).where(Server.id.in_(ids))):
        if node.id == exit_.id:
            continue
        addresses = await server_ops._host_addrs(node.host)
        if node.host in (entry.host, exit_.host) or addresses & (entry_addrs | exit_addrs):
            raise conflict("cascade_duplicate_host", "Этот узел уже используется под другой записью сервера",
                           server_id=node.id)


async def _siblings(session, exit_id: int) -> list[Cascade]:
    return list(await session.scalars(select(Cascade).where(Cascade.exit_server_id == exit_id)))


def _reserved_ports(rows: list[Cascade], transport: str) -> set[int]:
    # Failed/installing rows keep their reservations for a safe retry.
    key = "exit_port" if transport == "awg" else "port"
    return {int(p[key]) for c in rows if c.transport == transport
            for p in [json.loads(c.params or "{}")] if p.get(key)}


def _inner_reservation(rows: list[Cascade]) -> str:
    used = {cascade_exit.network(c.id, json.loads(c.params or "{}"))[0] for c in rows}
    for n in range(1, 255):
        candidate = f"10.99.{n}.0/30"
        if candidate not in used:
            return candidate
    raise conflict("cascade_no_inner_subnet", "На выходе нет свободной внутренней подсети")


async def _addresses(entry_conn, entry: Server, exit_: Server) -> tuple[str, str]:
    exit_ip = await _ipv4(exit_.host)
    entry_ip = await cascade.entry_source_ip(entry_conn, exit_ip) if exit_ip else ""
    entry_ip = entry_ip or await _ipv4(entry.host)
    if not entry_ip or not exit_ip:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Не удалось определить IPv4 серверов")
    return entry_ip, exit_ip


@router.get("", response_model=list[CascadeOut])
async def list_cascades(_: CurrentUser, session: SessionDep) -> list[CascadeOut]:
    rows = (await session.execute(select(Cascade).order_by(Cascade.id))).scalars().all()
    for c in rows:
        await _settle(session, c)
    entries = {s.id: s for s in await session.scalars(select(Server).where(
        Server.id.in_({c.entry_server_id for c in rows})
    ))} if rows else {}
    return [_out(c, entries.get(c.entry_server_id)) for c in rows]


@router.post("/probe", response_model=CascadeProbeOut)
async def probe(body: CascadePair, _: CurrentUser, session: SessionDep) -> CascadeProbeOut:
    entry, exit_ = await _pair(body, session)
    try:
        async with _locked_pair(entry, exit_) as (ec, xc):
            await _ensure_free(session, entry, exit_)
            entry_ip, exit_ip = await _addresses(ec, entry, exit_)
            res = await cascade.probe(xc, ec, entry_ip, exit_ip)
    except Exception as exc:  # noqa: BLE001
        raise _ssh_error(exc) from exc
    country, org = await geo.ip_info(exit_ip)
    res["checked_at"] = datetime.now(timezone.utc).isoformat()
    _last_probe[(entry.id, exit_.id)] = res
    return CascadeProbeOut(
        entry_ip=entry_ip, exit_ip=exit_ip, exit_country=country, exit_org=org,
        tcp=res["tcp"], gre=res["gre"], recommend=res["recommend"],
        entry_nat=res.get("entry_nat", False), exit_nat=res.get("exit_nat", False),
    )


@router.get("/probe-transport/{run_id}/progress", response_model=CascadeTransportProgressOut)
async def probe_transport_progress(run_id: UUID, user: CurrentUser) -> dict:
    return cascade_progress.snapshot(str(run_id), user.id)


@router.post("/probe-transport", response_model=CascadeTransportProbeOut)
async def probe_transport(
    body: CascadeTransportProbe, request: Request, user: CurrentUser, session: SessionDep,
) -> CascadeTransportProbeOut:
    entry, exit_ = await _pair(body, session)
    first, second = sorted((entry.id, exit_.id))
    run_id = str(body.run_id) if body.run_id else None
    if run_id:
        cascade_progress.start(run_id, user.id, entry.id, exit_.id, body.transport)

    def report(side, stage, status="running"):
        if run_id:
            cascade_progress.event(run_id, side, stage, status)

    try:
        # A repeated click must not queue another expensive remote measurement.
        async with nodelock.hold("cascade", first, wait=0.1), nodelock.hold("cascade", second, wait=0.1):
            async with _locked_pair(entry, exit_, report) as (ec, xc):
                await _ensure_free(session, entry, exit_)
                entry_source, exit_ip = await _addresses(ec, entry, exit_)
                entry_ip = await _ipv4(entry.host) or entry_source
                if cascade._is_public(entry_ip) and not cascade._is_public(entry_source):
                    entry_source = entry_ip
                entry_addresses = await server_ops._host_addrs(entry.host)
                exit_addresses = await server_ops._host_addrs(exit_.host)
                if entry_ip == exit_ip or entry_addresses & exit_addresses:
                    raise HTTPException(status.HTTP_400_BAD_REQUEST,
                                        "Вход и выход указывают на один сервер")
                nat = {
                    "entry_nat": cascade.behind_nat(await cascade._route_src(ec, exit_ip), entry_ip),
                    "exit_nat": cascade.behind_nat(await cascade._route_src(xc, entry_ip), exit_ip),
                }
                report("entry", "queued", "pending")
                report("exit", "queued", "pending")
                task = asyncio.create_task(cascade_probe.run(
                    xc, ec, entry_ip, exit_ip, body.transport, body.entry_port, body.exit_port,
                    entry_source_ip=entry_source, prepare_missing_image=body.prepare_missing_image,
                    reserved_exit_ports=_reserved_ports(await _siblings(session, exit_.id), body.transport),
                    on_progress=report if run_id else None,
                ))
                try:
                    while not task.done():
                        await asyncio.wait({task}, timeout=0.25)
                        if not task.done() and await request.is_disconnected():
                            task.cancel()
                            try:
                                await task
                            except asyncio.CancelledError:
                                pass
                            raise HTTPException(499, "Проверка отменена")
                    res = await task
                    res["checked_at"] = datetime.now(timezone.utc).isoformat()
                finally:
                    if not task.done():
                        task.cancel()
                        try:
                            await task
                        except asyncio.CancelledError:
                            pass
    except Exception as exc:  # noqa: BLE001
        if run_id:
            cascade_progress.finish(run_id, "cancelled" if isinstance(exc, HTTPException) and
                                    exc.status_code == 499 else "error")
        raise _ssh_error(exc) from exc
    except asyncio.CancelledError:
        if run_id:
            cascade_progress.finish(run_id, "cancelled")
        raise
    if run_id:
        res["run_id"] = run_id
        cascade_progress.finish(run_id, "done" if res.get("ok") is True else "error")
    country, org = exit_.country or "", ""
    try:
        found_country, org = await geo.ip_info(exit_ip)
        country = found_country or country
    except Exception:  # noqa: BLE001 — enrichment cannot invalidate measurement
        pass
    res |= {"entry_ip": entry_ip, "exit_ip": exit_ip, "exit_country": country,
            "exit_org": org, **nat}
    # Explicit transport/run markers distinguish these measurements from the
    # legacy plain-TCP prerequisite. No keys/configuration enter this cache.
    cached = _last_probe.setdefault((entry.id, exit_.id), {})
    previous = cached.get(body.transport, {})
    if not isinstance(previous, dict) or str(previous.get("checked_at", "")) <= res["checked_at"]:
        cached[body.transport] = res.copy()
    if res.get("ok") is not True:
        await debug_context.arecord(operation="probe", protocol=body.transport,
                             server_id=entry.id, stage="cleanup" if res.get("cleanup_failed") else "verify",
                             code="cleanup" if res.get("cleanup_failed") else
                             "dependency_missing" if res.get("reason") == "local_image_missing" else None,
                             text=res.get("error"))
    return CascadeTransportProbeOut(**res)


async def _vless_port(conn, reserved: set[int] | None = None) -> int:
    choices = (*cascade.VLESS_PORTS, *(30000 + secrets.randbelow(20000) for _ in range(20)))
    for port in choices:
        if port not in (reserved or ()) and await deploy.port_owner(conn, port, "tcp") is None:
            return port
    raise conflict(
        "cascade_vless_ports_busy",
        "На выходе заняты все порты для VLESS ("
        + ", ".join(str(p) for p in cascade.VLESS_PORTS) + ")",
    )


async def _awg_preflight(conn, cascade_id: int | None = None) -> None:
    res = await conn.run(cascade_awg.preflight_command(cascade_id), check=False, timeout=20)
    if "CASCADE_AVAILABLE" not in (res.stdout or ""):
        raise conflict("cascade_awg_resources_busy",
                       "На сервере уже есть внешний туннель или заняты ресурсы AWG каскада",
                       cascade_id=cascade_id)


async def _awg_port(conn, requested: int | None, reserved: set[int] | None = None) -> int:
    for port in (requested,) if requested is not None else cascade_awg.PORTS:
        if port not in (reserved or ()) and await deploy.port_owner(conn, port, "udp") is None:
            return port
    raise conflict("cascade_awg_port_busy", "UDP-порт для канала AWG занят. Укажите другой порт")


async def _external_preflight(conn) -> None:
    result = await conn.run(cascade_awg.foreign_guard() + "echo CASCADE_AVAILABLE\n",
                            check=False, timeout=20)
    if "CASCADE_EXTERNAL_UNDERLAY" in (result.stdout or ""):
        raise conflict("cascade_external_underlay",
                       "Канал защищен внешним AWG helper. Сначала отключите его штатным способом")
    if "CASCADE_AVAILABLE" not in (result.stdout or ""):
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "Не удалось проверить существующий канал")


async def _operation_available(conn, cascade_id: int, owner: str, side: str) -> None:
    result = await conn.run(cascade_lock.check_command(cascade_id, owner), check=False, timeout=20)
    if "CASCADE_OPERATION_BUSY" in (result.stdout or ""):
        raise _remote_install_busy(cascade_id, side)
    if "CASCADE_OPERATION_FREE" not in (result.stdout or "") or result.exit_status != 0:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "Не удалось проверить установку на узле")


def _remote_install_busy(cascade_id: int, side: str) -> HTTPException:
    label = "входном" if side == "entry" else "выходном"
    return conflict("cascade_remote_install_running",
                    f"Установка еще выполняется на {label} сервере. Дождитесь ее завершения.",
                    cascade_id=cascade_id, side=side)


def _bound_probe(raw: dict, transport: str, params: dict) -> dict:
    """Keep new measurements only for the endpoints/ports actually installed.

    The legacy TCP prerequisite has no transport marker and remains compatible.
    Filtering this snapshot must never modify another wizard's in-memory cache.
    """
    bound = {}
    for name, result in raw.items():
        if not isinstance(result, dict) or "measurement" not in result:
            bound[name] = result
            continue
        if result.get("measurement") != name or name not in cascade.TRANSPORTS:
            continue
        if any(result.get(key) != params.get(key) for key in ("entry_ip", "exit_ip")):
            continue
        if name == transport == "awg" and any(
            result.get(key) != params.get(key) for key in ("entry_port", "exit_port")
        ):
            continue
        if name == transport == "vless" and result.get("exit_port") != params.get("port"):
            continue
        bound[name] = result.copy()
    return bound


@router.post("", response_model=CascadeOut, status_code=status.HTTP_202_ACCEPTED)
async def create(
    body: CascadeCreate, request: Request, user: CurrentUser, session: SessionDep
) -> CascadeOut:
    # Bound the number of locks even when each request uses a fresh ID.
    request_lock = nodelock.hold("cascade-create-request", body.request_id.int % 64) if body.request_id else nullcontext()
    async with request_lock:
        if body.request_id:
            data = _create_request_data(body)
            rows = await session.scalars(select(Cascade))
            for row in rows:
                previous = json.loads(row.params or "{}").get("create_request")
                if previous and previous.get("request_id") == data["request_id"]:
                    if previous != data:
                        raise conflict("cascade_create_request_changed",
                                       "Этот запрос уже использован с другими параметрами каскада")
                    await _settle(session, row)
                    return _out(row)
        return await _create_cascade(body, request, user, session)


def _create_request_data(body: CascadeCreate) -> dict:
    # Requests stored by earlier versions have no routes key.
    return body.model_dump(mode="json", exclude={"routes"} if not body.routes else None)


async def _create_cascade(body: CascadeCreate, request: Request, user: CurrentUser, session: SessionDep) -> CascadeOut:
    entry, exit_ = await _pair(body, session)
    try:
        async with _locked_pair(entry, exit_) as (ec, xc):
            # проверка в _pair шла до блокировки: двойной клик проходил ее дважды
            # и создавал два каскада. Перепроверяем и пишем строку под блокировкой
            await _ensure_free(session, entry, exit_)
            params: dict = {"runtime_layout": 2, "runtime_owner": secrets.token_hex(16)}
            await _entry_creation_available(ec, body.transport, params, entry.id)
            entry_ip, exit_ip = await _addresses(ec, entry, exit_)
            siblings = await _siblings(session, exit_.id)
            params.update(entry_ip=entry_ip, exit_ip=exit_ip, inner_net=_inner_reservation(siblings))
            if body.entry_country:
                params["entry_country"] = body.entry_country.upper()
            if body.routes:
                params["routes"] = [route.model_dump() for route in body.routes]
            if body.request_id:
                params["create_request"] = _create_request_data(body)
            if body.transport == "vless":
                params |= cascade.new_vless_params()
                params["port"] = await _vless_port(xc, _reserved_ports(siblings, "vless"))
            elif body.transport == "awg":
                # The endpoint/firewall peer is the server's reachable address,
                # not a cloud VM's private source address behind provider NAT.
                params["entry_ip"] = await _ipv4(entry.host) or entry_ip
                await _awg_preflight(ec)
                params |= cascade_awg.new_params()
                params["entry_port"] = await _awg_port(ec, body.entry_port)
                params["exit_port"] = await _awg_port(xc, body.exit_port, _reserved_ports(siblings, "awg"))
            elif body.transport == "gre":
                params["gre_key"] = secrets.randbelow(4294967295) + 1
            c = Cascade(
                entry_server_id=entry.id,
                exit_server_id=exit_.id,
                transport=body.transport,
                status="installing",
                params=json.dumps(params),
                probe=json.dumps(_bound_probe(_last_probe.get((entry.id, exit_.id), {}),
                                             body.transport, params)),
            )
            # Different inventory IDs can resolve to the same host and bypass
            # the pair lock. Recheck physical ownership while serializing writes.
            async with nodelock.hold("cascade", 0):
                await _ensure_free(session, entry, exit_)
                session.add(c)
                await session.commit()
            cascadejob.spawn(request.app, c.id)
            await session.refresh(c)
    except Exception as exc:  # noqa: BLE001
        raise _ssh_error(exc) from exc
    await audit.record(
        session, user.username, "cascade_create", entry.name,
        f"-> {exit_.name}, {body.transport.upper()}",
    )
    return _out(c)


@router.get("/{cascade_id}", response_model=CascadeOut)
async def get_cascade(cascade_id: int, _: CurrentUser, session: SessionDep) -> CascadeOut:
    c = await _get_or_404(cascade_id, session)
    await _settle(session, c)
    return _out(c, await session.get(Server, c.entry_server_id))


@router.put("/{cascade_id}/routes", response_model=CascadeOut)
@_pair_operation
async def update_routes(
    cascade_id: int, body: RouteUpdate, user: CurrentUser, session: SessionDep
) -> CascadeOut:
    c = await session.scalar(select(Cascade).where(Cascade.id == cascade_id)
                             .with_for_update().execution_options(populate_existing=True))
    if c is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Каскад не найден")
    if c.status != "ready" or cascadejob.running(c.id):
        raise conflict("cascade_routes_not_ready", "Маршруты доступны после установки каскада",
                       cascade_id=cascade_id)
    entry = await session.get(Server, c.entry_server_id)
    if entry is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Сервер не найден")
    params = json.loads(c.params or "{}")
    routes = [rule.model_dump() for rule in body.routes]
    owner = params.get("runtime_owner", "")
    script = update_script(f"{cascade.DIR}/config", cascade.GATEWAY, cascade.SOCKS_PORT, owner, routes)
    command = cascade_lock.wrap(c.id, script, owner, edit=True)
    try:
        async with _locked(entry) as conn:
            result = await conn.run(command, check=False, timeout=125)
    except (asyncssh.Error, OSError, TimeoutError) as exc:
        raise _ssh_error(exc) from exc
    if result.exit_status != 0:
        detail = {
            73: "Шлюз каскада не соответствует настройкам панели",
            74: "Не удалось запустить шлюз после отката маршрутов",
            75: "Шлюз занят или предыдущие маршруты восстановлены",
        }.get(result.exit_status, "Не удалось применить маршруты")
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, detail)
    c.params = json.dumps(params | {"routes": routes})
    await session.commit()
    await audit.record(session, user.username, "cascade_routes", entry.name, str(len(routes)))
    return _out(c, entry)


@router.post("/{cascade_id}/install", response_model=CascadeOut,
             status_code=status.HTTP_202_ACCEPTED)
@_pair_operation
async def reinstall(
    cascade_id: int, request: Request, user: CurrentUser, session: SessionDep,
    body: CascadeInstall | None = None,
) -> CascadeOut:
    c = await _get_or_404(cascade_id, session)
    _check_local_install(c.id)
    entry = await session.get(Server, c.entry_server_id)
    exit_ = await session.get(Server, c.exit_server_id)
    if entry is None or exit_ is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Сервер не найден")
    try:
        async with _locked_pair(entry, exit_) as (ec, xc):
            _check_local_install(c.id)
            params = json.loads(c.params or "{}")
            scoped = cascade_exit.scoped(params)
            if scoped:
                owner = params["runtime_owner"]
                await _operation_available(ec, c.id, owner, "entry")
                await _operation_available(xc, c.id, owner, "exit")
            if c.transport == "awg":
                await _awg_preflight(ec, c.id)
                if not scoped:
                    await _awg_preflight(xc, c.id)
            else:
                await _external_preflight(ec)
                if not scoped:
                    await _external_preflight(xc)
            if body and body.entry_country:
                c.params = json.dumps(params | {"entry_country": body.entry_country.upper()})
            c.status = "installing"
            c.error = ""
            await session.commit()
            cascadejob.spawn(request.app, c.id)
    except Exception as exc:  # noqa: BLE001
        raise _ssh_error(exc) from exc
    await audit.record(
        session, user.username, "cascade_install", entry.name if entry else str(c.id), "",
    )
    return _out(c)


@router.post("/{cascade_id}/check", response_model=CascadeCheckOut)
async def check(cascade_id: int, _: CurrentUser, session: SessionDep) -> CascadeCheckOut:
    c = await _get_or_404(cascade_id, session)
    entry = await session.get(Server, c.entry_server_id)
    if entry is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Сервер не найден")
    generation = cascade_observations.Generation.of(c)
    entry_host = entry.host
    country = json.loads(c.params or "{}").get("entry_country") or entry.country
    # All reads above are complete; don't hold a DB transaction during SSH.
    await session.commit()
    try:
        async with _locked(entry) as conn:
            out = await cascade.run_check(conn, country)
            now = datetime.now(timezone.utc)
    except Exception as exc:  # noqa: BLE001
        raise _ssh_error(exc) from exc
    kv = cascade.parse_kv(out)
    res = cascade.check_result(kv)
    confirmed = cascade.egress_confirmed(res)
    transport = generation.transport
    tunnel = kv.get("tun", "") if transport == "gre" else (
        "UP" if kv.get("awg") == "yes" else "DOWN"
    ) if transport == "awg" else ""
    gateway = kv.get("gw") == "yes"
    tproxy = kv.get("tproxy") == "active"
    rule = kv.get("rule") != "no" and (transport != "gre" or kv.get("grerule") != "no")
    if transport == "awg":
        rule = rule and kv.get("awg") == "yes"
    ok, reason = cascade.health(transport, kv, res)
    response = CascadeCheckOut(
        ok=ok, gateway=gateway, tproxy=tproxy, rule=rule, tunnel=tunnel,
        egress=res["egress"], ru=res["ru"], client=res["client"], direct=res["direct"],
        leak=cascade.leaks(res), egress_confirmed=confirmed, reason=reason, checked_at=now,
        **cascade.encryption_result(kv),
    )
    if generation.status != "ready":
        return response
    desc = await server_ops.describe_egress(entry_host, res["client"]) if res["client"] else None
    for _attempt in range(cascade_observations.WRITE_ATTEMPTS):
        fresh = await session.get(Cascade, cascade_id, populate_existing=True)
        if (fresh is None or cascade_observations.Generation.of(fresh) != generation
                or cascadejob.running(cascade_id)):
            break
        result = json.loads(fresh.result or "{}")
        if cascade_observations.newer_than(result.get("manual_check") or {}, now):
            return response
        result["manual_check"] = {"ok": ok, "reason": reason, "checked_at": now.isoformat()}
        latest_paths = cascade_observations.merge_paths(result, res, now)
        if await cascade_observations.save(session, generation, fresh.result, result):
            # Only the client network observation can update its egress address.
            if latest_paths and res["client"]:
                fresh_entry = await session.get(Server, generation.entry_server_id, populate_existing=True)
                if fresh_entry is not None and fresh_entry.host == entry_host:
                    server_ops.apply_egress(fresh_entry, desc, now)
            await session.commit()
            return response
        await session.rollback()
    raise conflict("cascade_check_changed", "Каскад изменился во время проверки, повторите проверку.",
                   cascade_id=cascade_id)


async def _dismantle(server: Server, script: str, cascade_id: int, side: str) -> str:
    """Пусто - разобрано, иначе текст ошибки."""
    try:
        async with _locked(server) as conn:
            r = await conn.run(script, check=False, timeout=120)
    except Exception as exc:  # noqa: BLE001
        error = _ssh_error(exc)
        if error.status_code == status.HTTP_409_CONFLICT:
            raise error from exc
        return f"«{server.name}»: {error.detail}"
    if "CASCADE_EXTERNAL_UNDERLAY" in (r.stdout or ""):
        raise conflict("cascade_external_underlay",
                       "Канал защищен внешним AWG helper. Сначала отключите его штатным способом",
                       cascade_id=cascade_id, server_id=server.id, side=side)
    if "CASCADE_OPERATION_BUSY" in (r.stdout or ""):
        raise _remote_install_busy(cascade_id, side)
    if r.exit_status != 0 or "CASCADE_REMOVED=yes" not in (r.stdout or ""):
        return f"«{server.name}»: сервер не подтвердил удаление каскада"
    return ""


async def _check_remove_node(server: Server, cascade_id: int, owner: str, side: str) -> str:
    try:
        async with _locked(server) as conn:
            await _operation_available(conn, cascade_id, owner, side)
    except (HTTPException, asyncssh.Error, OSError, TimeoutError) as exc:
        error = _ssh_error(exc)
        if error.status_code == status.HTTP_409_CONFLICT:
            raise
        return f"«{server.name}»: {error.detail}"
    return ""


class EntryRecoveryRequest(BaseModel):
    token: str = Field(pattern=r"^[0-9a-f]{64}$")
    cascade_id: int | None = Field(default=None, gt=0)


class EntryRecoveryOut(BaseModel):
    token: str
    transport: str
    entry_country: str = ""
    routes: list[Route] = Field(default_factory=list)
    resume: CascadeOut | None = None


def _unsafe_entry() -> HTTPException:
    return conflict("cascade_recovery_ownership", "Панель не смогла подтвердить, что шлюз на входе принадлежит ей. Вход не изменен.")


async def _entry_creation_available(conn, transport: str, options: dict, entry_id: int) -> None:
    check = await conn.run(cascade_recovery.creation_guard(transport, options), check=False, timeout=45)
    markers = (check.stdout or "").splitlines()
    if "CASCADE_EXTERNAL_UNDERLAY" in markers:
        raise conflict("cascade_external_underlay", "Канал защищен внешним AWG helper. Сначала отключите его штатным способом")
    if "CASCADE_ENTRY_RECOVERY_REQUIRED" in markers:
        code = "cascade_entry_recovery_required"
        error = conflict(code, "На входе остался шлюз прежнего каскада. Проверьте его перед новой сборкой.",
                         server_id=entry_id)
        raise HTTPException(error.status_code, {"code": code, "message": error.detail})
    if check.exit_status != 0:
        raise _unsafe_entry()


async def _entry_recovery(entry_id: int, user: CurrentUser, session: SessionDep,
                          token: str | None = None, cascade_id: int | None = None) -> EntryRecoveryOut:
    async with nodelock.hold("cascade", entry_id):
        entry = await session.get(Server, entry_id, populate_existing=True)
        if entry is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Сервер не найден")
        rows = list(await session.scalars(select(Cascade).execution_options(populate_existing=True)))
        row = next((c for c in rows if c.entry_server_id == entry_id), None)
        if cascade_id is not None and (row is None or row.id != cascade_id
                                       or row.status not in ("error", "installing")):
            raise conflict("cascade_recovery_changed", "Черновик каскада изменился. Откройте восстановление заново.")
        other_ids = {c.exit_server_id for c in rows} | {c.entry_server_id for c in rows if c is not row}
        if entry_id in other_ids:
            raise conflict("cascade_role_in_use", "Сервер уже входит в каскад", server_id=entry_id)
        if other_ids:
            addresses = await server_ops._host_addrs(entry.host)
            for other in await session.scalars(select(Server).where(Server.id.in_(other_ids))):
                if entry.host == other.host or addresses & (await server_ops._host_addrs(other.host)):
                    raise conflict("cascade_duplicate_host", "Этот узел уже используется под другой записью сервера",
                                   server_id=other.id)
        if row:
            _check_local_install(row.id)
        options = json.loads(row.params or "{}") if row else {}
        try:
            async with _locked(entry) as conn:
                result = await conn.run(cascade_recovery.INSPECT, check=False, timeout=20)
                if "CASCADE_EXTERNAL_UNDERLAY" in (result.stdout or ""):
                    raise conflict("cascade_external_underlay", "Канал защищен внешним AWG helper. Сначала отключите его штатным способом")
                if result.exit_status != 0:
                    raise _unsafe_entry()
                runtime = json.loads(result.stdout)
                stored = cascade_exit._owner(row.id, row.transport, options) if row and cascade_exit.scoped(options) else None
                if runtime is None and stored is None:
                    raise conflict("cascade_recovery_absent", "На входе не найден шлюз каскада для восстановления.")
                marker = runtime or stored
                cid, transport, owner = marker["cascade_id"], marker["transport"], marker["owner"]
                same_owner = stored == {key: marker[key] for key in ("cascade_id", "transport", "owner", "layout")}
                if same_owner and runtime and "gre_key" in runtime and runtime["gre_key"] != options.get("gre_key"):
                    raise _unsafe_entry()
                if cascade_id is not None and (stored is None or (runtime is not None and same_owner)):
                    raise _unsafe_entry()
                resume = bool(row and (not same_owner or cascade_id is not None))
                if resume and (row.status not in ("error", "installing") or stored is None):
                    raise _unsafe_entry()
                recovery_options = cascade_recovery.params(marker)
                if same_owner and transport == "gre":
                    recovery_options |= {key: options[key] for key in ("gre_key", "exit_ip") if key in options}
                snapshot = (entry.id, entry.host, entry.ssh_port, entry.ssh_user, runtime, cascade_id,
                            (row.id, row.exit_server_id, row.transport, row.status, row.params, row.result) if row else None)
                fingerprint = hashlib.sha256(json.dumps(snapshot, sort_keys=True).encode()).hexdigest()
                out = EntryRecoveryOut(token=fingerprint, transport=transport,
                                       entry_country=options.get("entry_country", ""), routes=options.get("routes", []),
                                       resume=_out(row).model_copy(update={"status": "error"}) if resume else None)
                guard = cascade_recovery.guard(runtime, cid, transport, recovery_options)
                if token is None:
                    verified = await conn.run(guard, check=False, timeout=45)
                    if verified.exit_status != 0:
                        raise _unsafe_entry()
                    return out
                if not secrets.compare_digest(token, fingerprint):
                    raise conflict("cascade_recovery_changed", "Состояние каскада изменилось. Откройте восстановление заново.")
                row_lock = (row.id, stored["owner"]) if resume else None
                script = cascade_lock.recover(cid, cascade_recovery.cleanup(runtime, cid, transport, recovery_options),
                                              owner, guard, row_lock)
                removed = await conn.run(script, check=False, timeout=120)
                markers = (removed.stdout or "").splitlines()
                if "CASCADE_OPERATION_BUSY" in markers:
                    raise _remote_install_busy(cid, "entry")
                if "CASCADE_RECOVERY_LOCK_CONFLICT" in markers:
                    raise conflict("cascade_recovery_lock_conflict", "На входе сохранена операция другого каскада. Снятие шлюза не началось.")
                if "CASCADE_RECOVERY_STATE_CHANGED" in markers:
                    raise conflict("cascade_recovery_changed", "Состояние шлюза изменилось. Проверьте вход заново.")
                if removed.exit_status != 0 or "CASCADE_REMOVED=yes" not in markers:
                    if "CASCADE_RECOVERY_TPROXY_FAILED" in markers:
                        raise conflict("cascade_recovery_tproxy", "Не удалось снять правила маршрутизации старого шлюза (TPROXY).",
                                       cascade_id=cid, server_id=entry.id, side="entry")
                    if "CASCADE_RECOVERY_CLEANUP_STARTED" in markers:
                        raise conflict("cascade_recovery_cleanup", "Снятие шлюза началось, но на входе остались его ресурсы. Проверьте вход заново.")
                    raise conflict("cascade_recovery_failed", "Вход не подтвердил начало снятия шлюза. Проверьте вход заново.")
        except Exception as exc:  # noqa: BLE001
            raise _ssh_error(exc) from exc
        entry.egress_ip = entry.egress_country = entry.egress_org = ""
        entry.egress_at = None
        if row:
            if resume:
                row.status = "error"
            else:
                await session.delete(row)
        await session.commit()
        await audit.record(session, user.username, "cascade_entry_recovery", entry.name,
                           "снят старый шлюз каскада на входе")
        return out


@router.get("/entry-recovery/{entry_id}", response_model=EntryRecoveryOut)
async def preview_entry_recovery(entry_id: int, user: CurrentUser, session: SessionDep,
                                 cascade_id: Annotated[int | None, Query(gt=0)] = None) -> EntryRecoveryOut:
    return await _entry_recovery(entry_id, user, session, cascade_id=cascade_id)


@router.post("/entry-recovery/{entry_id}", response_model=EntryRecoveryOut)
async def recover_entry(entry_id: int, body: EntryRecoveryRequest,
                        user: CurrentUser, session: SessionDep) -> EntryRecoveryOut:
    return await _entry_recovery(entry_id, user, session, body.token, body.cascade_id)


@router.delete("/{cascade_id}", status_code=status.HTTP_204_NO_CONTENT)
@_pair_operation
async def delete(
    cascade_id: int, user: CurrentUser, session: SessionDep, force: bool = False
) -> None:
    c = await _get_or_404(cascade_id, session)
    _check_local_install(c.id)
    params = json.loads(c.params or "{}")
    entry = await session.get(Server, c.entry_server_id)
    exit_ = await session.get(Server, c.exit_server_id)
    errors: list[str] = []
    # Check both nodes before removing anything. The script still takes the
    # remote lock, since an already launched installer can acquire it later.
    entry_error = exit_error = ""
    if cascade_exit.scoped(params):
        owner = params["runtime_owner"]
        if entry is not None:
            entry_error = await _check_remove_node(entry, c.id, owner, "entry")
        if exit_ is not None:
            exit_error = await _check_remove_node(exit_, c.id, owner, "exit")
        errors.extend(error for error in (entry_error, exit_error) if error)
    if errors and not force:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "Разобрать не удалось: " + "; ".join(errors))
    # сначала вход: клиенты сразу пойдут напрямую, а не в разобранный выход
    if entry is not None and not entry_error:
        script = cascade.build_remove_entry(c.transport, c.id, params)
        if c.transport != "awg":
            script += cascade.ufw_cleanup(params.get("exit_ip", ""), None)
        if cascade_exit.scoped(params):
            script = cascade_lock.wrap(c.id, script, params["runtime_owner"], remove=True)
        entry_error = await _dismantle(entry, script, c.id, "entry")
        if entry_error:
            errors.append(entry_error)
    if exit_ is not None and not (entry_error or exit_error):
        script = cascade.build_remove_exit(c.transport, c.id, params)
        if c.transport != "awg" and not cascade_exit.scoped(params):
            script += cascade.ufw_cleanup(params.get("entry_ip", ""), params.get("port"))
        if cascade_exit.scoped(params):
            script = cascade_lock.wrap(c.id, script, params["runtime_owner"], remove=True)
        if err := await _dismantle(exit_, script, c.id, "exit"):
            errors.append(err)
    if errors and not force:
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY, "Разобрать не удалось: " + "; ".join(errors)
        )
    if entry is not None:
        entry.egress_ip = entry.egress_country = entry.egress_org = ""
        entry.egress_at = None
    name = entry.name if entry else str(c.id)
    await session.delete(c)
    await session.commit()
    await audit.record(
        session, user.username, "cascade_delete", name,
        "без разборки на сервере" if errors else "",
    )
    # туннеля больше нет: перечитываем ноды, чтобы бейдж GRE и маршрут не висели
    # до следующей проверки
    if not errors:
        for server in (entry, exit_):
            if server is None:
                continue
            try:
                await server_ops.run_check(session, server, get_settings())
            except Exception:  # noqa: BLE001 — каскад уже разобран
                pass
