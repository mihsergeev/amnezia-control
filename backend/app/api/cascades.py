"""Каскады из двух серверов: проверка канала, установка, проверка и разборка
(см. app/cascade.py и app/cascadejob.py)."""

import asyncio
import inspect
import json
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from functools import wraps

import asyncssh
from fastapi import APIRouter, HTTPException, Request, status
from sqlalchemy import select

from app import audit, cascade, cascade_awg, cascade_exit, cascade_lock, cascade_probe, cascadejob, deploy, geo, nodelock, server_ops
from app.cascade_routes import RouteUpdate, update_script
from app.config import get_settings
from app.deps import CurrentUser, SessionDep
from app.models import Cascade, Server
from app.schemas import (
    CascadeCheckOut,
    CascadeCreate,
    CascadeOut,
    CascadePair,
    CascadeProbeOut,
    CascadeTransportProbe,
    CascadeTransportProbeOut,
)

router = APIRouter(prefix="/cascades", tags=["cascades"])

# последняя проверка канала по паре (вход, выход): ее показывает карточка
_last_probe: dict[tuple[int, int], dict] = {}


def _pair_operation(handler):
    signature = inspect.signature(handler)

    @wraps(handler)
    async def wrapped(*args, **kwargs):
        values = signature.bind(*args, **kwargs).arguments
        session = values["session"]
        cid = values["cascade_id"]
        row = await _get_or_404(cid, session)
        if cascadejob.running(cid):
            raise HTTPException(status.HTTP_409_CONFLICT, "Идет установка, дождитесь ее конца")
        first, second = sorted((row.entry_server_id, row.exit_server_id))
        async with nodelock.hold("cascade", first), nodelock.hold("cascade", second):
            if await session.get(Cascade, cid, populate_existing=True) is None:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "Каскад не найден")
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
async def _locked_pair(entry: Server, exit_: Server):
    """Обе ноды под блокировкой, всегда в порядке id: встречные пары A-B и B-A,
    взятые как вход-выход, ждали бы друг друга. Отдает (вход, выход)."""
    first, second = sorted((entry, exit_), key=lambda s: s.id)
    async with _locked(first) as c1, _locked(second) as c2:
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
        entry_ip=params.get("entry_ip", ""),
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
    for s in (entry, exit_):
        if s.last_check_ok is not True:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                f"«{s.name}» не на связи: проверьте сервер и повторите",
            )
    return entry, exit_


async def _ensure_free(session, entry: Server, exit_: Server) -> None:
    rows = list(await session.scalars(select(Cascade)))
    if any(c.entry_server_id in (entry.id, exit_.id) or c.exit_server_id == entry.id for c in rows):
        raise HTTPException(status.HTTP_409_CONFLICT, "Сервер уже входит в каскад")
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
            raise HTTPException(status.HTTP_409_CONFLICT, "Этот узел уже используется под другой записью сервера")


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
    raise HTTPException(status.HTTP_409_CONFLICT, "На выходе нет свободной внутренней подсети")


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


@router.post("/probe-transport", response_model=CascadeTransportProbeOut)
async def probe_transport(
    body: CascadeTransportProbe, request: Request, _: CurrentUser, session: SessionDep,
) -> CascadeTransportProbeOut:
    entry, exit_ = await _pair(body, session)
    first, second = sorted((entry.id, exit_.id))
    try:
        # A repeated click must not queue another expensive remote measurement.
        async with nodelock.hold("cascade", first, wait=0.1), nodelock.hold("cascade", second, wait=0.1):
            async with _locked_pair(entry, exit_) as (ec, xc):
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
                task = asyncio.create_task(cascade_probe.run(
                    xc, ec, entry_ip, exit_ip, body.transport, body.entry_port, body.exit_port,
                    entry_source_ip=entry_source, prepare_missing_image=body.prepare_missing_image,
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
        raise _ssh_error(exc) from exc
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
    return CascadeTransportProbeOut(**res)


async def _vless_port(conn, reserved: set[int] | None = None) -> int:
    choices = (*cascade.VLESS_PORTS, *(30000 + secrets.randbelow(20000) for _ in range(20)))
    for port in choices:
        if port not in (reserved or ()) and await deploy.port_owner(conn, port, "tcp") is None:
            return port
    raise HTTPException(
        status.HTTP_409_CONFLICT,
        "На выходе заняты все порты для VLESS ("
        + ", ".join(str(p) for p in cascade.VLESS_PORTS) + ")",
    )


async def _awg_preflight(conn, cascade_id: int | None = None) -> None:
    res = await conn.run(cascade_awg.preflight_command(cascade_id), check=False, timeout=20)
    if "CASCADE_AVAILABLE" not in (res.stdout or ""):
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "На сервере уже есть внешний туннель или заняты ресурсы AWG каскада")


async def _awg_port(conn, requested: int | None, reserved: set[int] | None = None) -> int:
    for port in (requested,) if requested is not None else cascade_awg.PORTS:
        if port not in (reserved or ()) and await deploy.port_owner(conn, port, "udp") is None:
            return port
    raise HTTPException(status.HTTP_409_CONFLICT,
                        "UDP-порт для канала AWG занят. Укажите другой порт")


async def _external_preflight(conn) -> None:
    result = await conn.run(cascade_awg.foreign_guard() + "echo CASCADE_AVAILABLE\n",
                            check=False, timeout=20)
    if "CASCADE_EXTERNAL_UNDERLAY" in (result.stdout or ""):
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "Канал защищен внешним AWG helper. Сначала отключите его штатным способом")
    if "CASCADE_AVAILABLE" not in (result.stdout or ""):
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "Не удалось проверить существующий канал")


async def _operation_available(conn, cascade_id: int, owner: str) -> None:
    result = await conn.run(cascade_lock.check_command(cascade_id, owner), check=False, timeout=20)
    if "CASCADE_OPERATION_BUSY" in (result.stdout or ""):
        raise HTTPException(status.HTTP_409_CONFLICT, "Установка еще выполняется на узле, дождитесь ее конца")
    if "CASCADE_OPERATION_FREE" not in (result.stdout or "") or result.exit_status != 0:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "Не удалось проверить установку на узле")


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
    entry, exit_ = await _pair(body, session)
    try:
        async with _locked_pair(entry, exit_) as (ec, xc):
            # проверка в _pair шла до блокировки: двойной клик проходил ее дважды
            # и создавал два каскада. Перепроверяем и пишем строку под блокировкой
            await _ensure_free(session, entry, exit_)
            entry_ip, exit_ip = await _addresses(ec, entry, exit_)
            siblings = await _siblings(session, exit_.id)
            params: dict = {"entry_ip": entry_ip, "exit_ip": exit_ip,
                            "runtime_layout": 2, "runtime_owner": secrets.token_hex(16),
                            "inner_net": _inner_reservation(siblings)}
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
            session.add(c)
            await session.commit()
            await session.refresh(c)
    except Exception as exc:  # noqa: BLE001
        raise _ssh_error(exc) from exc
    cascadejob.spawn(request.app, c.id)
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
        raise HTTPException(status.HTTP_409_CONFLICT, "Маршруты доступны после установки каскада")
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
    cascade_id: int, request: Request, user: CurrentUser, session: SessionDep
) -> CascadeOut:
    c = await _get_or_404(cascade_id, session)
    if cascadejob.running(c.id):
        raise HTTPException(status.HTTP_409_CONFLICT, "Установка уже идет")
    entry = await session.get(Server, c.entry_server_id)
    exit_ = await session.get(Server, c.exit_server_id)
    if entry is None or exit_ is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Сервер не найден")
    try:
        async with _locked_pair(entry, exit_) as (ec, xc):
            if cascadejob.running(c.id):
                raise HTTPException(status.HTTP_409_CONFLICT, "Установка уже идет")
            if cascade_exit.scoped(json.loads(c.params or "{}")):
                owner = json.loads(c.params)["runtime_owner"]
                await _operation_available(ec, c.id, owner)
                await _operation_available(xc, c.id, owner)
            if c.transport == "awg":
                await _awg_preflight(ec, c.id)
                if not cascade_exit.scoped(json.loads(c.params or "{}")):
                    await _awg_preflight(xc, c.id)
            else:
                await _external_preflight(ec)
                if not cascade_exit.scoped(json.loads(c.params or "{}")):
                    await _external_preflight(xc)
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
    try:
        async with _locked(entry) as conn:
            out = await cascade.run_check(conn, entry.country)
    except Exception as exc:  # noqa: BLE001
        raise _ssh_error(exc) from exc
    kv = cascade.parse_kv(out)
    res = cascade.check_result(kv)
    now = datetime.now(timezone.utc)
    result = json.loads(c.result or "{}") | res | {"checked_at": now.isoformat()}
    c.result = json.dumps(result)
    # на карточку сервера - адрес, с которого реально выходят клиенты
    if res["client"] or res["egress"]:
        server_ops.apply_egress(
            entry, await server_ops.describe_egress(entry.host, res["client"] or res["egress"]), now
        )
    await session.commit()
    tunnel = kv.get("tun", "") if c.transport == "gre" else (
        "UP" if kv.get("awg") == "yes" else "DOWN"
    ) if c.transport == "awg" else ""
    gateway = kv.get("gw") == "yes"
    tproxy = kv.get("tproxy") == "active"
    rule = kv.get("rule") != "no" and (c.transport != "gre" or kv.get("grerule") != "no")
    if c.transport == "awg":
        rule = rule and kv.get("awg") == "yes"
    ok, _reason = cascade.health(c.transport, kv, res)
    return CascadeCheckOut(
        ok=ok, gateway=gateway, tproxy=tproxy, rule=rule, tunnel=tunnel,
        egress=res["egress"], ru=res["ru"], client=res["client"], direct=res["direct"],
        leak=cascade.leaks(res), checked_at=now,
        **cascade.encryption_result(kv),
    )


async def _dismantle(server: Server, script: str) -> str:
    """Пусто - разобрано, иначе текст ошибки."""
    try:
        async with _locked(server) as conn:
            r = await conn.run(script, check=False, timeout=120)
    except Exception as exc:  # noqa: BLE001
        return f"«{server.name}»: {_ssh_error(exc).detail}"
    if "CASCADE_EXTERNAL_UNDERLAY" in (r.stdout or ""):
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "Канал защищен внешним AWG helper. Сначала отключите его штатным способом")
    if "CASCADE_OPERATION_BUSY" in (r.stdout or ""):
        raise HTTPException(status.HTTP_409_CONFLICT, "Установка еще выполняется на узле, дождитесь ее конца")
    if "CASCADE_REMOVED=yes" not in (r.stdout or ""):
        return f"«{server.name}»: {(r.stderr or r.stdout or '').strip()[-300:]}"
    return ""


@router.delete("/{cascade_id}", status_code=status.HTTP_204_NO_CONTENT)
@_pair_operation
async def delete(
    cascade_id: int, user: CurrentUser, session: SessionDep, force: bool = False
) -> None:
    c = await _get_or_404(cascade_id, session)
    if cascadejob.running(c.id):
        raise HTTPException(status.HTTP_409_CONFLICT, "Идет установка, дождитесь ее конца")
    params = json.loads(c.params or "{}")
    entry = await session.get(Server, c.entry_server_id)
    exit_ = await session.get(Server, c.exit_server_id)
    errors: list[str] = []
    # сначала вход: клиенты сразу пойдут напрямую, а не в разобранный выход
    if entry is not None:
        script = cascade.build_remove_entry(c.transport, c.id, params)
        if c.transport != "awg":
            script += cascade.ufw_cleanup(params.get("exit_ip", ""), None)
        if cascade_exit.scoped(params):
            script = cascade_lock.wrap(c.id, script, params["runtime_owner"], remove=True)
        if err := await _dismantle(entry, script):
            errors.append(err)
    if exit_ is not None:
        script = cascade.build_remove_exit(c.transport, c.id, params)
        if c.transport != "awg" and not cascade_exit.scoped(params):
            script += cascade.ufw_cleanup(params.get("entry_ip", ""), params.get("port"))
        if cascade_exit.scoped(params):
            script = cascade_lock.wrap(c.id, script, params["runtime_owner"], remove=True)
        if err := await _dismantle(exit_, script):
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
