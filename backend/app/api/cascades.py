"""Каскады из двух серверов: проверка канала, установка, проверка и разборка
(см. app/cascade.py и app/cascadejob.py)."""

import json
from datetime import datetime, timezone

import asyncssh
from fastapi import APIRouter, HTTPException, Request, status
from sqlalchemy import select

from app import audit, cascade, cascadejob, deploy, geo, nodelock, server_ops
from app.config import get_settings
from app.deps import CurrentUser, SessionDep
from app.models import Cascade, Server
from app.schemas import (
    CascadeCheckOut,
    CascadeCreate,
    CascadeOut,
    CascadePair,
    CascadeProbeOut,
)

router = APIRouter(prefix="/cascades", tags=["cascades"])

# последняя проверка канала по паре (вход, выход): ее показывает карточка
_last_probe: dict[tuple[int, int], dict] = {}


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


async def _ipv4(host: str) -> str:
    for addr in sorted(await server_ops._host_addrs(host)):
        if ":" not in addr:
            return addr
    return ""


def _out(c: Cascade) -> CascadeOut:
    params = json.loads(c.params or "{}")
    result = json.loads(c.result or "{}")
    prog = cascadejob.progress(c.id)
    # на какой стороне упала установка - и после рестарта панели, когда хода в памяти нет
    phase = prog.get("phase", "") or (result.get("failed_phase", "") if c.status == "error" else "")
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
    ids = (entry.id, exit_.id)
    busy = (await session.execute(
        select(Cascade).where(
            Cascade.entry_server_id.in_(ids) | Cascade.exit_server_id.in_(ids)
        )
    )).scalars().first()
    if busy is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "Сервер уже входит в каскад")
    for s in (entry, exit_):
        if s.last_check_ok is not True:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                f"«{s.name}» не на связи: проверьте сервер и повторите",
            )
    return entry, exit_


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
    return [_out(c) for c in rows]


@router.post("/probe", response_model=CascadeProbeOut)
async def probe(body: CascadePair, _: CurrentUser, session: SessionDep) -> CascadeProbeOut:
    entry, exit_ = await _pair(body, session)
    try:
        async with _locked(entry) as ec, _locked(exit_) as xc:
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
    )


async def _vless_port(conn) -> int:
    for port in cascade.VLESS_PORTS:
        if await deploy.port_owner(conn, port, "tcp", own=cascade.EXIT_CONTAINER) is None:
            return port
    raise HTTPException(
        status.HTTP_409_CONFLICT,
        "На выходе заняты все порты для VLESS ("
        + ", ".join(str(p) for p in cascade.VLESS_PORTS) + ")",
    )


@router.post("", response_model=CascadeOut, status_code=status.HTTP_202_ACCEPTED)
async def create(
    body: CascadeCreate, request: Request, user: CurrentUser, session: SessionDep
) -> CascadeOut:
    entry, exit_ = await _pair(body, session)
    try:
        async with _locked(entry) as ec, _locked(exit_) as xc:
            entry_ip, exit_ip = await _addresses(ec, entry, exit_)
            params: dict = {"entry_ip": entry_ip, "exit_ip": exit_ip}
            if body.transport == "vless":
                params |= cascade.new_vless_params()
                params["port"] = await _vless_port(xc)
    except Exception as exc:  # noqa: BLE001
        raise _ssh_error(exc) from exc
    c = Cascade(
        entry_server_id=entry.id,
        exit_server_id=exit_.id,
        transport=body.transport,
        status="installing",
        params=json.dumps(params),
        probe=json.dumps(_last_probe.get((entry.id, exit_.id), {})),
    )
    session.add(c)
    await session.commit()
    await session.refresh(c)
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
    return _out(c)


@router.post("/{cascade_id}/install", response_model=CascadeOut,
             status_code=status.HTTP_202_ACCEPTED)
async def reinstall(
    cascade_id: int, request: Request, user: CurrentUser, session: SessionDep
) -> CascadeOut:
    c = await _get_or_404(cascade_id, session)
    if cascadejob.running(c.id):
        raise HTTPException(status.HTTP_409_CONFLICT, "Установка уже идет")
    c.status = "installing"
    c.error = ""
    await session.commit()
    cascadejob.spawn(request.app, c.id)
    entry = await session.get(Server, c.entry_server_id)
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
    tunnel = kv.get("tun", "") if c.transport == "gre" else ""
    gateway = kv.get("gw") == "yes"
    tproxy = kv.get("tproxy") == "active"
    rule = kv.get("rule") != "no" and (c.transport != "gre" or kv.get("grerule") != "no")
    ok, _reason = cascade.health(c.transport, kv, res)
    return CascadeCheckOut(
        ok=ok, gateway=gateway, tproxy=tproxy, rule=rule, tunnel=tunnel,
        egress=res["egress"], ru=res["ru"], client=res["client"], direct=res["direct"],
        leak=cascade.leaks(res), checked_at=now,
    )


async def _dismantle(server: Server, script: str) -> str:
    """Пусто - разобрано, иначе текст ошибки."""
    try:
        async with _locked(server) as conn:
            r = await conn.run(script, check=False, timeout=120)
    except Exception as exc:  # noqa: BLE001
        return f"«{server.name}»: {_ssh_error(exc).detail}"
    if "CASCADE_REMOVED=yes" not in (r.stdout or ""):
        return f"«{server.name}»: {(r.stderr or r.stdout or '').strip()[-300:]}"
    return ""


@router.delete("/{cascade_id}", status_code=status.HTTP_204_NO_CONTENT)
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
        script = cascade.build_remove_entry() + cascade.ufw_cleanup(
            params.get("exit_ip", ""), None
        )
        if err := await _dismantle(entry, script):
            errors.append(err)
    if exit_ is not None:
        script = cascade.build_remove_exit() + cascade.ufw_cleanup(
            params.get("entry_ip", ""), params.get("port")
        )
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
