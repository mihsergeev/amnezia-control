"""Фоновая установка каскада: сначала выход, потом вход (см. app/cascade.py).

Скрипты на нодах идут детачед (deploy.launch), задача ждет маркер DEPLOY_DONE
или DEPLOY_ERROR на каждой стороне по очереди. Ход установки держим в памяти:
окно мастера можно закрыть и открыть снова, а после рестарта панели незаконченная
установка помечается ошибкой, ее можно запустить повторно (скрипты идемпотентны).
"""

import asyncio
import json
import logging
import secrets
from datetime import datetime, timezone

from fastapi import HTTPException

from app import alerts, cascade, cascade_exit, cascade_lock, deploy, geo, nodelock, server_ops, sshops
from app.config import get_settings
from app.models import Cascade, Server
from app.sshkeys import ensure_panel_key, key_paths

log = logging.getLogger("acontrol.cascade")

_POLL_SECONDS = 4
# геобазы с github и docker pull на медленном входе бывают долгими
_MAX_SECONDS = 20 * 60

_tasks: dict[int, asyncio.Task] = {}
# id каскада -> {"phase": exit|entry, "log": ...}, только пока идет установка
_progress: dict[int, dict] = {}

PHASE_LABEL = {"exit": "выход", "entry": "вход"}


def running(cascade_id: int) -> bool:
    task = _tasks.get(cascade_id)
    return task is not None and not task.done()


def progress(cascade_id: int) -> dict:
    return _progress.get(cascade_id, {})


def connect(server: Server, settings=None):
    settings = settings or get_settings()
    ensure_panel_key(settings.data_dir)
    key_path, _pub = key_paths(settings.data_dir)
    return sshops.connect(
        server.host, server.ssh_port, server.ssh_user, key_path,
        settings.ssh_connect_timeout,
    )


def _joined(logs: dict[str, tuple[str, str]]) -> str:
    parts = []
    for phase in ("exit", "entry"):
        if phase in logs:
            name, text = logs[phase]
            parts.append(f"== {PHASE_LABEL[phase]}: {name} ==\n{text}".rstrip())
    return "\n".join(parts)


async def _side(
    cid: int, phase: str, server: Server, script: str, logs: dict, settings, *, tag: str | None = None,
    owner: str = "",
) -> tuple[str, str]:
    """Запускает скрипт на стороне и ждет итог. (state, хвост лога)."""
    logs[phase] = (server.name, "")
    _progress[cid] = {"phase": phase, "log": _joined(logs)}
    # шаг SSH без своего срока: зависшая нода иначе держала бы установку вечно
    step = max(settings.ssh_connect_timeout * 4, 30)
    async with asyncio.timeout(step), connect(server, settings) as conn:
        if owner:
            generation = secrets.token_hex(16)
            armed = await conn.run(cascade_lock.arm_command(cid, owner, generation), check=False, timeout=20)
            if armed.exit_status != 0 or "CASCADE_OPERATION_ARMED" not in (armed.stdout or ""):
                return "error", "DEPLOY_ERROR: previous cascade operation is still active or ownership is unknown"
            script = cascade_lock.wrap(cid, script, owner, generation=generation)
        await deploy.launch(conn, script, tag=tag or cascade.TAG)
    st: dict = {"state": "unknown", "log": ""}
    try:
        async with asyncio.timeout(_MAX_SECONDS):
            while True:
                await asyncio.sleep(_POLL_SECONDS)
                try:
                    async with asyncio.timeout(step), connect(server, settings) as conn:
                        st = await deploy.read_status(conn, tag=tag or cascade.TAG)
                except Exception:  # noqa: BLE001 — нода моргнула, спросим еще раз
                    continue
                logs[phase] = (server.name, st.get("log", ""))
                _progress[cid] = {"phase": phase, "log": _joined(logs)}
                if st.get("state") in ("done", "error"):
                    return st["state"], st.get("log", "")
    except TimeoutError:
        pass
    return "error", st.get("log", "") + "\nDEPLOY_ERROR: не дождался конца установки"


def _error_line(text: str) -> str:
    for line in reversed(text.splitlines()):
        if "DEPLOY_ERROR:" in line:
            return line.split("DEPLOY_ERROR:", 1)[1].strip()
    return "ошибка установки"


async def _run(cid: int, factory, settings) -> None:
    async with factory() as session:
        c = await session.get(Cascade, cid)
        if c is None:
            return
        first, second = sorted((c.entry_server_id, c.exit_server_id))
    # Retain both node locks through both phases. Another entry may share the
    # exit, but install/delete must not interleave with a half-finished job.
    try:
        async with nodelock.hold("cascade", first), nodelock.hold("cascade", second):
            await _run_locked(cid, factory, settings)
    except HTTPException as exc:
        message = "Не удалось дождаться освобождения узлов каскада" if exc.status_code == 409 else "Установка каскада прервана"
        await _finish(factory, cid, "error", message, "", {"failed_phase": "exit"})
    except Exception:
        log.exception("unexpected cascade job failure for %s", cid)
        await _finish(factory, cid, "error", "Установка каскада прервана", "", {"failed_phase": "exit"})


async def _run_locked(cid: int, factory, settings) -> None:
    async with factory() as session:
        c = await session.get(Cascade, cid)
        if c is None:
            return
        entry = await session.get(Server, c.entry_server_id)
        exit_ = await session.get(Server, c.exit_server_id)
        transport = c.transport
        params = json.loads(c.params or "{}")
    if entry is None or exit_ is None:
        return
    # The collector may not have looked up a newly added entry yet.
    country = entry.country or await geo.country_code(entry.host)
    steps = [
        ("exit", exit_, cascade.build_exit_script(transport, params["entry_ip"], cid, params)),
        ("entry", entry, cascade.build_entry_script(transport, params["exit_ip"], cid, params,
                                                     country)),
    ]
    logs: dict[str, tuple[str, str]] = {}
    entry_log = ""
    for phase, server, script in steps:
        try:
            state, tail = await _side(cid, phase, server, script, logs, settings,
                                      tag=f"{cascade.TAG}-{cid}" if cascade_exit.scoped(params) else None,
                                      owner=params["runtime_owner"] if cascade_exit.scoped(params) else "")
        except Exception as exc:  # noqa: BLE001 — SSH при запуске
            state, tail = "error", f"DEPLOY_ERROR: SSH: {exc or type(exc).__name__}"
        if state != "done":
            msg = f"{PHASE_LABEL[phase]} «{server.name}»: {_error_line(tail)}"
            # хвост этой стороны кладем на ее место (при сбое SSH его там еще нет)
            logs[phase] = (server.name, tail)
            await _finish(factory, cid, "error", msg, _joined(logs), {"failed_phase": phase})
            if entry.alerts_enabled or exit_.alerts_enabled:
                await alerts.maybe_alert(
                    factory, settings,
                    alerts.Card(
                        "crit", "", alerts.t("Каскад не собрался"), msg,
                        subject=entry.name,
                    ),
                )
            return
        if phase == "entry":
            entry_log = tail
    result = cascade.check_result(cascade.parse_kv(entry_log))
    result["checked_at"] = datetime.now(timezone.utc).isoformat()
    await _finish(factory, cid, "ready", "", _joined(logs), result)
    # адрес выхода и бейджи в карточках: перечитываем обе ноды
    async with factory() as session:
        for sid in (entry.id, exit_.id):
            server = await session.get(Server, sid)
            if server is None:
                continue
            try:
                await server_ops.run_check(session, server, settings)
            except Exception:  # noqa: BLE001 — каскад уже собран
                log.warning("post-cascade check failed for server %s", sid, exc_info=True)
        server = await session.get(Server, entry.id)
        if server is not None and result.get("egress"):
            desc = await server_ops.describe_egress(server.host, result["egress"])
            server_ops.apply_egress(server, desc, datetime.now(timezone.utc))
            await session.commit()


async def _finish(factory, cid: int, status: str, error: str, text: str, result: dict) -> None:
    async with factory() as session:
        c = await session.get(Cascade, cid)
        if c is not None:
            c.status = status
            c.error = error
            if result:
                c.result = json.dumps(result)
            await session.commit()
    # последний лог оставляем: мастер покажет его на шаге «Готово» или при ошибке
    _progress[cid] = {"phase": result.get("failed_phase", ""), "log": text}


def spawn(app, cascade_id: int) -> None:
    factory = getattr(app.state, "session_factory", None)
    if factory is None or running(cascade_id):
        return
    _progress[cascade_id] = {"phase": "exit", "log": ""}
    task = asyncio.create_task(_run(cascade_id, factory, get_settings()))
    _tasks[cascade_id] = task

    def _done(t: asyncio.Task) -> None:
        if _tasks.get(cascade_id) is t:
            _tasks.pop(cascade_id, None)
        if not t.cancelled() and t.exception() is not None:
            log.error("cascade %s install crashed", cascade_id, exc_info=t.exception())

    task.add_done_callback(_done)
