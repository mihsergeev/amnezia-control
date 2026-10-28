"""Фоновый сборщик метрик: периодически снимает статистику со всех серверов."""

import asyncio
import json
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app import (
    alerts, audit, awg, deploy, geo, nodestat, onlinedrop, openvpn, server_ops,
    settings_store, sshops, xray,
)
from app.config import Settings
from app.models import (
    AuditLog,
    ClientName,
    ClientTrafficSample,
    NodeMetric,
    Server,
    TrafficSample,
)
from app.sshkeys import ensure_panel_key, key_paths

log = logging.getLogger("acontrol.collector")

ONLINE_WINDOW = 180  # секунд — пир считается онлайн, если хендшейк свежее

# server_id нод, по которым уже отправлен алерт о смене host-ключа (чтобы не
# спамить каждый цикл); снимается, когда нода снова успешно подключается
_hostkey_alerted: set[int] = set()

_ZERO = {"rx": 0, "tx": 0, "total": 0, "online": 0}

# Какие протоколы сервера прочитались в прошлом цикле. Счетчик сервера - сумма
# по протоколам: если один не прочитался, сумма падает (дельта обрезается до 0),
# а в следующем цикле весь накопленный счетчик протокола уходил бы как прирост.
# Поэтому, пока набор протоколов не повторился два цикла подряд, общий снимок
# сервера не пишем: дельта считается между двумя снимками с одним набором.
_last_parts: dict[int, frozenset[str]] = {}


async def _awg_part(conn, host) -> tuple[dict, list[dict]]:
    """Собирает клиентов ВСЕХ версий AmneziaWG на ноде, каждую под своим
    протоколом. Раньше читался только основной контейнер и всё помечалось как
    «awg»: клиенты 3.0 не попадали в статистику и в глобальный поиск вовсе, а
    legacy рядом с новым сливался с ним. Ключ протокола важен и для отзыва —
    по нему выбирается контейнер."""
    targets: list[tuple[str, str]] = []  # (контейнер, протокол)
    conts = await awg.detect_awg_containers(conn)  # awg3 сюда не попадает
    if conts["new"]:
        targets.append((conts["new"], "awg"))
    if conts["legacy"]:
        targets.append((conts["legacy"], "awglegacy"))
    for name in await deploy.awg3_containers(conn):
        targets.append((name, "awg3"))
    if not targets:
        targets.append((await awg.detect_container(conn), "awg"))

    now = datetime.now(timezone.utc).timestamp()
    totals = {"rx": 0, "tx": 0, "total": 0, "online": 0}
    clients: list[dict] = []
    parts: list[str] = []
    for container, proto in targets:
        try:
            state = await awg.read_state(conn, host, container=container)
        except Exception:  # noqa: BLE001 — один протокол не должен ронять сбор
            continue
        parts.append(f"{proto}:{container}")
        totals["rx"] += sum(c.rx_bytes for c in state.clients)
        totals["tx"] += sum(c.tx_bytes for c in state.clients)
        totals["total"] += len(state.clients)
        totals["online"] += sum(
            1
            for c in state.clients
            if c.latest_handshake and now - c.latest_handshake < ONLINE_WINDOW
        )
        clients += [
            {"protocol": proto, "client_id": c.public_key, "rx": c.rx_bytes,
             "tx": c.tx_bytes, "name": c.name}
            for c in state.clients
        ]
    totals["parts"] = parts
    totals["known"] = [(c["protocol"], c["client_id"]) for c in clients]
    return totals, clients


async def _openvpn_part(conn, host) -> tuple[dict, list[dict]]:
    # total — из clientsTable; online + трафик — из openvpn-status.log (v1, CSV)
    container = await openvpn.detect_container(conn)
    table = await openvpn._read_table(conn, container)
    total = len(table)
    ovpn_names = {
        e.get("clientId"): (e.get("userData", {}) or {}).get("clientName", "")
        for e in table
        if isinstance(e, dict)
    }
    status_map = await openvpn.read_status_map(conn, container)
    rx = tx = online = 0
    clients: list[dict] = []
    for cid, st in status_map.items():
        rx += st["rx"]
        tx += st["tx"]
        online += 1
        clients.append(
            {"protocol": "openvpn", "client_id": cid,
             "rx": st["rx"], "tx": st["tx"], "name": ovpn_names.get(cid, "")}
        )
    known = [("openvpn", e.get("clientId")) for e in table
             if isinstance(e, dict) and e.get("clientId")]
    return {"rx": rx, "tx": tx, "total": total, "online": online,
            "parts": ["openvpn"], "known": known}, clients


async def _xray_part(conn, host) -> tuple[dict, list[dict]]:
    # трафик по клиентам — из xray StatsService (если включён на сервере)
    container = await xray.detect_container(conn)
    clients = await xray.read_clients(conn)
    stats = await xray.read_client_stats(conn, container)
    names = {c.client_id: c.name for c in clients}
    rows: list[dict] = []
    rx = tx = 0
    for uid, st in stats.items():
        if uid not in names:  # дефолтный UUID / уже отозванные — пропускаем
            continue
        rx += st["up"]
        tx += st["down"]
        rows.append(
            {"protocol": "xray", "client_id": uid,
             "rx": st["up"], "tx": st["down"], "name": names.get(uid, "")}
        )
    return {"rx": rx, "tx": tx, "total": len(clients), "online": 0,
            "parts": ["xray"], "known": [("xray", c.client_id) for c in clients]}, rows


async def _sample_server(
    server: Server, key_path, timeout: int, hostkey_changed: set[int]
) -> dict | None:
    try:
        # ЖЁСТКИЙ таймаут на весь сбор с ноды: connect_timeout покрывает только
        # TCP-хендшейк, а последующие docker exec/wg show могут зависнуть (I/O-
        # сталл, зависший докер) и без таймаута заморозить весь gather — одна
        # плохая нода парализовала бы мониторинг всех остальных.
        async with asyncio.timeout(max(timeout * 4, 30)):
            async with sshops.connect(
                server.host, server.ssh_port, server.ssh_user, key_path, timeout
            ) as conn:
                agg = dict(_ZERO)
                client_rows: list[dict] = []
                parts: set[str] = set()
                known: list[tuple[str, str]] = []
                for part in (_awg_part, _openvpn_part, _xray_part):
                    try:
                        totals, cl = await part(conn, server.host)
                    except Exception:  # noqa: BLE001 — протокола нет / ошибка чтения
                        continue
                    for k in agg:
                        agg[k] += totals[k]
                    parts.update(totals.get("parts") or [part.__name__])
                    known.extend(totals.get("known") or [])
                    client_rows.extend(cl)
                try:
                    res = await nodestat.read_resources(conn)
                except Exception:  # noqa: BLE001 — ресурсы не критичны
                    res = None
                # живой список контейнеров — чтобы удаление протокола извне
                # (через десктоп-клиент/руками) отражалось без ручной «Проверки»
                try:
                    check = await sshops.probe_containers(conn)
                except Exception:  # noqa: BLE001 — список не критичен
                    check = None
                # адрес выхода клиентов - раз в EGRESS_TTL (ходит во внешний сервис)
                egress = None
                if (
                    check is not None
                    and check.amnezia_containers
                    and server_ops.egress_due(server, datetime.now(timezone.utc))
                ):
                    try:
                        egress = await sshops.probe_egress(conn)
                    except Exception:  # noqa: BLE001 — не критично
                        egress = None
    except sshops.HostKeyChangedError:
        # host-ключ ноды не совпал — сигналим наверх (возможен MITM/подмена)
        hostkey_changed.add(server.id)
        return None
    except Exception:  # noqa: BLE001 — сервер офлайн/завис, пропускаем
        return None
    return {
        "server_id": server.id,
        "rx_total": agg["rx"],
        "tx_total": agg["tx"],
        "clients_total": agg["total"],
        "clients_online": agg["online"],
        "resources": res,
        "clients": client_rows,
        "parts": frozenset(parts),
        "known": known,  # все клиенты на ноде, не только с трафиком
        "check": check,  # CheckResult | None (None = docker не ответил, не трогаем список)
        "egress": egress,  # str | None (None = в этот раз не спрашивали)
    }


async def collect_once(
    session_factory: async_sessionmaker[AsyncSession], settings: Settings
) -> int:
    ensure_panel_key(settings.data_dir)
    key_path, _pub = key_paths(settings.data_dir)
    async with session_factory() as session:
        servers = list(await session.scalars(select(Server)))

    hostkey_changed: set[int] = set()
    results = await asyncio.gather(
        *[
            _sample_server(s, key_path, settings.ssh_connect_timeout, hostkey_changed)
            for s in servers
        ]
    )
    names = {s.id: s.name for s in servers}
    samples = [r for r in results if r is not None]
    stable = []
    for s in samples:
        prev = _last_parts.get(s["server_id"])
        parts = s.get("parts", frozenset())
        _last_parts[s["server_id"]] = parts
        if prev is None or prev == parts:
            stable.append(s)
    if samples:
        if stable:
            async with session_factory() as session:
                session.add_all(
                    TrafficSample(
                        server_id=s["server_id"],
                        rx_total=s["rx_total"],
                        tx_total=s["tx_total"],
                        clients_total=s["clients_total"],
                        clients_online=s["clients_online"],
                    )
                    for s in stable
                )
                await session.commit()
        try:
            await _store_node_metrics(session_factory, settings, samples, names)
        except Exception:  # noqa: BLE001 — метрики нод не критичны
            log.exception("ошибка сохранения ресурсов нод")
        try:
            await _store_client_samples(session_factory, samples)
        except Exception:  # noqa: BLE001 — пер-клиентская стата не критична
            log.exception("ошибка сохранения трафика клиентов")
        try:
            await _store_client_names(session_factory, samples)
        except Exception:  # noqa: BLE001 — кэш имён не критичен
            log.exception("ошибка сохранения имён клиентов")

    # страна по IP (для флажка на карточке) — разово для серверов без country
    need_geo = [s for s in servers if not (s.country or "")]
    geo_map: dict[int, str] = {}
    if need_geo:
        codes = await asyncio.gather(
            *[geo.country_code(s.host) for s in need_geo], return_exceptions=True
        )
        geo_map = {
            s.id: c for s, c in zip(need_geo, codes) if isinstance(c, str) and c
        }

    # адрес выхода клиентов (схема каскада на карточке) - только где спрашивали
    host_of = {s.id: s.host for s in servers}
    asked = [r for r in samples if r.get("egress") is not None]
    egress_map: dict[int, dict[str, str] | None] = {}
    if asked:
        descs = await asyncio.gather(
            *[server_ops.describe_egress(host_of[r["server_id"]], r["egress"]) for r in asked],
            return_exceptions=True,
        )
        egress_map = {
            r["server_id"]: (d if not isinstance(d, BaseException) else None)
            for r, d in zip(asked, descs)
        }

    # алерты о падении/восстановлении: online = удалось снять метрики
    online_map = {s.id: r is not None for s, r in zip(servers, results)}
    # свежий список контейнеров по каждому серверу, где docker надёжно ответил
    # (check.docker=True). Пустой список — валидное «протоколов нет» (контейнер
    # удалили извне). None/docker=False — не трогаем прежний список (транзиентный
    # сбой не должен спрятать вкладки протоколов).
    check_map: dict[int, str] = {}
    for s, r in zip(servers, results):
        chk = r.get("check") if r else None
        if chk is not None and chk.docker:
            check_map[s.id] = json.dumps(chk.as_dict(), ensure_ascii=False)
    # отражаем живой online/offline прямо на карточке сервера, чтобы упавшая нода
    # краснела без ручной «Проверки», и обновляем список контейнеров (вкладки
    # протоколов), чтобы удалённый извне протокол пропадал автоматически.
    if online_map:
        try:
            now = datetime.now(timezone.utc)
            async with session_factory() as session:
                rows = await session.scalars(
                    select(Server).where(Server.id.in_(online_map))
                )
                for srv in rows:
                    srv.last_check_ok = online_map[srv.id]
                    srv.last_check_at = now
                    if geo_map.get(srv.id):
                        srv.country = geo_map[srv.id]
                    if srv.id in check_map:
                        srv.last_check_info = check_map[srv.id]
                    if srv.id in egress_map:
                        server_ops.apply_egress(srv, egress_map[srv.id], now)
                await session.commit()
        except Exception:  # noqa: BLE001 — статус карточки не критичен
            log.exception("ошибка обновления статуса серверов")
    if online_map:
        try:
            async with session_factory() as session:
                await alerts.reconcile(session, settings, online_map, names)
        except Exception:  # noqa: BLE001 — алерты не должны ронять сбор метрик
            log.exception("ошибка сверки статусов серверов")
        try:
            await onlinedrop.check(session_factory, settings, online_map, names)
        except Exception:  # noqa: BLE001
            log.exception("ошибка проверки просадки онлайна")
    try:
        await _handle_hostkey_alerts(
            session_factory, settings, hostkey_changed, online_map, names
        )
    except Exception:  # noqa: BLE001
        log.exception("ошибка обработки смены host-ключей")
    return len(samples)


async def _handle_hostkey_alerts(
    session_factory, settings: Settings, hostkey_changed: set[int],
    online_map: dict[int, bool], names: dict[int, str],
) -> None:
    """Однократный security-алерт о смене host-ключа ноды (возможен MITM)."""
    # нода снова успешно подключилась (ключ совпал) — разрешаем алертить заново
    for sid, online in online_map.items():
        if online:
            _hostkey_alerted.discard(sid)
    fresh = [sid for sid in hostkey_changed if sid not in _hostkey_alerted]
    if not fresh:
        return
    async with session_factory() as session:
        for sid in fresh:
            _hostkey_alerted.add(sid)
            name = names.get(sid, str(sid))
            await audit.record(session, "система", "host_key_changed", name)
            await alerts.security_alert(
                session, settings,
                alerts.Card(
                    "crit", "🔑", alerts.t("Сменился SSH-ключ сервера"),
                    alerts.t(
                        "возможна подмена. Если сервер пересоздавали, удалите его строку "
                        "из data/ssh/known_hosts"
                    ),
                    subject=name,
                ),
            )


async def _store_client_samples(session_factory, samples) -> None:
    """Пишет снимок трафика по каждому клиенту (там, где протокол его отдаёт)."""
    now = datetime.now(timezone.utc)
    rows = []
    for s in samples:
        for c in s.get("clients", []):
            rows.append(
                ClientTrafficSample(
                    server_id=s["server_id"],
                    protocol=c["protocol"],
                    client_id=c["client_id"],
                    rx=c["rx"],
                    tx=c["tx"],
                    ts=now,
                )
            )
    if rows:
        async with session_factory() as session:
            session.add_all(rows)
            await session.commit()


async def _store_client_names(session_factory, samples) -> None:
    """Апсертит имена клиентов (из clientsTable ноды) в кэш ClientName — чтобы
    статистика показывала имена и для клиентов, созданных не через панель.
    Имена клиентов, которых больше нет на ноде, удаляет: иначе поиск показывал
    давно отозванных. Удаляем только по протоколам, которые прочитались."""
    wanted: dict[tuple[int, str, str], str] = {}
    present: set[tuple[int, str, str]] = set()
    read_ok: set[tuple[int, str]] = set()
    for s in samples:
        sid = s["server_id"]
        for part in s.get("parts", ()):
            read_ok.add((sid, part.split(":", 1)[0]))
        for proto, cid in s.get("known", ()):
            present.add((sid, proto, cid))
        for c in s.get("clients", []):
            present.add((sid, c["protocol"], c["client_id"]))
            name = (c.get("name") or "").strip()
            if not name or name == "—":
                continue
            wanted[(sid, c["protocol"], c["client_id"])] = name[:128]
    server_ids = {k[0] for k in wanted} | {k[0] for k in read_ok}
    if not server_ids:
        return
    async with session_factory() as session:
        existing = {
            (r.server_id, r.protocol, r.client_id): r
            for r in await session.scalars(
                select(ClientName).where(ClientName.server_id.in_(server_ids))
            )
        }
        for key, row in existing.items():
            if (key[0], key[1]) in read_ok and key not in present:
                await session.delete(row)
        for (sid, proto, cid), name in wanted.items():
            row = existing.get((sid, proto, cid))
            if row is None:
                session.add(
                    ClientName(
                        server_id=sid, protocol=proto, client_id=cid, name=name
                    )
                )
            elif row.name != name:
                row.name = name
        await session.commit()


async def _store_node_metrics(session_factory, settings: Settings, samples, names):
    """Апсерт снимка ресурсов нод + алерт о нехватке места (с гистерезисом)."""
    now = datetime.now(timezone.utc)
    disk_alerts: list[tuple[int, bool, int]] = []  # (server_id, over_threshold, pct)
    th = settings.disk_alert_percent
    async with session_factory() as session:
        for s in samples:
            res = s.get("resources")
            if res is None:
                continue
            sid = s["server_id"]
            pct = round(res.disk_used / res.disk_total * 100) if res.disk_total else 0
            row = await session.get(NodeMetric, sid)
            prev_alerted = row.disk_alerted if row else False
            new_alerted = prev_alerted
            if th > 0 and pct >= th and not prev_alerted:
                new_alerted = True
                disk_alerts.append((sid, True, pct))
            elif prev_alerted and (th <= 0 or pct < th - 5):
                new_alerted = False
                disk_alerts.append((sid, False, pct))
            if row is None:
                row = NodeMetric(server_id=sid)
                session.add(row)
            row.cpu_count = res.cpu_count
            row.load1 = res.load1
            row.mem_total = res.mem_total
            row.mem_used = res.mem_used
            row.disk_total = res.disk_total
            row.disk_used = res.disk_used
            row.uptime_seconds = res.uptime_seconds
            row.disk_alerted = new_alerted
            row.ts = now
        await session.commit()

    if not disk_alerts:
        return
    async with session_factory() as session:
        cfg = await settings_store.get_alert_config(session, settings)
    if not alerts.alerts_enabled(cfg):
        return
    for sid, over, pct in disk_alerts:
        name = names.get(sid, str(sid))
        card = (
            alerts.Card("warn", "💾", alerts.t("Мало места: диск занят на {pct}%", pct=pct),
                        subject=name)
            if over
            else alerts.Card("ok", "💾", alerts.t("Место на диске снова есть"),
                             alerts.t("занято {pct}%", pct=pct), subject=name)
        )
        await alerts.send_card(cfg, settings, card)


async def _prune(session_factory, settings: Settings) -> None:
    cutoff = datetime.now(timezone.utc) - timedelta(days=settings.stats_retention_days)
    client_cutoff = datetime.now(timezone.utc) - timedelta(
        days=settings.client_stats_retention_days
    )
    async with session_factory() as session:
        await session.execute(
            delete(TrafficSample).where(TrafficSample.ts < cutoff)
        )
        await session.execute(
            delete(ClientTrafficSample).where(ClientTrafficSample.ts < client_cutoff)
        )
        # журнал пишут и неудачные входы без авторизации, без срока он растет
        if settings.audit_retention_days > 0:
            audit_cutoff = datetime.now(timezone.utc) - timedelta(
                days=settings.audit_retention_days
            )
            await session.execute(delete(AuditLog).where(AuditLog.ts < audit_cutoff))
        await session.commit()


async def collector_loop(
    session_factory: async_sessionmaker[AsyncSession], settings: Settings
) -> None:
    if settings.stats_interval <= 0:
        log.info("сбор метрик выключен (stats_interval=0)")
        return
    # первый снимок сразу, потом по интервалу
    while True:
        try:
            n = await collect_once(session_factory, settings)
            log.info("собрано метрик с %d серверов", n)
            await _prune(session_factory, settings)
        except Exception:  # noqa: BLE001 — цикл не должен падать
            log.exception("ошибка сбора метрик")
        await asyncio.sleep(settings.stats_interval)
