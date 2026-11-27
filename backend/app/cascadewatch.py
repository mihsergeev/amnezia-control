"""Алерт «каскад не работает»: оба сервера отвечают по SSH, а трафик клиентов
через выход не идет. Так выглядит заблокированный GRE, упавший шлюз на входе,
сломанный выпуск в интернет на выходе - алерт о падении сервера тут молчит.

Раз в пару минут на входе запускается та же проверка, что и кнопка «Каскад:
проверить канал»: шлюз, туннель, tproxy и адрес выхода через шлюз (скрипты входа
старой ревизии она заодно обновляет, см. cascade.run_check). Алерт - только
когда отказ держится непрерывно дольше cascade_down_minutes, и один на аварию;
когда каскад снова работает - сообщение об этом. Состояние лежит в
cascades.result["health"], рестарт панели алерт не повторяет.

Вход недоступен по SSH - каскад не проверяем и состояние не трогаем: об этом
скажет алерт о сервере."""

import asyncio
import json
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app import (alerts, cascade, cascade_awg, cascade_exit, cascade_lock, cascade_observations, cascade_routes,
                 cascadejob, geo, geo_vet, nodelock, settings_store)
from app.config import Settings
from app.models import Cascade, Server

log = logging.getLogger("acontrol.cascadewatch")

CHECK_EVERY = 120
# после старта панели даем ей подняться и не проверяем сразу
START_DELAY = 60


async def _ssh_check(entry: Server, country: str, settings: Settings) -> str:
    async with nodelock.connect("cascade", entry.id, cascadejob.connect(entry, settings)) as conn:
        return await cascade.run_check(conn, country, timeout=90)


async def ensure_awg_runtime(c: Cascade, entry: Server, exit_: Server | None, settings: Settings,
                             kv: dict[str, str], *, manual: bool = False) -> None:
    if (c.transport != "awg" or c.status != "ready" or exit_ is None or kv.get("encryption") != "awg"
            or (not manual and kv.get("awgrev") == cascade_awg.RUNTIME_REV)):
        return
    params = json.loads(c.params or "{}")
    owner = params.get("runtime_owner", "")
    # Upgrade the exit first. A new entry revision means both sides succeeded.
    try:
        for role, server in (("exit", exit_), ("entry", entry)):
            if role == "entry" and kv.get("awgrev") == cascade_awg.RUNTIME_REV:
                continue
            script = cascade_awg.upgrade_runtime(
                c.id, owner, role, scoped_exit=role == "exit" and cascade_exit.scoped(params),
            )
            async with nodelock.connect("cascade", server.id, cascadejob.connect(server, settings)) as conn:
                await conn.run(cascade_lock.wrap(c.id, script, owner, edit=True), check=True, timeout=25)
    except Exception as exc:  # noqa: BLE001 - retry on the next check
        log.warning("каскад %s: не удалось обновить восстановление AWG (%s)", c.id, type(exc).__name__)


async def _move_domain_strategy(c: Cascade, entry: Server, settings: Settings) -> None:
    """One-time move of an installed gateway to the current routing base (AsIs
    instead of IPIfNonMatch, explicit private networks instead of geoip:private),
    through the same tested in-place update as a routes change (lock, xray -test,
    restore)."""
    params = json.loads(c.params or "{}")
    owner = params.get("runtime_owner", "")
    country = (geo.normalize_country_code(params.get("entry_country_override", params.get("entry_country")))
               or geo.normalize_country_code(entry.country)) or None
    script = cascade_routes.update_script(f"{cascade.DIR}/config", cascade.GATEWAY, cascade.SOCKS_PORT,
                                          owner, params.get("routes", []), country)
    command = cascade_lock.wrap(c.id, script, owner, edit=True)
    async with nodelock.connect("cascade", entry.id, cascadejob.connect(entry, settings)) as conn:
        result = await conn.run(command, check=False, timeout=125)
    if result.exit_status == 0:
        log.info("каскад %s: правила шлюза входа обновлены", c.id)
    else:
        log.warning("каскад %s: не удалось обновить правила шлюза (код %s)", c.id, result.exit_status)


def _since(health: dict, now: datetime) -> datetime:
    try:
        at = datetime.fromisoformat(health["since"])
    except (KeyError, TypeError, ValueError):
        return now
    return at if at.tzinfo else at.replace(tzinfo=timezone.utc)


async def _push_geo_pin(c: Cascade, entry: Server, pin: str, settings: Settings) -> None:
    """Give the gateway the geo databases release the panel accepted, and fetch it
    now instead of waiting for the daily timer. The updater checks the hashes."""
    command = cascade.geo_pin_command(pin) + " && sudo systemctl start --no-block acontrol-cascade-geo.service"
    async with nodelock.connect("cascade", entry.id, cascadejob.connect(entry, settings)) as conn:
        result = await conn.run(command, check=False, timeout=60)
    if result.exit_status == 0:
        log.info("каскад %s: геобазы %s переданы шлюзу", c.id, pin.split()[0])
    else:
        log.warning("каскад %s: не удалось передать шлюзу геобазы (код %s)", c.id, result.exit_status)


def next_health(health: dict, ok: bool, reason: str, now: datetime, grace: timedelta):
    """Новое состояние и событие для алерта: "down", "up" или None."""
    if ok:
        event = "up" if health.get("alerted") else None
        return {"ok": True, "checked_at": now.isoformat()}, event
    since = _since(health, now) if health.get("ok") is False else now
    alerted = bool(health.get("alerted"))
    event = None
    if not alerted and now - since >= grace:
        alerted, event = True, "down"
    return {
        "ok": False, "reason": reason, "since": since.isoformat(),
        "alerted": alerted, "checked_at": now.isoformat(),
    }, event


async def _send(session, settings: Settings, entry: str, exit_: str, event: str,
                reason: str, mins: int) -> None:
    cfg = await settings_store.get_alert_config(session, settings)
    if not alerts.alerts_enabled(cfg):
        return
    t = alerts.t
    if event == "down":
        card = alerts.Card("crit", "", t("Каскад не работает больше {mins} мин", mins=mins),
                           t("{reason}, выход {exit}", reason=t(reason), exit=exit_), subject=entry)
    else:
        card = alerts.Card("ok", "", t("Каскад снова работает"), t("выход {exit}", exit=exit_),
                           subject=entry)
    await alerts.send_card(cfg, settings, card)


async def watch_once(session_factory, settings: Settings, *, now: datetime | None = None,
                     check=None, move_strategy=None, push_pin=None) -> None:
    """Одна проверка всех готовых каскадов. check(entry) -> вывод проверки (для тестов)."""
    grace = timedelta(minutes=max(0, settings.cascade_down_minutes))
    async with session_factory() as session:
        rows = list(await session.scalars(select(Cascade).where(Cascade.status == "ready")))
        names = dict((await session.execute(select(Server.id, Server.name))).all())
        ids = {server_id for c in rows for server_id in (c.entry_server_id, c.exit_server_id)}
        nodes = {
            s.id: s for s in await session.scalars(select(Server).where(Server.id.in_(ids)))
        } if ids else {}
        geo_pin = await geo_vet.accepted_pin(session)
    # SSH-проверка идет до 90 с: сессию БД на это время не держим (на Postgres
    # висела idle in transaction), а результат пишем в перечитанную строку -
    # каскад могли удалить или проверить вручную, пока шла наша проверка
    for c in rows:
        entry = nodes.get(c.entry_server_id)
        if entry is None or cascadejob.running(c.id):
            continue
        generation = cascade_observations.Generation.of(c)
        try:
            country = json.loads(c.params or "{}").get("entry_country") or entry.country
            out = await check(entry) if check else await _ssh_check(entry, country, settings)
        except Exception as exc:  # noqa: BLE001 - вход недоступен: скажет алерт о сервере
            log.info("каскад %s: вход не проверить: %s", c.id, exc)
            continue
        kv = cascade.parse_kv(out)
        await ensure_awg_runtime(c, entry, nodes.get(c.exit_server_id), settings, kv)
        if kv.get("dnsstrategy") == "IPIfNonMatch" or kv.get("privaterule") == "geoip":
            try:
                await (move_strategy or _move_domain_strategy)(c, entry, settings)
            except Exception as exc:  # noqa: BLE001 - the next round tries again
                log.warning("каскад %s: правила шлюза не обновлены: %s", c.id, exc)
        if geo_pin and kv.get("rev") and kv.get("gw") == "yes" and kv.get("geopin", "") != geo_pin.split()[0]:
            try:
                await (push_pin or _push_geo_pin)(c, entry, geo_pin, settings)
            except Exception as exc:  # noqa: BLE001 - the next round tries again
                log.warning("каскад %s: геобазы шлюзу не переданы: %s", c.id, exc)
        res = cascade.check_result(kv)
        ok, reason = cascade.health(c.transport, kv, res)
        stamp = now or datetime.now(timezone.utc)
        for _attempt in range(cascade_observations.WRITE_ATTEMPTS):
            async with session_factory() as session:
                fresh = await session.get(Cascade, c.id)
                if (fresh is None or cascade_observations.Generation.of(fresh) != generation
                        or cascadejob.running(c.id)):
                    break
                result = json.loads(fresh.result or "{}")
                saved_health = result.get("health") or {}
                if cascade_observations.newer_than(saved_health, stamp):
                    break
                # SSH мог идти полторы минуты: галочку успели выключить во время
                # проверки, поэтому разрешение отправки перечитываем сейчас.
                cascade_alerts = bool(await session.scalar(
                    select(Server.id).where(
                        Server.id.in_((fresh.entry_server_id, fresh.exit_server_id)),
                        Server.alerts_enabled.is_(True),
                    ).limit(1)
                ))
                health, event = next_health(saved_health if cascade_alerts else {}, ok, reason, stamp, grace)
                if not cascade_alerts:
                    # Пока обе стороны выключены, отсчет аварии не копим и не
                    # запоминаем отправленный алерт.
                    event = None
                    if not ok:
                        health["since"] = stamp.isoformat()
                        health["alerted"] = False
                result["health"] = health
                cascade_observations.merge_paths(result, res, stamp)
                if not await cascade_observations.save(session, generation, fresh.result, result):
                    continue
                await session.commit()
                if event:
                    await _send(
                        session, settings, names.get(c.entry_server_id, "?"),
                        names.get(c.exit_server_id, "?"), event, reason,
                        settings.cascade_down_minutes,
                    )
                break


async def cascade_watch_loop(session_factory, settings: Settings) -> None:
    if settings.cascade_down_minutes < 0:
        log.info("проверка каскадов выключена (cascade_down_minutes < 0)")
        return
    await asyncio.sleep(START_DELAY)
    while True:
        try:
            await watch_once(session_factory, settings)
        except Exception:  # noqa: BLE001 - цикл не должен ронять приложение
            log.exception("проверка каскадов упала")
        await asyncio.sleep(CHECK_EVERY)
