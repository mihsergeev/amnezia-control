"""Алерт «каскад не работает»: оба сервера отвечают по SSH, а трафик клиентов
через выход не идет. Так выглядит заблокированный GRE, упавший шлюз на входе,
сломанный выпуск в интернет на выходе - алерт о падении сервера тут молчит.

Раз в пару минут на входе запускается та же проверка, что и кнопка «Каскад:
проверить канал»: шлюз, туннель, tproxy и адрес выхода через шлюз. Алерт - только
когда отказ держится непрерывно дольше cascade_down_minutes, и один на аварию;
когда каскад снова работает - сообщение об этом. Состояние лежит в
cascades.result["health"], рестарт панели алерт не повторяет.

Вход недоступен по SSH - каскад не проверяем и состояние не трогаем: об этом
скажет алерт о сервере."""

import asyncio
import json
import logging
from datetime import datetime, timedelta, timezone
from html import escape

from sqlalchemy import select

from app import alerts, cascade, cascadejob, nodelock, settings_store
from app.config import Settings
from app.models import Cascade, Server

log = logging.getLogger("acontrol.cascadewatch")

CHECK_EVERY = 120
# после старта панели даем ей подняться и не проверяем сразу
START_DELAY = 60


async def _ssh_check(entry: Server, settings: Settings) -> str:
    async with nodelock.connect("cascade", entry.id, cascadejob.connect(entry, settings)) as conn:
        r = await conn.run(cascade.build_check_command(), check=False, timeout=90)
    return r.stdout if isinstance(r.stdout, str) else ""


def _since(health: dict, now: datetime) -> datetime:
    try:
        at = datetime.fromisoformat(health["since"])
    except (KeyError, TypeError, ValueError):
        return now
    return at if at.tzinfo else at.replace(tzinfo=timezone.utc)


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
    pair = f"{entry} → {exit_}"
    if event == "down":
        tail = f" не работает больше {mins} мин: {reason}"
        icon = "🔴"
    else:
        tail = " снова работает"
        icon = "✅"
    text = f"{icon} Каскад «{pair}»{tail}"
    html_text = None
    panel = (getattr(settings, "panel_url", "") or "").rstrip("/")
    if panel:
        html_text = f'{icon} Каскад «<a href="{escape(panel)}">{escape(pair)}</a>»{escape(tail)}'
        text = f"{text}\n{panel}"
    await alerts.send_alert(cfg, text, html_text=html_text)


async def watch_once(session_factory, settings: Settings, *, now: datetime | None = None,
                     check=None) -> None:
    """Одна проверка всех готовых каскадов. check(entry) -> вывод проверки (для тестов)."""
    check = check or (lambda entry: _ssh_check(entry, settings))
    grace = timedelta(minutes=max(0, settings.cascade_down_minutes))
    async with session_factory() as session:
        rows = list(await session.scalars(select(Cascade).where(Cascade.status == "ready")))
        names = dict((await session.execute(select(Server.id, Server.name))).all())
        for c in rows:
            entry = await session.get(Server, c.entry_server_id)
            if entry is None or cascadejob.running(c.id):
                continue
            try:
                out = await check(entry)
            except Exception as exc:  # noqa: BLE001 - вход недоступен: скажет алерт о сервере
                log.info("каскад %s: вход не проверить: %s", c.id, exc)
                continue
            kv = cascade.parse_kv(out)
            res = cascade.check_result(kv)
            ok, reason = cascade.health(c.transport, kv, res)
            stamp = now or datetime.now(timezone.utc)
            result = json.loads(c.result or "{}")
            health, event = next_health(result.get("health") or {}, ok, reason, stamp, grace)
            result["health"] = health
            if res["egress"]:
                result.update(res, checked_at=stamp.isoformat())
            c.result = json.dumps(result)
            await session.commit()
            if event:
                await _send(
                    session, settings, names.get(c.entry_server_id, "?"),
                    names.get(c.exit_server_id, "?"), event, reason,
                    settings.cascade_down_minutes,
                )


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
