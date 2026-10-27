"""Алерт «на ноде пропали клиенты»: нода отвечает, но активных клиентов за
последние 2 часа намного меньше, чем в то же время неделю назад.

Так выглядит блокировка адреса ноды у провайдеров: SSH и сбор метрик живы,
а клиенты подключиться не могут, и алерт о падении сервера молчит. Сравниваем
с тем же окном неделю назад, а не со вчера: в выходные клиентов и так меньше.

Активный клиент - тот, у кого за окно менялся счетчик rx. Считаем агрегатом в
БД (group by клиент), историю в память не грузим: снимков миллионы."""

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select

from app import alerts, settings_store
from app.config import Settings
from app.models import ClientTrafficSample

log = logging.getLogger("acontrol.onlinedrop")

WINDOW = timedelta(hours=2)
WEEK = timedelta(days=7)
CHECK_EVERY = timedelta(minutes=30)
# сколько проверок подряд условие должно держаться (и для алерта, и для отбоя):
# одиночный провал онлайна дежурного не будит
CONFIRM = 2
# какая доля снимков сбора должна быть в текущем окне: без этого панель, которая
# сама лежала пару часов, после старта увидела бы «пустую» ноду
MIN_COVERAGE = 0.5

# server_id -> {"hits": проверок подряд с просадкой, "ok": подряд без нее,
#               "alerted": отправлен ли алерт}
_state: dict[int, dict] = {}
_last_check: datetime | None = None


async def _active_counts(session, start: datetime, end: datetime) -> dict[int, int]:
    """server_id -> сколько клиентов меняли rx в окне [start, end)."""
    per_client = (
        select(ClientTrafficSample.server_id)
        .where(ClientTrafficSample.ts >= start, ClientTrafficSample.ts < end)
        .group_by(
            ClientTrafficSample.server_id,
            ClientTrafficSample.protocol,
            ClientTrafficSample.client_id,
        )
        .having(func.max(ClientTrafficSample.rx) > func.min(ClientTrafficSample.rx))
        .subquery()
    )
    rows = await session.execute(
        select(per_client.c.server_id, func.count()).group_by(per_client.c.server_id)
    )
    return {sid: n for sid, n in rows.all()}


async def _coverage(session, start: datetime, end: datetime) -> dict[int, int]:
    """server_id -> сколько циклов сбора записано в окне (у одного цикла один ts)."""
    rows = await session.execute(
        select(
            ClientTrafficSample.server_id,
            func.count(func.distinct(ClientTrafficSample.ts)),
        )
        .where(ClientTrafficSample.ts >= start, ClientTrafficSample.ts < end)
        .group_by(ClientTrafficSample.server_id)
    )
    return {sid: n for sid, n in rows.all()}


def _dropped(now_n: int, base_n: int, percent: int, min_clients: int) -> bool:
    return base_n >= min_clients and now_n * 100 <= base_n * percent


async def check(
    session_factory,
    settings: Settings,
    online_map: dict[int, bool],
    names: dict[int, str],
    *,
    now: datetime | None = None,
) -> list[tuple[int, bool]]:
    """Раз в CHECK_EVERY сверяет онлайн нод с прошлой неделей и шлет алерты.
    Возвращает переходы (server_id, просел) - для тестов."""
    global _last_check
    percent = settings.online_drop_percent
    if percent <= 0:
        return []
    now = now or datetime.now(timezone.utc)
    if _last_check is not None and now - _last_check < CHECK_EVERY:
        return []
    _last_check = now

    async with session_factory() as session:
        cur = await _active_counts(session, now - WINDOW, now)
        base = await _active_counts(session, now - WEEK - WINDOW, now - WEEK)
        cover = await _coverage(session, now - WINDOW, now)
    expected = WINDOW.total_seconds() / max(settings.stats_interval, 60)

    transitions: list[tuple[int, bool]] = []
    for sid, online in online_map.items():
        st = _state.setdefault(sid, {"hits": 0, "ok": 0, "alerted": False})
        if not online or cover.get(sid, 0) < expected * MIN_COVERAGE:
            # нода лежит (про это свой алерт) или данных мало - не судим
            continue
        if _dropped(cur.get(sid, 0), base.get(sid, 0), percent,
                    settings.online_drop_min_clients):
            st["hits"] += 1
            st["ok"] = 0
            if not st["alerted"] and st["hits"] >= CONFIRM:
                st["alerted"] = True
                transitions.append((sid, True))
        else:
            st["ok"] += 1
            st["hits"] = 0
            if st["alerted"] and st["ok"] >= CONFIRM:
                st["alerted"] = False
                transitions.append((sid, False))
    for sid in list(_state):
        if sid not in online_map:
            del _state[sid]

    if not transitions:
        return transitions
    async with session_factory() as session:
        cfg = await settings_store.get_alert_config(session, settings)
    if not alerts.alerts_enabled(cfg):
        return transitions
    for sid, dropped in transitions:
        name = names.get(sid, str(sid))
        now_n, base_n = cur.get(sid, 0), base.get(sid, 0)
        if dropped:
            text = (
                f"📉 На сервере «{name}» пропали клиенты: активных за 2 часа {now_n}, "
                f"неделю назад в это время {base_n}. Сервер отвечает - возможно, "
                f"его адрес режут у провайдеров"
            )
        else:
            text = (
                f"✅ На сервере «{name}» клиенты вернулись: активных за 2 часа "
                f"{now_n}, неделю назад {base_n}"
            )
        await alerts.send_alert(cfg, text)
    return transitions
