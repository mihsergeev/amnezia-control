"""Алерт «на ноде пропали клиенты»: нода отвечает, но активных клиентов за
последние 2 часа намного меньше, чем в то же время вчера И неделю назад.

Так выглядит блокировка адреса ноды у провайдеров: SSH и сбор метрик живы,
а клиенты подключиться не могут, и алерт о падении сервера молчит.

База - меньшее из «вчера» и «неделю назад» в том же окне: алертим только про
новую просадку. Если клиентов меньше уже со вчера (их перевели на другой
сервер, адрес режут давно), это не новость и дежурного не будит. Неделя
назад нужна из-за выходных: в субботу клиентов и так меньше, чем в пятницу.

Один алерт на просадку: флаг в server_status (рестарт панели не шлет его
заново), повтор по тому же серверу не раньше чем через сутки, сообщения
«клиенты вернулись» нет - на него реагировать не нужно.

Активный клиент - тот, у кого за окно менялся счетчик rx. Считаем агрегатом в
БД (group by клиент), историю в память не грузим: снимков миллионы."""

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select

from app import alerts, settings_store
from app.config import Settings
from app.models import ClientTrafficSample, ServerStatus

log = logging.getLogger("acontrol.onlinedrop")

WINDOW = timedelta(hours=2)
DAY = timedelta(days=1)
WEEK = timedelta(days=7)
# повторный алерт по тому же серверу - не чаще раза в сутки (просадка у порога
# то уходит, то возвращается)
COOLDOWN = timedelta(hours=24)
CHECK_EVERY = timedelta(minutes=30)
# сколько проверок подряд условие должно держаться (и для алерта, и для отбоя):
# одиночный провал онлайна дежурного не будит
CONFIRM = 2
# какая доля снимков сбора должна быть в текущем окне: без этого панель, которая
# сама лежала пару часов, после старта увидела бы «пустую» ноду
MIN_COVERAGE = 0.5

# server_id -> {"hits": проверок подряд с просадкой, "ok": подряд без нее};
# отправлен ли алерт - в server_status (drop_alerted), чтобы пережить рестарт
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
    """Раз в CHECK_EVERY сверяет онлайн нод со вчера и прошлой неделей и шлет
    алерты. Возвращает переходы (server_id, просел): True - алерт отправлен,
    False - просадка закончилась (молча) - для тестов."""
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
        yday = await _active_counts(session, now - DAY - WINDOW, now - DAY)
        week = await _active_counts(session, now - WEEK - WINDOW, now - WEEK)
        cover = await _coverage(session, now - WINDOW, now)
    expected = WINDOW.total_seconds() / max(settings.stats_interval, 60)

    judged: dict[int, bool] = {}
    for sid, online in online_map.items():
        st = _state.setdefault(sid, {"hits": 0, "ok": 0})
        if not online or cover.get(sid, 0) < expected * MIN_COVERAGE:
            # нода лежит (про это свой алерт) или данных мало - не судим
            continue
        base = min(yday.get(sid, 0), week.get(sid, 0))
        if _dropped(cur.get(sid, 0), base, percent, settings.online_drop_min_clients):
            st["hits"] += 1
            st["ok"] = 0
            if st["hits"] >= CONFIRM:
                judged[sid] = True
        else:
            st["ok"] += 1
            st["hits"] = 0
            if st["ok"] >= CONFIRM:
                judged[sid] = False
    for sid in list(_state):
        if sid not in online_map:
            del _state[sid]
    if not judged:
        return []

    transitions: list[tuple[int, bool]] = []
    to_send: list[int] = []
    async with session_factory() as session:
        rows = {
            r.server_id: r
            for r in await session.scalars(
                select(ServerStatus).where(ServerStatus.server_id.in_(judged))
            )
        }
        for sid, dropped in judged.items():
            row = rows.get(sid)
            if row is None:
                row = ServerStatus(server_id=sid, online=True, changed_at=now)
                session.add(row)
            if dropped and not row.drop_alerted:
                row.drop_alerted = True
                last = row.drop_alerted_at
                if last is not None and last.tzinfo is None:
                    last = last.replace(tzinfo=timezone.utc)
                if last is None or now - last >= COOLDOWN:
                    row.drop_alerted_at = now
                    to_send.append(sid)
                    transitions.append((sid, True))
            elif not dropped and row.drop_alerted:
                row.drop_alerted = False
                transitions.append((sid, False))
        await session.commit()

    if not to_send:
        return transitions
    async with session_factory() as session:
        cfg = await settings_store.get_alert_config(session, settings)
    if not alerts.alerts_enabled(cfg):
        return transitions
    for sid in to_send:
        name = names.get(sid, str(sid))
        text = (
            f"📉 На сервере «{name}» пропали клиенты: активных за 2 часа "
            f"{cur.get(sid, 0)}, в это время вчера {yday.get(sid, 0)}, неделю назад "
            f"{week.get(sid, 0)}. Сервер отвечает - возможно, его адрес режут у "
            f"провайдеров"
        )
        await alerts.send_alert(cfg, text)
    return transitions
