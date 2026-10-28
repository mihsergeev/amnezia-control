from datetime import datetime, timedelta, timezone

import pytest

from app import alerts, config, onlinedrop, settings_store
from app.db import Base, create_engine_and_factory
from app.models import ClientTrafficSample

NOW = datetime(2026, 7, 21, 15, 0, tzinfo=timezone.utc)
STEP = timedelta(minutes=5)


@pytest.fixture
async def factory(tmp_path):
    config.get_settings.cache_clear()
    engine, factory = create_engine_and_factory(
        f"sqlite+aiosqlite:///{(tmp_path / 'od.db').as_posix()}"
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    onlinedrop._state.clear()
    onlinedrop._last_check = None
    yield factory
    onlinedrop._state.clear()
    onlinedrop._last_check = None
    await engine.dispose()
    config.get_settings.cache_clear()


@pytest.fixture
def sent(monkeypatch):
    out: list[str] = []

    async def fake_send(cfg, text, *, html_text=None):
        out.append(text)
        return []

    monkeypatch.setattr(alerts, "send_alert", fake_send)
    return out


async def _samples(factory, sid, start, end, active, silent):
    """Снимки каждые 5 минут: active клиентов качают трафик, silent стоят."""
    rows = []
    t, i = start, 0
    while t < end:
        for c in range(active):
            rows.append(ClientTrafficSample(
                server_id=sid, protocol="awg", client_id=f"a{c}", rx=1000 + i, tx=0, ts=t))
        for c in range(silent):
            rows.append(ClientTrafficSample(
                server_id=sid, protocol="awg", client_id=f"s{c}", rx=500, tx=0, ts=t))
        t += STEP
        i += 1
    async with factory() as s:
        s.add_all(rows)
        await s.commit()


async def _week_ago(factory, sid, active, until=NOW + timedelta(hours=2)):
    """Неделю назад и вчера в то же время было active клиентов (база алерта)."""
    for days in (7, 1):
        await _samples(factory, sid, NOW - timedelta(days=days, hours=3),
                       until - timedelta(days=days), active, 0)


async def _restart():
    """Рестарт панели: память модуля обнуляется, БД остается."""
    onlinedrop._state.clear()
    onlinedrop._last_check = None


async def _setup_alerts(factory):
    async with factory() as s:
        await settings_store.set_alert_config(s, "TOKEN", "123", "")


async def test_drop_alerts_once_and_recovers_silently(factory, sent):
    settings = config.get_settings()
    await _setup_alerts(factory)
    await _week_ago(factory, 1, active=12)
    # сегодня активны 2 из 12: адрес режут
    await _samples(factory, 1, NOW - timedelta(hours=3), NOW + timedelta(minutes=31), 2, 10)

    names = {1: "vpn-a"}
    assert await onlinedrop.check(factory, settings, {1: True}, names, now=NOW) == []
    assert sent == []
    later = NOW + timedelta(minutes=30)
    assert await onlinedrop.check(factory, settings, {1: True}, names, now=later) == [(1, True)]
    assert len(sent) == 1 and "Пропали клиенты" in sent[0] and "vpn-a" in sent[0]
    assert "2" in sent[0] and "12" in sent[0]

    # просадка держится - больше не пишем
    await _samples(factory, 1, later + timedelta(minutes=31), later + timedelta(hours=1), 2, 10)
    assert await onlinedrop.check(factory, settings, {1: True}, names,
                                  now=later + timedelta(minutes=30)) == []
    assert len(sent) == 1

    # клиенты вернулись: отбой после двух проверок подряд, без сообщения
    await _samples(factory, 1, later + timedelta(hours=1), later + timedelta(hours=4), 12, 0)
    t = later + timedelta(hours=3, minutes=30)
    assert await onlinedrop.check(factory, settings, {1: True}, names, now=t) == []
    t += timedelta(minutes=30)
    assert await onlinedrop.check(factory, settings, {1: True}, names, now=t) == [(1, False)]
    assert len(sent) == 1


async def test_restart_does_not_resend(factory, sent):
    """Раньше флаг жил в памяти и каждый релиз панели слал алерт заново."""
    settings = config.get_settings()
    await _setup_alerts(factory)
    await _week_ago(factory, 1, active=12, until=NOW + timedelta(hours=4))
    await _samples(factory, 1, NOW - timedelta(hours=3), NOW + timedelta(hours=4), 2, 10)
    names = {1: "vpn-a"}
    for k in range(2):
        await onlinedrop.check(factory, settings, {1: True}, names,
                               now=NOW + timedelta(minutes=30 * k))
    assert len(sent) == 1
    await _restart()
    for k in range(2, 6):
        await onlinedrop.check(factory, settings, {1: True}, names,
                               now=NOW + timedelta(minutes=30 * k))
    assert len(sent) == 1


async def test_drop_already_yesterday_is_not_news(factory, sent):
    """Клиентов меньше уже со вчера (перевели на другой сервер) - не алертим."""
    settings = config.get_settings()
    await _setup_alerts(factory)
    await _samples(factory, 1, NOW - timedelta(days=7, hours=3),
                   NOW - timedelta(days=7) + timedelta(hours=2), 12, 0)
    await _samples(factory, 1, NOW - timedelta(days=1, hours=3),
                   NOW - timedelta(days=1) + timedelta(hours=2), 2, 10)
    await _samples(factory, 1, NOW - timedelta(hours=3), NOW + timedelta(hours=2), 2, 10)
    for k in range(3):
        await onlinedrop.check(factory, settings, {1: True}, {1: "vpn-a"},
                               now=NOW + timedelta(minutes=30 * k))
    assert sent == []


async def test_repeat_drop_waits_cooldown(factory, sent):
    """Просадка у порога то уходит, то возвращается - второй алерт не раньше суток."""
    settings = config.get_settings()
    await _setup_alerts(factory)
    names = {1: "vpn-a"}
    await _week_ago(factory, 1, active=12, until=NOW + timedelta(hours=8))
    # просадка -> вернулись -> снова просадка, все за несколько часов
    await _samples(factory, 1, NOW - timedelta(hours=3), NOW + timedelta(hours=1), 2, 10)
    await _samples(factory, 1, NOW + timedelta(hours=1), NOW + timedelta(hours=4), 12, 0)
    await _samples(factory, 1, NOW + timedelta(hours=4), NOW + timedelta(hours=8), 2, 10)
    seen = []
    for k in range(16):
        seen += await onlinedrop.check(factory, settings, {1: True}, names,
                                       now=NOW + timedelta(minutes=30 * k))
    assert (1, False) in seen
    assert seen.count((1, True)) == 1
    assert len(sent) == 1


async def test_small_node_is_not_checked(factory, sent):
    """Неделю назад было 5 активных (меньше порога 8) - тишину не трактуем."""
    settings = config.get_settings()
    await _setup_alerts(factory)
    await _week_ago(factory, 1, active=5)
    await _samples(factory, 1, NOW - timedelta(hours=3), NOW + timedelta(hours=1), 0, 5)
    for k in range(3):
        await onlinedrop.check(factory, settings, {1: True}, {1: "vpn-a"},
                               now=NOW + timedelta(minutes=30 * k))
    assert sent == []


async def test_offline_node_and_missing_samples_are_skipped(factory, sent):
    settings = config.get_settings()
    await _setup_alerts(factory)
    await _week_ago(factory, 1, active=12)
    await _week_ago(factory, 2, active=12)
    # у второй ноды за 2 часа всего пара снимков: панель сама лежала
    await _samples(factory, 2, NOW - timedelta(minutes=10), NOW + timedelta(hours=1), 0, 12)
    for k in range(3):
        await onlinedrop.check(factory, settings, {1: False, 2: True},
                               {1: "vpn-a", 2: "vpn-b"}, now=NOW + timedelta(minutes=30 * k))
    # у первой снимков нет вовсе и она офлайн (про это алерт о падении);
    # у второй на NOW и NOW+30 снимков меньше половины окна, судим только с NOW+60
    assert sent == []
    assert onlinedrop._state[2]["hits"] == 1
    await onlinedrop.check(factory, settings, {1: False, 2: True}, {2: "vpn-b"},
                           now=NOW + timedelta(minutes=90))
    assert len(sent) == 1 and "vpn-b" in sent[0]
    assert onlinedrop._state[1]["hits"] == 0


async def test_disabled_and_throttled(factory, sent, monkeypatch):
    monkeypatch.setenv("VPNPANEL_ONLINE_DROP_PERCENT", "0")
    config.get_settings.cache_clear()
    settings = config.get_settings()
    await _setup_alerts(factory)
    await _week_ago(factory, 1, active=12)
    await _samples(factory, 1, NOW - timedelta(hours=3), NOW + timedelta(hours=1), 0, 12)
    for k in range(3):
        assert await onlinedrop.check(factory, settings, {1: True}, {1: "vpn-a"},
                                      now=NOW + timedelta(minutes=30 * k)) == []
    assert sent == []

    monkeypatch.setenv("VPNPANEL_ONLINE_DROP_PERCENT", "35")
    config.get_settings.cache_clear()
    settings = config.get_settings()
    await onlinedrop.check(factory, settings, {1: True}, {1: "vpn-a"}, now=NOW)
    # через 10 минут проверка не повторяется, счетчик подряд не растет
    await onlinedrop.check(factory, settings, {1: True}, {1: "vpn-a"},
                           now=NOW + timedelta(minutes=10))
    assert onlinedrop._state[1]["hits"] == 1
    await onlinedrop.check(factory, settings, {1: True}, {1: "vpn-a"},
                           now=NOW + timedelta(minutes=30))
    assert len(sent) == 1
