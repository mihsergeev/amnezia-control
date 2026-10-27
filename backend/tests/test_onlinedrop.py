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
    await _samples(factory, sid, NOW - timedelta(days=7, hours=3),
                   until - timedelta(days=7), active, 0)


async def _setup_alerts(factory):
    async with factory() as s:
        await settings_store.set_alert_config(s, "TOKEN", "123", "")


async def test_drop_alerts_after_two_checks_and_recovers(factory, sent):
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
    assert len(sent) == 1 and "пропали клиенты" in sent[0] and "vpn-a" in sent[0]
    assert "2" in sent[0] and "12" in sent[0]

    # клиенты вернулись: отбой тоже после двух проверок подряд
    await _samples(factory, 1, later, later + timedelta(hours=3), 12, 0)
    t = later + timedelta(hours=2, minutes=30)
    assert await onlinedrop.check(factory, settings, {1: True}, names, now=t) == []
    t += timedelta(minutes=30)
    assert await onlinedrop.check(factory, settings, {1: True}, names, now=t) == [(1, False)]
    assert len(sent) == 2 and "вернулись" in sent[1]


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
