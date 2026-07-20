from datetime import datetime, timedelta, timezone

import httpx
import pytest

from app import alerts, config, settings_store
from app.db import Base, create_engine_and_factory

# «сейчас» и момент заведомо позже порога недоступности — антидребезг теперь
# ВРЕМЕННОЙ (server_down_minutes), состояние в БД, а не в памяти модуля
NOW = datetime(2026, 7, 17, 12, 0, tzinfo=timezone.utc)
LATER = NOW + timedelta(minutes=31)


@pytest.fixture
async def session(tmp_path, monkeypatch):
    db_path = (tmp_path / "al.db").as_posix()
    config.get_settings.cache_clear()
    engine, factory = create_engine_and_factory(f"sqlite+aiosqlite:///{db_path}")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with factory() as s:
        yield s
    await engine.dispose()
    config.get_settings.cache_clear()


async def test_reconcile_alerts_on_transition(session, monkeypatch):
    settings = config.get_settings()
    await settings_store.set_alert_config(session, "TOKEN", "123", "")

    sent: list[str] = []

    async def fake_send(cfg, text, *, html_text=None):
        sent.append(text)
        return []

    monkeypatch.setattr(alerts, "send_alert", fake_send)

    names = {1: "n1"}
    # первое наблюдение — только фиксируем статус, без алерта
    assert await alerts.reconcile(session, settings, {1: True}, names, now=NOW) == []
    assert sent == []
    # офлайн замечен, но порог (30 мин) ещё не выбран — молчим
    assert await alerts.reconcile(session, settings, {1: False}, names, now=NOW) == []
    assert sent == []
    # всё ещё офлайн через минуту — по-прежнему блип, не алертим
    assert await alerts.reconcile(
        session, settings, {1: False}, names, now=NOW + timedelta(minutes=1)
    ) == []
    assert sent == []
    # недоступен непрерывно дольше порога — вот теперь падение
    assert await alerts.reconcile(
        session, settings, {1: False}, names, now=LATER
    ) == [(1, False)]
    assert len(sent) == 1 and "недоступен" in sent[0]
    # восстановился — алерт сразу (без задержки)
    assert await alerts.reconcile(session, settings, {1: True}, names, now=LATER) == [
        (1, True)
    ]
    assert len(sent) == 2 and "онлайн" in sent[1]


async def test_reconcile_debounces_flapping_offline(session, monkeypatch):
    """Регресс на спам: нода «моргает» (офлайн 2 мин → онлайн) часами — ни одного
    алерта, т.к. непрерывной недоступности дольше порога так и не набралось."""
    settings = config.get_settings()
    await settings_store.set_alert_config(session, "TOKEN", "123", "")
    sent: list[str] = []

    async def fake_send(cfg, text, *, html_text=None):
        sent.append(text)
        return []

    monkeypatch.setattr(alerts, "send_alert", fake_send)

    names = {1: "n1"}
    await alerts.reconcile(session, settings, {1: True}, names, now=NOW)
    # 10 циклов «упал на 2 минуты и вернулся» подряд — таймер каждый раз обнуляется
    t = NOW
    for _ in range(10):
        t += timedelta(minutes=9)
        assert await alerts.reconcile(session, settings, {1: False}, names, now=t) == []
        t += timedelta(minutes=2)
        assert await alerts.reconcile(session, settings, {1: True}, names, now=t) == []
    assert sent == []  # за полтора часа моргания — тишина, дежурного не будим


async def test_reconcile_no_alert_when_unconfigured(session, monkeypatch):
    settings = config.get_settings()

    sent: list[str] = []

    async def fake_send(cfg, text, *, html_text=None):
        sent.append(text)
        return []

    monkeypatch.setattr(alerts, "send_alert", fake_send)

    names = {1: "n1"}
    await alerts.reconcile(session, settings, {1: True}, names, now=NOW)
    # переход (после порога недоступности) есть, но каналы не настроены → send не зовём
    await alerts.reconcile(session, settings, {1: False}, names, now=NOW)
    assert await alerts.reconcile(
        session, settings, {1: False}, names, now=LATER
    ) == [(1, False)]
    assert sent == []


async def test_down_alert_carries_panel_link(session, monkeypatch):
    """В алерте должна быть ссылка на панель: в Telegram — кликабельным именем
    (HTML), вебхуку — отдельной строкой. Имя экранируется."""
    settings = config.get_settings()
    settings.panel_url = "https://acontrol.example/"
    await settings_store.set_alert_config(session, "TOKEN", "123", "")
    sent: list[tuple[str, str | None]] = []

    async def fake_send(cfg, text, *, html_text=None):
        sent.append((text, html_text))
        return []

    monkeypatch.setattr(alerts, "send_alert", fake_send)

    names = {1: "srv<&>"}
    await alerts.reconcile(session, settings, {1: True}, names, now=NOW)
    await alerts.reconcile(session, settings, {1: False}, names, now=NOW)
    assert await alerts.reconcile(
        session, settings, {1: False}, names, now=LATER
    ) == [(1, False)]

    plain, html_text = sent[0]
    assert "https://acontrol.example" in plain  # вебхуку — ссылка строкой
    assert '<a href="https://acontrol.example">' in html_text  # TG — кликабельно
    assert "srv&lt;&amp;&gt;" in html_text  # имя экранировано
    assert "больше 30 мин" in plain  # видно, что это не блип


async def test_alerts_api_roundtrip(
    client: httpx.AsyncClient, auth_headers: dict[str, str]
):
    r = await client.get("/api/alerts", headers=auth_headers)
    assert r.status_code == 200
    assert r.json()["enabled"] is False

    r = await client.put(
        "/api/alerts",
        headers=auth_headers,
        json={"telegram_token": "", "telegram_chat": "", "webhook": "https://ex/hook"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["enabled"] is True
    assert body["webhook"] == "https://ex/hook"

    r = await client.get("/api/alerts", headers=auth_headers)
    assert r.json()["webhook"] == "https://ex/hook"


async def test_alerts_test_requires_config(
    client: httpx.AsyncClient, auth_headers: dict[str, str]
):
    r = await client.post("/api/alerts/test", headers=auth_headers)
    assert r.status_code == 400
