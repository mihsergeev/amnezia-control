import httpx
import pytest

from app import alerts, config, settings_store
from app.db import Base, create_engine_and_factory


@pytest.fixture(autouse=True)
def _reset_down_streak():
    """Антидребезг падений держит стрик в памяти модуля — чистим между тестами."""
    alerts._down_streak.clear()
    yield
    alerts._down_streak.clear()


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

    async def fake_send(cfg, text):
        sent.append(text)
        return []

    monkeypatch.setattr(alerts, "send_alert", fake_send)

    names = {1: "n1"}
    # первое наблюдение — только фиксируем статус, без алерта
    assert await alerts.reconcile(session, settings, {1: True}, names) == []
    assert sent == []
    # антидребезг: одиночный офлайн (по умолчанию нужно 2 подряд) НЕ алертит
    assert await alerts.reconcile(session, settings, {1: False}, names) == []
    assert sent == []
    # второй подряд офлайн — теперь падение
    assert await alerts.reconcile(session, settings, {1: False}, names) == [(1, False)]
    assert len(sent) == 1 and "недоступен" in sent[0]
    # восстановился — алерт сразу (без задержки)
    assert await alerts.reconcile(session, settings, {1: True}, names) == [(1, True)]
    assert len(sent) == 2 and "онлайн" in sent[1]


async def test_reconcile_debounces_transient_offline(session, monkeypatch):
    """Транзиентный офлайн между онлайнами не поднимает ложную тревогу."""
    settings = config.get_settings()
    await settings_store.set_alert_config(session, "TOKEN", "123", "")
    sent: list[str] = []

    async def fake_send(cfg, text):
        sent.append(text)
        return []

    monkeypatch.setattr(alerts, "send_alert", fake_send)

    names = {1: "n1"}
    await alerts.reconcile(session, settings, {1: True}, names)
    assert await alerts.reconcile(session, settings, {1: False}, names) == []  # 1 пропуск
    assert await alerts.reconcile(session, settings, {1: True}, names) == []   # снова онлайн
    # стрик сбросился — одиночный офлайн опять не алертит
    assert await alerts.reconcile(session, settings, {1: False}, names) == []
    assert sent == []


async def test_reconcile_no_alert_when_unconfigured(session, monkeypatch):
    settings = config.get_settings()

    sent: list[str] = []

    async def fake_send(cfg, text):
        sent.append(text)
        return []

    monkeypatch.setattr(alerts, "send_alert", fake_send)

    names = {1: "n1"}
    await alerts.reconcile(session, settings, {1: True}, names)
    # переход (после 2 пропусков) есть, но каналы не настроены → send не вызывается
    await alerts.reconcile(session, settings, {1: False}, names)
    assert await alerts.reconcile(session, settings, {1: False}, names) == [(1, False)]
    assert sent == []


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
