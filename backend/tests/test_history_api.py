"""Интеграционные тесты /api/stats/history: окно from/to и адаптивный шаг."""

from datetime import datetime, timedelta, timezone

import httpx
import pytest

from app import config
from app.db import Base
from app.models import TrafficSample


async def _seed(app, rows: list[tuple[int, datetime, int, int, int]]) -> None:
    async with app.state.session_factory() as s:
        for sid, ts, rx, tx, online in rows:
            s.add(
                TrafficSample(
                    server_id=sid, ts=ts, rx_total=rx, tx_total=tx,
                    clients_total=online, clients_online=online,
                )
            )
        await s.commit()


@pytest.fixture
async def app_with_samples(tmp_path, monkeypatch):
    db_path = (tmp_path / "h.db").as_posix()
    monkeypatch.setenv("VPNPANEL_DB_URL", f"sqlite+aiosqlite:///{db_path}")
    monkeypatch.setenv("VPNPANEL_DATA_DIR", (tmp_path / "data").as_posix())
    monkeypatch.setenv("VPNPANEL_ADMIN_USER", "admin")
    monkeypatch.setenv("VPNPANEL_ADMIN_PASSWORD", "testpass")
    monkeypatch.setenv(
        "VPNPANEL_JWT_SECRET", "test-secret-0123456789abcdef0123456789abcdef"
    )
    config.get_settings.cache_clear()

    from app.bootstrap import ensure_admin
    from app.main import create_app

    app = create_app()
    async with app.state.engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    await ensure_admin(app.state.session_factory, config.get_settings())
    yield app
    await app.state.engine.dispose()
    config.get_settings.cache_clear()


async def _headers(app) -> dict[str, str]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        r = await c.post(
            "/api/auth/login", json={"username": "admin", "password": "testpass"}
        )
        return {"Authorization": f"Bearer {r.json()['access_token']}"}


async def test_history_from_to_window(app_with_samples) -> None:
    app = app_with_samples
    base = datetime(2026, 7, 6, 12, 0, tzinfo=timezone.utc)
    # 4 снимка по 5 минут; окном захватываем только средние два
    rows = [
        (1, base + timedelta(minutes=i * 5), 100 * (i + 1), 0, i) for i in range(4)
    ]
    await _seed(app, rows)
    headers = await _headers(app)

    from_ms = int((base + timedelta(minutes=4)).timestamp() * 1000)
    to_ms = int((base + timedelta(minutes=11)).timestamp() * 1000)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        r = await c.get(
            f"/api/stats/history?from_ms={from_ms}&to_ms={to_ms}", headers=headers
        )
    assert r.status_code == 200
    body = r.json()
    # в окне [4м, 11м] лежат снимки на 5м и 10м → 2 точки
    assert len(body["points"]) == 2
    assert body["interval_seconds"] == 300  # узкое окно → шаг = интервалу сбора


async def test_history_long_range_coarsens_bucket(app_with_samples) -> None:
    app = app_with_samples
    headers = await _headers(app)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        r = await c.get("/api/stats/history?hours=2160", headers=headers)  # 90 дней
    assert r.status_code == 200
    # 90 дней укрупняются до 12-часовых бакетов
    assert r.json()["interval_seconds"] == 43200
