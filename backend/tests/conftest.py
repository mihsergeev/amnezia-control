from collections.abc import AsyncIterator

import httpx
import pytest

from app import config


@pytest.fixture
async def client(tmp_path, monkeypatch) -> AsyncIterator[httpx.AsyncClient]:
    db_path = (tmp_path / "test.db").as_posix()
    monkeypatch.setenv("VPNPANEL_DB_URL", f"sqlite+aiosqlite:///{db_path}")
    monkeypatch.setenv("VPNPANEL_DATA_DIR", (tmp_path / "data").as_posix())
    monkeypatch.setenv("VPNPANEL_PANEL_IP", "203.0.113.7")
    monkeypatch.setenv("VPNPANEL_ADMIN_USER", "admin")
    monkeypatch.setenv("VPNPANEL_ADMIN_PASSWORD", "testpass")
    monkeypatch.setenv("VPNPANEL_JWT_SECRET", "test-secret-0123456789abcdef0123456789abcdef")
    config.get_settings.cache_clear()

    from app.bootstrap import ensure_admin
    from app.db import Base
    from app.main import create_app

    app = create_app()
    async with app.state.engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    await ensure_admin(app.state.session_factory, config.get_settings())

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c

    await app.state.engine.dispose()
    config.get_settings.cache_clear()


@pytest.fixture(autouse=True)
def _reset_ratelimit():
    """Сбрасываем in-memory лимитер входа между тестами (глобальное состояние)."""
    from app import ratelimit

    ratelimit._failures.clear()
    yield
    ratelimit._failures.clear()


@pytest.fixture
async def auth_headers(client: httpx.AsyncClient) -> dict[str, str]:
    response = await client.post(
        "/api/auth/login", json={"username": "admin", "password": "testpass"}
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}
