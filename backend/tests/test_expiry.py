from datetime import datetime, timedelta, timezone

import pytest

from app import config, expiry
from app.db import Base, create_engine_and_factory
from app.models import AwgConfig, ClientLimit, Server


@pytest.fixture
async def factory(tmp_path, monkeypatch):
    db_path = (tmp_path / "exp.db").as_posix()
    monkeypatch.setenv("VPNPANEL_DATA_DIR", (tmp_path / "data").as_posix())
    config.get_settings.cache_clear()
    engine, session_factory = create_engine_and_factory(
        f"sqlite+aiosqlite:///{db_path}"
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield session_factory
    await engine.dispose()
    config.get_settings.cache_clear()


async def _seed(session_factory, expires_at):
    async with session_factory() as session:
        server = Server(name="n1", host="10.0.0.1", ssh_port=22, ssh_user="acontrol")
        session.add(server)
        await session.commit()
        await session.refresh(server)
        session.add(
            AwgConfig(
                server_id=server.id, public_key="PUB=", name="c1", config="cfg"
            )
        )
        session.add(
            ClientLimit(
                server_id=server.id, protocol="awg", client_id="PUB=",
                name="c1", expires_at=expires_at,
            )
        )
        await session.commit()
        return server.id


async def test_expired_client_is_revoked(factory, monkeypatch):
    settings = config.get_settings()
    past = datetime.now(timezone.utc) - timedelta(hours=1)
    server_id = await _seed(factory, past)

    calls = []

    async def fake_revoke(server, protocol, client_id, key_path, timeout):
        calls.append((server.id, protocol, client_id))

    monkeypatch.setattr(expiry, "_revoke_ssh", fake_revoke)

    n = await expiry.expiry_once(factory, settings)

    assert n == 1
    assert calls == [(server_id, "awg", "PUB=")]
    async with factory() as session:
        assert (await session.get(ClientLimit, 1)) is None
        cfg = await session.scalars(AwgConfig.__table__.select())
        assert list(cfg) == []


async def test_future_client_is_kept(factory, monkeypatch):
    settings = config.get_settings()
    future = datetime.now(timezone.utc) + timedelta(days=7)
    await _seed(factory, future)

    monkeypatch.setattr(
        expiry, "_revoke_ssh",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("не должно вызываться")),
    )

    n = await expiry.expiry_once(factory, settings)

    assert n == 0
    async with factory() as session:
        assert (await session.get(ClientLimit, 1)) is not None


async def test_unreachable_node_keeps_limit(factory, monkeypatch):
    settings = config.get_settings()
    past = datetime.now(timezone.utc) - timedelta(hours=1)
    await _seed(factory, past)

    async def boom(*a, **k):
        raise OSError("нода недоступна")

    monkeypatch.setattr(expiry, "_revoke_ssh", boom)

    n = await expiry.expiry_once(factory, settings)

    assert n == 0
    async with factory() as session:
        # лимит остаётся — повторим на следующем цикле
        assert (await session.get(ClientLimit, 1)) is not None
