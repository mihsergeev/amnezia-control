import pytest
from sqlalchemy import select

from app import collector, config
from app.db import Base, create_engine_and_factory
from app.models import ClientTrafficSample


@pytest.fixture
async def factory(tmp_path, monkeypatch):
    monkeypatch.setenv("VPNPANEL_DATA_DIR", (tmp_path / "data").as_posix())
    config.get_settings.cache_clear()
    engine, f = create_engine_and_factory(
        f"sqlite+aiosqlite:///{(tmp_path / 'c.db').as_posix()}"
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield f
    await engine.dispose()
    config.get_settings.cache_clear()


async def test_store_client_samples_writes_rows(factory):
    samples = [
        {
            "server_id": 1,
            "clients": [
                {"protocol": "awg", "client_id": "PUB=", "rx": 10, "tx": 20},
                {"protocol": "openvpn", "client_id": "abc", "rx": 5, "tx": 7},
            ],
        },
        {"server_id": 2, "clients": []},  # xray/без данных — ничего не пишем
    ]
    await collector._store_client_samples(factory, samples)
    async with factory() as s:
        rows = list(await s.scalars(select(ClientTrafficSample)))
    assert len(rows) == 2
    awg = next(r for r in rows if r.protocol == "awg")
    assert awg.server_id == 1 and awg.client_id == "PUB=" and awg.rx == 10
