"""Хранилище паузы: положить → перечитать → извлечь/удалить."""

import pytest

from app import config, pausestore
from app.db import Base, create_engine_and_factory


@pytest.fixture
async def session(tmp_path):
    config.get_settings.cache_clear()
    engine, factory = create_engine_and_factory(
        f"sqlite+aiosqlite:///{(tmp_path / 'p.db').as_posix()}"
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with factory() as s:
        yield s
    await engine.dispose()
    config.get_settings.cache_clear()


async def test_pausestore_roundtrip(session):
    await pausestore.add(session, 1, "awg", "PUBKEY", "phone-max", {"ip": "10.8.1.55"})
    await pausestore.add(session, 1, "xray", "UUID-1", "laptop", {"entry": {"id": "UUID-1"}})

    awg_paused = await pausestore.list_paused(session, 1, "awg")
    assert set(awg_paused) == {"PUBKEY"}
    assert awg_paused["PUBKEY"]["name"] == "phone-max"
    assert awg_paused["PUBKEY"]["data"]["ip"] == "10.8.1.55"
    # разные протоколы не пересекаются
    assert set(await pausestore.list_paused(session, 1, "xray")) == {"UUID-1"}

    # pop возвращает данные и удаляет
    rec = await pausestore.pop(session, 1, "awg", "PUBKEY")
    assert rec["data"]["ip"] == "10.8.1.55"
    assert await pausestore.list_paused(session, 1, "awg") == {}
    assert await pausestore.pop(session, 1, "awg", "PUBKEY") is None


async def test_pausestore_add_is_upsert(session):
    await pausestore.add(session, 2, "awg", "PK", "old", {"ip": "10.8.1.2"})
    await pausestore.add(session, 2, "awg", "PK", "new", {"ip": "10.8.1.3"})
    paused = await pausestore.list_paused(session, 2, "awg")
    assert len(paused) == 1
    assert paused["PK"]["name"] == "new"
    assert paused["PK"]["data"]["ip"] == "10.8.1.3"


async def test_pausestore_drop(session):
    await pausestore.add(session, 3, "xray", "U", "n", {})
    await pausestore.drop(session, 3, "xray", "U")
    await session.commit()
    assert await pausestore.list_paused(session, 3, "xray") == {}
