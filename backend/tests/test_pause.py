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


async def test_last_traffic_of_paused_client(session):
    """На паузе нода отдает нули: трафик и последнюю активность берем из истории
    сборщика - последний снимок и момент, когда трафик последний раз вырос."""
    from datetime import datetime, timedelta, timezone

    from app.models import ClientTrafficSample

    t0 = datetime(2026, 10, 30, 12, 0, tzinfo=timezone.utc)
    for i, (rx, tx) in enumerate([(100, 50), (300, 80), (500, 90), (500, 90), (500, 90)]):
        session.add(ClientTrafficSample(server_id=1, protocol="awg3", client_id="K=",
                                        rx=rx, tx=tx, ts=t0 + timedelta(minutes=i)))
    # не менялся за всю историю - когда был активен, не знаем
    for i in range(3):
        session.add(ClientTrafficSample(server_id=1, protocol="awg3", client_id="IDLE=",
                                        rx=7, tx=7, ts=t0 + timedelta(minutes=i)))
    # другой протокол того же ключа не мешает
    session.add(ClientTrafficSample(server_id=1, protocol="awg", client_id="K=",
                                    rx=9999, tx=9999, ts=t0 + timedelta(minutes=9)))
    await session.commit()

    got = await pausestore.last_traffic(session, 1, "awg3", ["K=", "IDLE=", "NONE="])
    assert got["K="] == {"rx": 500, "tx": 90,
                         "seen": int((t0 + timedelta(minutes=2)).timestamp())}
    assert got["IDLE="] == {"rx": 7, "tx": 7, "seen": None}
    # без истории - нет записи, клиент показывается с нулями, как раньше
    assert "NONE=" not in got


async def test_paused_view_prefers_counters_from_pause(session):
    from datetime import datetime, timezone

    from app.models import ClientTrafficSample

    session.add(ClientTrafficSample(server_id=1, protocol="awg", client_id="K=", rx=10, tx=10,
                                    ts=datetime(2026, 10, 30, tzinfo=timezone.utc)))
    session.add(ClientTrafficSample(server_id=1, protocol="awg", client_id="OLD=", rx=5, tx=6,
                                    ts=datetime(2026, 10, 30, tzinfo=timezone.utc)))
    await session.commit()
    paused = {
        # AWG запоминает счетчики и рукопожатие в момент паузы
        "K=": {"name": "a", "data": {"ip": "10.8.1.2", "rx": 700, "tx": 800, "handshake": 1793350669}},
        # поставлен на паузу до этой версии - только IP, берем историю
        "OLD=": {"name": "b", "data": {"ip": "10.8.1.3"}},
    }
    got = await pausestore.paused_view(session, 1, "awg", paused, ["K=", "OLD="])
    assert got["K="] == {"rx": 700, "tx": 800, "seen": 1793350669}
    assert got["OLD="] == {"rx": 5, "tx": 6, "seen": None}
