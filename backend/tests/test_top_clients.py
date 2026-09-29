from datetime import datetime, timezone

import pytest

from app import config
from app.api import stats
from app.db import Base, create_engine_and_factory
from app.models import AwgConfig, ClientTrafficSample, Server


@pytest.fixture
async def factory(tmp_path, monkeypatch):
    monkeypatch.setenv("VPNPANEL_DATA_DIR", (tmp_path / "data").as_posix())
    config.get_settings.cache_clear()
    engine, f = create_engine_and_factory(
        f"sqlite+aiosqlite:///{(tmp_path / 't.db').as_posix()}"
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield f
    await engine.dispose()
    config.get_settings.cache_clear()


async def test_top_clients_ranks_and_names(factory):
    now = datetime.now(timezone.utc)
    async with factory() as s:
        s.add(Server(id=1, name="srv-a", host="h", ssh_port=22, ssh_user="acontrol"))
        s.add(AwgConfig(server_id=1, public_key="PUBA", name="alice", config="c"))
        # свежие снимки: bob больше alice; zero — с нулём (в топ не попадёт)
        s.add(ClientTrafficSample(server_id=1, protocol="awg", client_id="PUBA",
                                  rx=100, tx=50, ts=now))
        s.add(ClientTrafficSample(server_id=1, protocol="awg", client_id="PUBB",
                                  rx=900, tx=100, ts=now))
        s.add(ClientTrafficSample(server_id=1, protocol="openvpn", client_id="cid0",
                                  rx=0, tx=0, ts=now))
        await s.commit()

    async with factory() as s:
        rows = await stats.top_clients(None, s, limit=10)

    assert [r.client_id for r in rows] == ["PUBB", "PUBA"]  # bob(1000) > alice(150)
    assert rows[0].total == 1000 and rows[0].name == "PUBB"[:12]  # нет конфига → id
    assert rows[1].name == "alice"  # имя из AwgConfig
    assert rows[1].server_name == "srv-a"


async def test_top_clients_empty(factory):
    async with factory() as s:
        rows = await stats.top_clients(None, s, limit=10)
    assert rows == []


async def test_top_clients_uses_name_cache(factory):
    """Клиент без панельного конфига (создан на ноде) получает имя из кэша,
    а не префикс pubkey."""
    from app.models import ClientName

    now = datetime.now(timezone.utc)
    async with factory() as s:
        s.add(Server(id=1, name="srv-a", host="h", ssh_port=22, ssh_user="acontrol"))
        s.add(ClientTrafficSample(server_id=1, protocol="awg", client_id="PUBX",
                                  rx=500, tx=100, ts=now))
        s.add(ClientName(server_id=1, protocol="awg", client_id="PUBX",
                         name="@node_client"))
        await s.commit()
    async with factory() as s:
        rows = await stats.top_clients(None, s, limit=10)
    assert rows[0].client_id == "PUBX"
    assert rows[0].name == "@node_client"  # из кэша, не "PUBX"[:12]


async def test_collector_stores_client_names(factory):
    from app.models import ClientName
    from app import collector
    from sqlalchemy import select

    samples = [{
        "server_id": 1,
        "clients": [
            {"protocol": "awg", "client_id": "PUBX", "rx": 1, "tx": 1, "name": "@bob"},
            {"protocol": "awg", "client_id": "PUBY", "rx": 1, "tx": 1, "name": "—"},
            {"protocol": "awg", "client_id": "PUBZ", "rx": 1, "tx": 1, "name": ""},
        ],
    }]
    await collector._store_client_names(factory, samples)
    async with factory() as s:
        rows = {r.client_id: r.name for r in await s.scalars(select(ClientName))}
    assert rows == {"PUBX": "@bob"}  # "—" и пустые не кэшируются

    # апдейт имени
    samples[0]["clients"][0]["name"] = "@bob2"
    await collector._store_client_names(factory, samples)
    async with factory() as s:
        rows = {r.client_id: r.name for r in await s.scalars(select(ClientName))}
    assert rows == {"PUBX": "@bob2"}


async def test_top_clients_filters_by_servers(factory):
    # топ по выбранным серверам: клиенты других серверов в него не попадают,
    # даже если качают больше всех
    now = datetime.now(timezone.utc)
    async with factory() as s:
        s.add(Server(id=1, name="kz-a", host="h1", ssh_port=22, ssh_user="acontrol"))
        s.add(Server(id=2, name="de-b", host="h2", ssh_port=22, ssh_user="acontrol"))
        s.add(ClientTrafficSample(server_id=1, protocol="awg", client_id="SMALL",
                                  rx=10, tx=0, ts=now))
        s.add(ClientTrafficSample(server_id=2, protocol="awg", client_id="HUGE",
                                  rx=10_000, tx=0, ts=now))
        await s.commit()

    async with factory() as s:
        only_first = await stats.top_clients(None, s, limit=10, server_id=[1])
        everyone = await stats.top_clients(None, s, limit=10)

    assert [r.client_id for r in only_first] == ["SMALL"]
    assert [r.client_id for r in everyone] == ["HUGE", "SMALL"]


async def test_top_clients_carry_protocol_label(factory):
    # в топе на "Обзоре" протокол подписан версией, как на карточке сервера;
    # раньше клиенты Legacy и 3.x выходили с пустой плашкой
    import json

    now = datetime.now(timezone.utc)
    info = json.dumps({
        "amnezia_containers": ["amnezia-awg3", "amnezia-awg2", "amnezia-awg"],
        "protocols": {"amnezia-awg3": "awg31", "amnezia-awg2": "awg2", "amnezia-awg": "awg1"},
    })
    async with factory() as s:
        s.add(Server(id=1, name="kz", host="h", ssh_port=22, ssh_user="acontrol",
                     last_check_info=info))
        for proto, cid, rx in (("awg", "A", 300), ("awg3", "B", 200), ("awglegacy", "C", 100)):
            s.add(ClientTrafficSample(server_id=1, protocol=proto, client_id=cid,
                                      rx=rx, tx=0, ts=now))
        await s.commit()

    async with factory() as s:
        rows = await stats.top_clients(None, s, limit=10)

    assert {r.protocol: r.protocol_label for r in rows} == {
        "awg": "AmneziaWG 2.0",
        "awg3": "AmneziaWG 3.1",
        "awglegacy": "AmneziaWG Legacy",
    }
