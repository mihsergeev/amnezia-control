from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

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


async def _seed(session_factory, expires_at, *, alerts_enabled=True):
    async with session_factory() as session:
        server = Server(
            name="n1", host="10.0.0.1", ssh_port=22, ssh_user="acontrol",
            alerts_enabled=alerts_enabled,
        )
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

    async def fake_revoke(server, protocol, client_ids, key_path, timeout):
        calls.extend((server.id, protocol, cid) for cid in client_ids)
        return {}

    monkeypatch.setattr(expiry, "revoke_many_on_node", fake_revoke)

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
        expiry, "revoke_many_on_node",
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

    monkeypatch.setattr(expiry, "revoke_many_on_node", boom)

    n = await expiry.expiry_once(factory, settings)

    assert n == 0
    async with factory() as session:
        # лимит остаётся — повторим на следующем цикле
        assert (await session.get(ClientLimit, 1)) is not None


async def test_protocol_gone_drops_limit(factory, monkeypatch):
    """Протокол удалили с ноды: срок снимаем, а не откладываем каждый день."""
    settings = config.get_settings()
    await _seed(factory, datetime.now(timezone.utc) - timedelta(hours=1))

    async def gone(*a, **k):
        raise expiry.ProtocolGone("контейнер AmneziaWG 2.0 не запущен")

    monkeypatch.setattr(expiry, "revoke_many_on_node", gone)
    assert await expiry.expiry_once(factory, settings) == 1
    async with factory() as session:
        assert (await session.get(ClientLimit, 1)) is None


class _PsConn:
    def __init__(self, names: str):
        self.names = names

    async def run(self, cmd, check=False):  # noqa: A002
        return type("R", (), {"exit_status": 0, "stdout": self.names})()


async def test_not_ready_vs_gone():
    # остановленный контейнер поднимется и вернет клиента: отзыв только откладываем
    err = await expiry._not_ready(_PsConn("amnezia-awg2\n"), "awg", "x")
    assert isinstance(err, expiry.NodeNotReady)
    err = await expiry._not_ready(_PsConn("amnezia-awg3\namnezia-xray\n"), "awg", "x")
    assert isinstance(err, expiry.ProtocolGone)
    err = await expiry._not_ready(_PsConn("amnezia-awg2\n"), "awg3", "x")
    assert isinstance(err, expiry.ProtocolGone)


async def test_awg_revoke_on_legacy_only_node(monkeypatch):
    """Нода только со старым AmneziaWG: клиент "awg" живет в legacy-контейнере."""
    from app import awg

    async def detect(conn):
        return {"new": None, "legacy": "amnezia-awg"}

    async def state(conn, host, container=None):
        return type("S", (), {"container": container, "interface": "wg0"})()

    revoked = []

    async def revoke(conn, container, iface, key):
        revoked.append((container, iface, key))

    monkeypatch.setattr(awg, "detect_awg_containers", detect)
    monkeypatch.setattr(awg, "read_state", state)
    monkeypatch.setattr(awg, "revoke_client", revoke)
    srv = Server(id=1, name="vpn-a", host="203.0.113.10", ssh_port=22, ssh_user="acontrol")
    revoke_one = await expiry._revoker(object(), srv, "awg")
    await revoke_one("PUB=")
    assert revoked == [("amnezia-awg", "wg0", "PUB=")]


async def test_expired_grouped_per_node_and_dead_node_skipped(factory, monkeypatch):
    settings = config.get_settings()
    past = datetime.now(timezone.utc) - timedelta(hours=1)
    async with factory() as session:
        a = Server(name="vpn-a", host="203.0.113.1", ssh_port=22, ssh_user="acontrol")
        b = Server(name="vpn-b", host="203.0.113.2", ssh_port=22, ssh_user="acontrol")
        session.add_all([a, b])
        await session.commit()
        rows = [
            (a.id, "awg", "A1="), (a.id, "awg", "A2="), (a.id, "xray", "AX"),
            (b.id, "awg", "B1="),
        ]
        session.add_all(
            ClientLimit(server_id=sid, protocol=p, client_id=c, expires_at=past)
            for sid, p, c in rows
        )
        await session.commit()
        a_id, b_id = a.id, b.id

    calls = []

    async def fake_many(server, protocol, client_ids, key_path, timeout):
        calls.append((server.id, protocol, list(client_ids)))
        if server.id == a_id:
            raise OSError("connect timeout")
        return {}

    monkeypatch.setattr(expiry, "revoke_many_on_node", fake_many)
    assert await expiry.expiry_once(factory, settings) == 1
    # одна пачка на (сервер, протокол); после ошибки подключения к vpn-a его
    # xray в этот проход уже не пробуем
    assert calls == [(a_id, "awg", ["A1=", "A2="]), (b_id, "awg", ["B1="])]
    async with factory() as session:
        left = set(await session.scalars(select(ClientLimit.client_id)))
    assert left == {"A1=", "A2=", "AX"}


async def test_warn_expiring_on_sqlite(factory, monkeypatch):
    """SQLite отдает наивный expires_at: вычитание не должно падать."""
    settings = config.get_settings()
    monkeypatch.setattr(settings, "expiry_warn_days", 3)
    await _seed(factory, datetime.now(timezone.utc) + timedelta(days=1))
    cards = []

    async def fake_alert(session_factory, settings, card, **_kwargs):
        cards.append(card)

    monkeypatch.setattr(expiry.alerts, "maybe_alert", fake_alert)
    expiry._expiry_warned.clear()
    assert await expiry.warn_expiring(factory, settings) == 1
    assert len(cards) == 1


async def test_warn_expiring_disabled_server_is_silent(factory, monkeypatch):
    settings = config.get_settings()
    monkeypatch.setattr(settings, "expiry_warn_days", 3)
    await _seed(
        factory, datetime.now(timezone.utc) + timedelta(days=1), alerts_enabled=False
    )
    cards = []

    async def fake_alert(session_factory, settings, card, **_kwargs):
        cards.append(card)

    monkeypatch.setattr(expiry.alerts, "maybe_alert", fake_alert)
    expiry._expiry_warned.clear()
    assert await expiry.warn_expiring(factory, settings) == 0
    assert cards == []
