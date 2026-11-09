"""Фоновый сбор обновляет список контейнеров (вкладки протоколов) по живому
docker ps — чтобы удалённый извне протокол пропадал без ручной «Проверки»."""

import json
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import select

from app import cascade_alias, collector, config
from app.db import Base, create_engine_and_factory
from app.models import Server, TrafficSample
from app.sshops import CheckResult


@pytest.fixture
async def factory(tmp_path, monkeypatch):
    db_path = (tmp_path / "col.db").as_posix()
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


async def _seed(session_factory, containers: list[str]) -> int:
    """Сервер со «старым» last_check_info, где есть amnezia-awg (протокол виден)."""
    info = {
        "error": "",
        "hostname": "node1",
        "docker": True,
        "containers": containers,
        "amnezia_containers": [c for c in containers if c.startswith("amnezia")],
    }
    async with session_factory() as session:
        s = Server(
            name="n1", host="10.0.0.1", ssh_port=22, ssh_user="acontrol",
            country="de", last_check_ok=True,
            last_check_info=json.dumps(info, ensure_ascii=False),
        )
        session.add(s)
        await session.commit()
        await session.refresh(s)
        return s.id


def _sample(server_id: int, check: CheckResult | None) -> dict:
    return {
        "server_id": server_id, "rx_total": 0, "tx_total": 0,
        "clients_total": 0, "clients_online": 0,
        "resources": None, "clients": [], "check": check,
    }


async def _run(factory, monkeypatch, sample: dict):
    # без внешних вызовов: геосервис и алерты — заглушки
    async def _noop_reconcile(*a, **k):
        return None
    monkeypatch.setattr(collector.alerts, "reconcile", _noop_reconcile)

    async def _fake_sample(server, *a, **k):
        return sample
    monkeypatch.setattr(collector, "_sample_server", _fake_sample)
    await collector.collect_once(factory, config.get_settings())


async def _info(factory, sid: int) -> dict:
    async with factory() as session:
        s = await session.get(Server, sid)
        return json.loads(s.last_check_info)


async def test_xray_online_counts_recent_traffic_not_cumulative_totals(factory, monkeypatch):
    sid = await _seed(factory, ["amnezia-xray", "amnezia-awg"])
    monkeypatch.setattr(collector, "_last_xray_counters", {})
    clients = [
        {"id": f"client-{i}", "email": f"stats-{i}"} for i in range(7)
    ]
    clients.append({"id": "default", "email": "default-stats"})
    server = {"inbounds": [{"settings": {"clients": clients}}]}
    monkeypatch.setattr(collector.xray, "detect_container", AsyncMock(return_value="amnezia-xray"))
    monkeypatch.setattr(collector.xray, "_read_all", AsyncMock(return_value=(server, "default", [])))
    read_stats = AsyncMock()
    monkeypatch.setattr(collector.xray, "read_client_stats", read_stats)

    async def sample(stats, expected_online):
        read_stats.return_value = stats
        totals, rows = await collector._xray_part(None, "node.example")
        await _run(factory, monkeypatch, _sample(sid, None) | {
            "clients_online": 1,  # one connected AWG client
            "clients_total": 1 + totals["total"],
            "rx_total": totals["rx"], "tx_total": totals["tx"],
            "clients": rows, "parts": frozenset({"xray", "awg"}),
            "xray_counters": totals["xray_counters"],
        })
        async with factory() as session:
            last = await session.scalar(select(TrafficSample).order_by(TrafficSample.id.desc()))
        assert (last.clients_online, last.clients_total) == (expected_online, 8)

    await sample({}, 1)
    active = {"stats-0": {"up": 15, "down": 100}, "stats-1": {"up": 0, "down": 20},
              "client-2": {"up": 10, "down": 10}, "default-stats": {"up": 50, "down": 50},
              "revoked": {"up": 50, "down": 50}}
    await sample(active, 3)
    await sample(active, 1)
    await sample(active | {"stats-0": {"up": 2, "down": 0},
                           "stats-1": {"up": 0, "down": 0}}, 2)
    await sample(None, 1)
    await sample(active, 1)  # the first good poll after a failure only sets the baseline
    await sample(active | {"stats-0": {"up": 15, "down": 101}}, 2)


@pytest.mark.parametrize("extra_flaps, carried", [(False, 1), (True, 0)])
async def test_xray_activity_survives_skipped_aggregate(factory, monkeypatch, extra_flaps, carried):
    sid = await _seed(factory, ["amnezia-xray", "amnezia-awg"])
    for name in ("_last_parts", "_last_clients", "_pending", "_last_xray_counters", "_pending_xray_active"):
        monkeypatch.setattr(collector, name, {})

    async def sample(awg_available, rx, client_ids=("active", "revoked")):
        parts = {"xray", "awg"} if awg_available else {"xray"}
        await _run(factory, monkeypatch, _sample(sid, None) | {
            "parts": frozenset(parts),
            "clients_total": int(awg_available) + len(client_ids),
            "known": [("xray", cid) for cid in client_ids],
            "xray_counters": {cid: (rx, 0) for cid in client_ids},
        })

    await sample(True, 100)
    await sample(False, 200)
    await sample(True, 200, ("active",))
    if extra_flaps:
        await sample(False, 200, ("active",))
        await sample(True, 200, ("active",))
    await sample(True, 200, ("active",))
    await sample(True, 200, ("active",))
    async with factory() as session:
        rows = await session.scalars(select(TrafficSample).order_by(TrafficSample.id))
        assert [(row.clients_online, row.clients_total) for row in rows] == [(0, 3), (carried, 2), (0, 2)]


async def test_removed_container_drops_protocol(factory, monkeypatch):
    sid = await _seed(factory, ["amnezia-awg2", "3x-ui"])
    # контейнер удалён извне: docker ответил, amnezia-контейнеров больше нет
    chk = CheckResult(ok=True, docker=True, hostname="node1", containers=["3x-ui"])
    chk.amnezia_containers = []
    await _run(factory, monkeypatch, _sample(sid, chk))
    info = await _info(factory, sid)
    assert info["amnezia_containers"] == []  # протокол пропал автоматически


async def test_transient_ssh_keeps_protocol(factory, monkeypatch):
    sid = await _seed(factory, ["amnezia-awg2"])
    # docker не ответил (check=None) — прежний список НЕ трогаем
    await _run(factory, monkeypatch, _sample(sid, None))
    info = await _info(factory, sid)
    assert info["amnezia_containers"] == ["amnezia-awg2"]


async def test_docker_down_keeps_protocol(factory, monkeypatch):
    sid = await _seed(factory, ["amnezia-awg2"])
    # SSH ок, но docker недоступен (docker=False) — список сохраняем
    chk = CheckResult(ok=True, docker=False)
    await _run(factory, monkeypatch, _sample(sid, chk))
    info = await _info(factory, sid)
    assert info["amnezia_containers"] == ["amnezia-awg2"]


async def _manual_alias(factory, sid):
    route = {"transport": "vless", "security": "reality", "network": "xhttp",
             "exit_host": "203.0.113.20", "exit_port": 443}
    async with factory() as session:
        server = await session.get(Server, sid)
        info = json.loads(server.last_check_info)
        info["manual_cascade"] = route | {"exit_country": "KZ"}
        server.last_check_info = json.dumps(info)
        await cascade_alias.set_name(session, server, "vpn-exit (transit)")
        await session.commit()
    return route


async def test_periodic_check_preserves_manual_alias_and_country(factory, monkeypatch):
    sid = await _seed(factory, ["amnezia-awg2"])
    route = await _manual_alias(factory, sid)

    async def no_lookup(host):
        raise AssertionError("The country for this configured peer is already known")

    monkeypatch.setattr(collector.geo, "country_code", no_lookup)
    # Each runtime observation intentionally has no user alias or geography.
    for _ in range(2):
        check = CheckResult(ok=True, docker=True, manual_cascade=dict(route))
        await _run(factory, monkeypatch, _sample(sid, check))
        peer = (await _info(factory, sid))["manual_cascade"]
        assert peer["exit_name"] == "vpn-exit (transit)"
        assert peer["exit_country"] == "KZ"


async def test_periodic_check_does_not_transfer_alias_or_country_to_new_peer(factory, monkeypatch):
    sid = await _seed(factory, ["amnezia-awg2"])
    route = await _manual_alias(factory, sid)

    async def country(host):
        assert host == "203.0.113.21"
        return "FI"

    monkeypatch.setattr(collector.geo, "country_code", country)
    check = CheckResult(ok=True, docker=True,
                        manual_cascade=route | {"exit_host": "203.0.113.21"})
    await _run(factory, monkeypatch, _sample(sid, check))
    peer = (await _info(factory, sid))["manual_cascade"]
    assert "exit_name" not in peer
    assert peer["exit_country"] == "FI"


async def test_periodic_check_recovers_alias_and_country_from_previously_raw_metadata(factory, monkeypatch):
    sid = await _seed(factory, ["amnezia-awg2"])
    route = await _manual_alias(factory, sid)
    # Reproduce a DTO already overwritten by an older collector. Its alias
    # still exists separately, so the next scheduled check must recover it.
    async with factory() as session:
        server = await session.get(Server, sid)
        server.last_check_info = json.dumps({"manual_cascade": route})
        await session.commit()
    lookups = []

    async def country(host):
        lookups.append(host)
        return "KZ"

    monkeypatch.setattr(collector.geo, "country_code", country)
    for _ in range(2):
        check = CheckResult(ok=True, docker=True, manual_cascade=dict(route))
        await _run(factory, monkeypatch, _sample(sid, check))
        peer = (await _info(factory, sid))["manual_cascade"]
        assert peer["exit_name"] == "vpn-exit (transit)" and peer["exit_country"] == "KZ"
    assert lookups == ["203.0.113.20"]


async def test_server_sample_skipped_while_protocol_set_changes(factory, monkeypatch):
    """Протокол не прочитался в одном цикле: снимки сервера с другим набором
    протоколов не пишем, иначе на графике ложный пик."""
    from sqlalchemy import select

    from app.models import TrafficSample

    sid = await _seed(factory, ["amnezia-awg2"])
    collector._last_parts.clear()
    for parts in ({"awg", "xray"}, {"awg"}, {"awg", "xray"}, {"awg", "xray"}):
        sample = {**_sample(sid, None), "parts": frozenset(parts)}
        await _run(factory, monkeypatch, sample)
    async with factory() as s:
        n = len(list(await s.scalars(select(TrafficSample))))
    assert n == 2  # первый и последний циклы
    collector._last_parts.clear()


async def test_client_names_of_revoked_are_dropped(factory, monkeypatch):
    """Клиента отозвали: его имя уходит из кэша, иначе поиск показывает его
    годами. Протокол, который не прочитался, не трогаем."""
    from sqlalchemy import select

    from app.models import ClientName

    sid = await _seed(factory, ["amnezia-awg2"])
    async with factory() as s:
        s.add_all([
            ClientName(server_id=sid, protocol="awg", client_id="gone", name="old"),
            ClientName(server_id=sid, protocol="awg", client_id="live", name="a"),
            ClientName(server_id=sid, protocol="xray", client_id="x1", name="x"),
        ])
        await s.commit()
    collector._last_parts.clear()
    sample = {
        **_sample(sid, None),
        "parts": frozenset({"awg:amnezia-awg2"}),
        "known": [("awg", "live")],
        "clients": [{"protocol": "awg", "client_id": "live", "rx": 0, "tx": 0, "name": "a"}],
    }
    await _run(factory, monkeypatch, sample)
    async with factory() as s:
        left = sorted(r.client_id for r in await s.scalars(select(ClientName)))
    assert left == ["live", "x1"]
    collector._last_parts.clear()


def _traffic(sid, parts, clients):
    return {
        **_sample(sid, None),
        "parts": frozenset(parts),
        "rx_total": sum(c[1] for c in clients),
        "clients": [{"protocol": p, "client_id": c, "rx": rx, "tx": 0, "name": ""}
                    for c, rx, p in ((c[0], c[1], c[2]) for c in clients)],
    }


async def test_traffic_delta_counted_per_client(factory, monkeypatch):
    """Сброс счетчика одного клиента (отзыв, рестарт xray) не обнуляет прирост
    остальных: раньше прирост сервера был дельтой суммы счетчиков."""
    from sqlalchemy import select

    from app.models import TrafficSample

    sid = await _seed(factory, ["amnezia-awg2"])
    for st in (collector._last_parts, collector._last_clients, collector._pending):
        st.clear()
    gb = 1024 ** 3
    parts = {"awg:amnezia-awg2", "xray"}
    cycles = [
        [("A", 100 * gb, "awg"), ("B", gb, "awg"), ("X", 5 * gb, "xray")],
        [("A", 100 * gb, "awg"), ("B", 2 * gb, "awg"), ("X", 6 * gb, "xray")],
        # A отозвали, xray перезапустился (счетчик X с нуля)
        [("B", 4 * gb, "awg"), ("X", gb, "xray")],
    ]
    for clients in cycles:
        await _run(factory, monkeypatch, _traffic(sid, parts, clients))
    # xray не прочитался: снимок не пишем, прирост awg переносим в следующий
    await _run(factory, monkeypatch, _traffic(sid, {"awg:amnezia-awg2"}, [("B", 5 * gb, "awg")]))
    await _run(factory, monkeypatch, _traffic(sid, parts, [("B", 6 * gb, "awg"), ("X", 2 * gb, "xray")]))
    await _run(factory, monkeypatch, _traffic(sid, parts, [("B", 6 * gb, "awg"), ("X", 2 * gb, "xray")]))
    async with factory() as s:
        rows = list(await s.scalars(select(TrafficSample).order_by(TrafficSample.id)))
    # первый цикл - сравнивать не с чем; четвертый и пятый (набор протоколов
    # менялся) не записаны, их прирост B +2 ГБ и X +1 ГБ ушел в шестой
    assert [r.rx_delta for r in rows] == [None, 2 * gb, 3 * gb, 3 * gb]
    for st in (collector._last_parts, collector._last_clients, collector._pending):
        st.clear()


async def test_deleted_during_collect_leaves_no_orphans(factory, monkeypatch):
    from sqlalchemy import delete, select

    from app.models import ClientName, NodeMetric, ServerStatus, TrafficSample

    sid = await _seed(factory, ["amnezia-awg2"])
    collector._last_parts.clear()

    async def _sample_and_delete(server, *a, **k):
        # пользователь удалил сервер, пока шел сбор
        async with factory() as s:
            await s.execute(delete(Server).where(Server.id == server.id))
            await s.commit()
        return {
            **_sample(server.id, None), "parts": frozenset({"awg:amnezia-awg2"}),
            "resources": type("R", (), {"disk_used": 1, "disk_total": 2})(),
            "clients": [{"protocol": "awg", "client_id": "K=", "rx": 1, "tx": 1, "name": "n"}],
        }

    monkeypatch.setattr(collector, "_sample_server", _sample_and_delete)
    await collector.collect_once(factory, config.get_settings())
    async with factory() as s:
        for model in (TrafficSample, NodeMetric, ClientName, ServerStatus):
            assert list(await s.scalars(select(model))) == [], model.__tablename__
