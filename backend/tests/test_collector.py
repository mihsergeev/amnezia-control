"""Фоновый сбор обновляет список контейнеров (вкладки протоколов) по живому
docker ps — чтобы удалённый извне протокол пропадал без ручной «Проверки»."""

import json

import pytest

from app import collector, config
from app.db import Base, create_engine_and_factory
from app.models import Server
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
