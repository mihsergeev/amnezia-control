import pytest

from app import alerts, collector, config, settings_store
from app.db import Base, create_engine_and_factory
from app.models import NodeMetric
from app.nodestat import NodeResources, _parse


def test_parse_resources():
    text = (
        "CPU=4\n"
        "LOAD=0.42\n"
        "MEMTOTAL=8000000000\n"
        "MEMAVAIL=3000000000\n"
        "DISKTOTAL=100000000000\n"
        "DISKUSED=91000000000\n"
        "UPTIME=123456.78\n"
    )
    r = _parse(text)
    assert r.cpu_count == 4
    assert r.load1 == 0.42
    assert r.mem_total == 8_000_000_000
    assert r.mem_used == 5_000_000_000  # total - avail
    assert r.disk_total == 100_000_000_000
    assert r.disk_used == 91_000_000_000
    assert r.uptime_seconds == 123456


def test_parse_missing_fields_are_zero():
    r = _parse("CPU=2\n")
    assert r.cpu_count == 2
    assert r.mem_total == 0 and r.mem_used == 0 and r.disk_total == 0


@pytest.fixture
async def factory(tmp_path, monkeypatch):
    monkeypatch.setenv("VPNPANEL_DATA_DIR", (tmp_path / "data").as_posix())
    config.get_settings.cache_clear()
    engine, f = create_engine_and_factory(
        f"sqlite+aiosqlite:///{(tmp_path / 'n.db').as_posix()}"
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield f
    await engine.dispose()
    config.get_settings.cache_clear()


def _sample(sid, disk_used, disk_total=100):
    return {
        "server_id": sid,
        "resources": NodeResources(
            cpu_count=2, load1=0.1, mem_total=1000, mem_used=500,
            disk_total=disk_total, disk_used=disk_used, uptime_seconds=10,
        ),
    }


async def test_store_metrics_and_disk_alert(factory, monkeypatch):
    settings = config.get_settings()  # disk_alert_percent=90 по умолчанию
    async with factory() as s:
        await settings_store.set_alert_config(s, "", "", "https://ex/hook")

    sent: list[str] = []

    async def fake_send(cfg, text):
        sent.append(text)
        return []

    monkeypatch.setattr(alerts, "send_alert", fake_send)
    names = {1: "n1"}

    # 95% занято → алерт «мало места», строка создана
    await collector._store_node_metrics(factory, settings, [_sample(1, 95)], names)
    async with factory() as s:
        row = await s.get(NodeMetric, 1)
        assert row.disk_used == 95 and row.disk_alerted is True
    assert len(sent) == 1 and "мало места" in sent[0]

    # всё ещё 95% → повторного алерта нет
    await collector._store_node_metrics(factory, settings, [_sample(1, 95)], names)
    assert len(sent) == 1

    # упало до 80% (< 90-5) → снятие + алерт восстановления
    await collector._store_node_metrics(factory, settings, [_sample(1, 80)], names)
    async with factory() as s:
        assert (await s.get(NodeMetric, 1)).disk_alerted is False
    assert len(sent) == 2 and "снова ок" in sent[1]
