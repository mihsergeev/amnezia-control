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

    async def fake_send(cfg, text, *, html_text=None):
        sent.append(text)
        return []

    monkeypatch.setattr(alerts, "send_alert", fake_send)
    names = {1: "n1"}

    # 95% занято → алерт «мало места», строка создана
    await collector._store_node_metrics(factory, settings, [_sample(1, 95)], names)
    async with factory() as s:
        row = await s.get(NodeMetric, 1)
        assert row.disk_used == 95 and row.disk_alerted is True
    assert len(sent) == 1 and "Мало места" in sent[0]

    # всё ещё 95% → повторного алерта нет
    await collector._store_node_metrics(factory, settings, [_sample(1, 95)], names)
    assert len(sent) == 1

    # упало до 80% (< 90-5) → снятие + алерт восстановления
    await collector._store_node_metrics(factory, settings, [_sample(1, 80)], names)
    async with factory() as s:
        assert (await s.get(NodeMetric, 1)).disk_alerted is False
    assert len(sent) == 2 and "снова есть" in sent[1]


def test_parse_cpu_counters_and_psi():
    # вывод команды с настоящей ноды (1 vCPU)
    r = _parse("CPU=1\nLOAD=0.90\nCPUBUSY=29387215\nCPUTOTAL=189630025\nPSICPU=23.45\n")
    assert (r.cpu_busy, r.cpu_total, r.psi_cpu) == (29387215, 189630025, 23.45)
    # ядро без PSI - None, а не 0 (0 значило бы "CPU хватает")
    assert _parse("CPU=1\n").psi_cpu is None


def _res(busy, total):
    return NodeResources(
        cpu_count=1, load1=1.7, mem_total=1, mem_used=1, disk_total=1, disk_used=1,
        uptime_seconds=1, cpu_busy=busy, cpu_total=total,
    )


def test_cpu_percent_from_counters():
    from datetime import datetime, timedelta, timezone

    now = datetime.now(timezone.utc)
    prev = NodeMetric(server_id=1, cpu_busy=1000, cpu_total=10000, ts=now - timedelta(seconds=60))
    # за минуту 6000 тиков, из них занято 1620 - 27%, хотя load 1.7 на 1 ядро
    assert collector.cpu_percent(prev, _res(2620, 16000), now, 60) == 27.0
    # первый снимок, перезагрузка (счетчики сбросились), старый снимок - не знаем
    assert collector.cpu_percent(None, _res(2620, 16000), now, 60) is None
    assert collector.cpu_percent(prev, _res(50, 900), now, 60) is None
    old = NodeMetric(server_id=1, cpu_busy=1000, cpu_total=10000, ts=now - timedelta(hours=2))
    assert collector.cpu_percent(old, _res(2620, 16000), now, 60) is None


async def test_store_keeps_cpu_counters(factory, monkeypatch):
    settings = config.get_settings()
    s1 = {"server_id": 1, "resources": _res(1000, 10000)}
    await collector._store_node_metrics(factory, settings, [s1], {1: "n1"})
    async with factory() as s:
        row = await s.get(NodeMetric, 1)
        assert row.cpu_pct is None and row.cpu_total == 10000
    s2 = {"server_id": 1, "resources": _res(1500, 12000)}
    await collector._store_node_metrics(factory, settings, [s2], {1: "n1"})
    async with factory() as s:
        assert (await s.get(NodeMetric, 1)).cpu_pct == 25.0
