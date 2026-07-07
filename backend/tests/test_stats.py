from datetime import datetime, timezone
from types import SimpleNamespace

from app import stats_calc


def _smp(server_id, ts, rx, tx, online, total=0):
    return SimpleNamespace(
        server_id=server_id,
        ts=ts,
        rx_total=rx,
        tx_total=tx,
        clients_online=online,
        clients_total=total,
    )


def test_build_overview_online_and_offline() -> None:
    servers = [(1, "srv-a"), (2, "srv-b")]
    s1 = _smp(1, None, 100, 200, 2, total=3)
    latest = {1: s1}  # сервер 2 без свежего снимка → офлайн
    ov = stats_calc.build_overview(servers, latest)
    assert ov["servers_total"] == 2
    assert ov["servers_online"] == 1
    assert ov["clients_total"] == 3
    assert ov["clients_online"] == 2
    assert ov["rx_total"] == 100 and ov["tx_total"] == 200
    by_id = {p["id"]: p for p in ov["per_server"]}
    assert by_id[1]["online"] is True
    assert by_id[2]["online"] is False and by_id[2]["clients_total"] == 0


def test_aggregate_history_sums_servers_and_throughput() -> None:
    t0 = datetime(2026, 7, 6, 12, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 7, 6, 12, 5, tzinfo=timezone.utc)
    samples = [
        _smp(1, t0, 100, 100, 1),
        _smp(2, t0, 50, 50, 2),
        _smp(1, t1, 300, 300, 1),  # +400 суммарно к своему прошлому
        _smp(2, t1, 50, 50, 0),
    ]
    points = stats_calc.aggregate_history(samples, interval=300)
    assert len(points) == 2
    # bucket t0: rx=150, tx=150, online=3
    assert points[0]["rx_total"] == 150 and points[0]["clients_online"] == 3
    assert points[0]["throughput"] == 0  # первая точка
    # bucket t1: total = (300+300)+(50+50)=700, prev total=(150+150)=300 → 400
    assert points[1]["throughput"] == 700 - 300
    assert points[1]["clients_online"] == 1


def test_aggregate_history_clamps_reset() -> None:
    t0 = datetime(2026, 7, 6, 12, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 7, 6, 12, 5, tzinfo=timezone.utc)
    # счётчики сбросились (рестарт контейнера) → отрицательной дельты быть не должно
    samples = [_smp(1, t0, 1000, 1000, 1), _smp(1, t1, 10, 10, 1)]
    points = stats_calc.aggregate_history(samples, interval=300)
    assert points[1]["throughput"] == 0


def test_aggregate_history_empty() -> None:
    assert stats_calc.aggregate_history([], interval=300) == []


def _csmp(ts, rx, tx):
    return SimpleNamespace(ts=ts, rx=rx, tx=tx)


def test_aggregate_client_history_throughput() -> None:
    t0 = datetime(2026, 7, 6, 12, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 7, 6, 12, 5, tzinfo=timezone.utc)
    t2 = datetime(2026, 7, 6, 12, 10, tzinfo=timezone.utc)
    samples = [
        _csmp(t0, 100, 100),
        _csmp(t1, 300, 500),  # total 800, prev 200 → 600
        _csmp(t2, 50, 50),  # сброс (перевыпуск) → clamp 0
    ]
    points = stats_calc.aggregate_client_history(samples, interval=300)
    assert len(points) == 3
    assert points[0]["throughput"] == 0
    assert points[1]["rx_total"] == 300 and points[1]["throughput"] == 600
    assert points[2]["throughput"] == 0


def test_aggregate_client_history_empty() -> None:
    assert stats_calc.aggregate_client_history([], interval=300) == []
