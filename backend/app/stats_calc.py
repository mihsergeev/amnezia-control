"""Чистые функции агрегации метрик (без БД/IO) — легко тестируются."""

from collections import defaultdict
from datetime import datetime, timezone


def build_overview(servers: list, latest_by_id: dict) -> dict:
    """servers: [(id, name)], latest_by_id: {id: sample} (только свежие снимки)."""
    per_server = []
    agg = {"servers_online": 0, "clients_total": 0, "clients_online": 0, "rx": 0, "tx": 0}
    for sid, name in servers:
        smp = latest_by_id.get(sid)
        online = smp is not None
        per_server.append(
            {
                "id": sid,
                "name": name,
                "online": online,
                "clients_total": smp.clients_total if smp else 0,
                "clients_online": smp.clients_online if smp else 0,
                "rx_total": smp.rx_total if smp else 0,
                "tx_total": smp.tx_total if smp else 0,
            }
        )
        if online:
            agg["servers_online"] += 1
            agg["clients_total"] += smp.clients_total
            agg["clients_online"] += smp.clients_online
            agg["rx"] += smp.rx_total
            agg["tx"] += smp.tx_total
    return {
        "servers_total": len(servers),
        "servers_online": agg["servers_online"],
        "clients_total": agg["clients_total"],
        "clients_online": agg["clients_online"],
        "rx_total": agg["rx"],
        "tx_total": agg["tx"],
        "per_server": per_server,
    }


def aggregate_client_history(samples: list, interval: int) -> list[dict]:
    """История одного клиента: бинует по интервалу, последний снимок в бакете.

    samples: объекты с .ts, .rx, .tx (кумулятивные). throughput = дельта суммы
    rx+tx с clamp≥0 (переустановка/перевыпуск сбрасывает счётчик).
    """
    step = max(interval, 1)
    by_bucket: dict[int, tuple[int, int]] = {}
    for s in samples:
        bucket = int(s.ts.timestamp() // step) * step
        by_bucket[bucket] = (s.rx, s.tx)  # последний снимок в бакете побеждает

    points = []
    prev_total = None
    for bucket in sorted(by_bucket):
        rx, tx = by_bucket[bucket]
        total = rx + tx
        throughput = max(0, total - prev_total) if prev_total is not None else 0
        prev_total = total
        points.append(
            {
                "ts": datetime.fromtimestamp(bucket, timezone.utc).isoformat(),
                "rx_total": rx,
                "tx_total": tx,
                "throughput": throughput,
            }
        )
    return points


def aggregate_history(samples: list, interval: int) -> list[dict]:
    """Бинует снимки по интервалу, суммирует по серверам, считает throughput.

    samples: объекты с .server_id, .ts (datetime), .rx_total, .tx_total, .clients_online.
    throughput точки = max(0, суммарный_кумулятивный_трафик - предыдущий) — так
    рестарты контейнера (сброс счётчиков) не дают отрицательных всплесков.
    """
    step = max(interval, 1)
    # (bucket, server_id) -> (rx, tx, online); последний снимок в бакете побеждает
    by_bucket_server: dict[tuple[int, int], tuple[int, int, int]] = {}
    for s in samples:
        bucket = int(s.ts.timestamp() // step) * step
        by_bucket_server[(bucket, s.server_id)] = (
            s.rx_total, s.tx_total, s.clients_online,
        )

    bucket_agg: dict[int, list[int]] = defaultdict(lambda: [0, 0, 0])
    for (bucket, _sid), (rx, tx, online) in by_bucket_server.items():
        bucket_agg[bucket][0] += rx
        bucket_agg[bucket][1] += tx
        bucket_agg[bucket][2] += online

    points = []
    prev_total = None
    for bucket in sorted(bucket_agg):
        rx, tx, online = bucket_agg[bucket]
        total = rx + tx
        throughput = max(0, total - prev_total) if prev_total is not None else 0
        prev_total = total
        points.append(
            {
                "ts": datetime.fromtimestamp(bucket, timezone.utc).isoformat(),
                "clients_online": online,
                "throughput": throughput,
                "rx_total": rx,
                "tx_total": tx,
            }
        )
    return points
