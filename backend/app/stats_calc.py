"""Чистые функции агрегации метрик (без БД/IO) — легко тестируются."""

from collections import defaultdict
from datetime import datetime, timezone

# «Красивая» лесенка шагов бакета в секундах: 5м, 10м, 15м, 30м, 1ч, 2ч, 3ч,
# 6ч, 12ч, 1д, 2д, 3д, 7д. По ней выбираем укрупнение так, чтобы на любой
# диапазон (от 3 часов до 90 дней) выходило ~несколько сотен точек — иначе
# 90 дней при 5-минутном шаге дали бы ~26 000 точек в одном polyline.
_NICE_STEPS = (
    300, 600, 900, 1800,
    3600, 7200, 10800, 21600, 43200,
    86400, 172800, 259200, 604800,
)


def pick_bucket_seconds(
    range_seconds: float, base_interval: int, max_points: int = 350
) -> int:
    """Наименьший «красивый» шаг ≥ интервала сбора, при котором точек ≤ max_points."""
    base = max(base_interval, 1)
    min_step = max(base, range_seconds / max_points if max_points else base)
    for step in _NICE_STEPS:
        if step >= min_step:
            return step
    return _NICE_STEPS[-1]


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


def _bucketize(
    samples: list, step: int
) -> dict[int, dict[int, tuple[int, int, int, float]]]:
    """bucket -> {server_id: (rx, tx, online, ts)}; последний снимок в бакете побеждает."""
    buckets: dict[int, dict[int, tuple[int, int, int, float]]] = defaultdict(dict)
    for s in samples:
        ts = s.ts.timestamp()
        bucket = int(ts // step) * step
        buckets[bucket][s.server_id] = (s.rx_total, s.tx_total, s.clients_online, ts)
    return buckets


def aggregate_history(samples: list, interval: int) -> list[dict]:
    """Бинует снимки по интервалу, суммирует по серверам, считает трафик за бакет.

    samples: объекты с .server_id, .ts (datetime), .rx_total, .tx_total, .clients_online.

    Трафик считается по каждому серверу отдельно и только потом складывается.
    Разность общих сумм врала: сервер, пропустивший сбор, выпадал из суммы
    (минус, срезанный в ноль), а в следующем бакете возвращался всем счетчиком с
    запуска - и на графике вырастал пик в сотни гигабайт, которого не было.

    Скорость (rx_rate / tx_rate, байт в секунду) - тоже посерверно: прирост
    сервера делится на ЕГО промежуток между снимками. Иначе вернувшийся после
    пропуска сервер отдал бы в одну точку прирост за несколько интервалов, и
    точка вышла бы в разы выше. Рестарт контейнера сбрасывает счетчик -
    отрицательный прирост считаем нулем.
    """
    step = max(interval, 1)
    buckets = _bucketize(samples, step)
    prev: dict[int, tuple[float, int, int]] = {}
    points = []
    for bucket in sorted(buckets):
        rx_sum = tx_sum = online = rx_delta = tx_delta = 0
        rx_rate = tx_rate = 0.0
        for sid, (rx, tx, on, ts) in buckets[bucket].items():
            rx_sum += rx
            tx_sum += tx
            online += on
            if sid in prev:
                pts, prx, ptx = prev[sid]
                elapsed = max(1.0, ts - pts)
                drx = max(0, rx - prx)
                dtx = max(0, tx - ptx)
                rx_delta += drx
                tx_delta += dtx
                rx_rate += drx / elapsed
                tx_rate += dtx / elapsed
            prev[sid] = (ts, rx, tx)
        points.append(
            {
                "ts": datetime.fromtimestamp(bucket, timezone.utc).isoformat(),
                "clients_online": online,
                "throughput": rx_delta + tx_delta,
                "rx_total": rx_sum,
                "tx_total": tx_sum,
                "rx_rate": round(rx_rate, 1),
                "tx_rate": round(tx_rate, 1),
            }
        )
    return points


def clients_by_server(samples: list, interval: int) -> dict[int, list[int | None]]:
    """Клиенты онлайн по каждому серверу, выровненные по тем же бакетам, что и
    aggregate_history. None - в этом бакете снимка сервера нет (график рисует
    разрыв, а не ноль: "данных нет" и "никого нет" - разные вещи)."""
    step = max(interval, 1)
    buckets = _bucketize(samples, step)
    order = sorted(buckets)
    sids = {sid for per in buckets.values() for sid in per}
    return {
        sid: [buckets[b][sid][2] if sid in buckets[b] else None for b in order]
        for sid in sids
    }
