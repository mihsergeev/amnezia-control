"""Ротация авто-бэкапов по дням и пропуск бэкапа на старте при свежей копии."""

import os
from datetime import datetime, timedelta, timezone

from app import autobackup

NOW = datetime(2026, 10, 30, 12, 0, tzinfo=timezone.utc)


def _name(t: datetime) -> str:
    return f"acontrol-backup-{t:%Y%m%d-%H%M%S}.tar.gz"


def _touch(d, t: datetime) -> str:
    n = _name(t)
    (d / n).write_bytes(b"x")
    return n


def test_prune_keeps_daily_and_weekly(tmp_path):
    names = []
    # 120 дней по копии в день + 10 копий за последний день (частые релизы)
    for i in range(120):
        names.append(_touch(tmp_path, NOW - timedelta(days=i)))
    for h in range(1, 11):
        _touch(tmp_path, NOW - timedelta(minutes=10 * h))
    (tmp_path / "other.txt").write_bytes(b"x")
    autobackup._prune(str(tmp_path), 14)
    left = sorted(os.listdir(tmp_path))
    assert "other.txt" in left
    left.remove("other.txt")
    # за 14 дней - по последней копии за день, частые релизы не вытеснили старые
    for i in range(14):
        assert _name(NOW - timedelta(days=i)) in left
    days = {n[16:24] for n in left}
    assert len(left) == len(days)  # по одной на день
    # недельные: всего 8 недель, старше - удалены
    weeks = {datetime.strptime(n[16:24], "%Y%m%d").isocalendar()[:2] for n in left}
    assert len(weeks) == autobackup.WEEKLY_KEEP
    assert _name(NOW - timedelta(days=119)) not in left


def test_prune_counts_from_newest_copy(tmp_path):
    """Панель долго была выключена: ротация считает от последней копии."""
    old = NOW - timedelta(days=60)
    for i in range(5):
        _touch(tmp_path, old - timedelta(days=i))
    autobackup._prune(str(tmp_path), 14)
    assert len(os.listdir(tmp_path)) == 5


def test_until_due_skips_backup_after_restart(tmp_path):
    data = tmp_path / "data"
    d = data / "backups"
    d.mkdir(parents=True)
    assert autobackup._until_due(str(data), 86400, now=NOW) == 0
    _touch(d, NOW - timedelta(hours=2))
    assert autobackup._until_due(str(data), 86400, now=NOW) == 22 * 3600
    _touch(d, NOW + timedelta(hours=1))  # часы сбились - не ждем
    assert autobackup._until_due(str(data), 86400, now=NOW) == 0
    (d / _name(NOW + timedelta(hours=1))).unlink()
    _touch(d, NOW - timedelta(days=2))
    assert autobackup._until_due(str(data), 86400, now=NOW) == 22 * 3600
