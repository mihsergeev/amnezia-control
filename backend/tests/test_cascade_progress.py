import json

import pytest
from fastapi import HTTPException

from app import cascade_progress


@pytest.fixture(autouse=True)
def reset(monkeypatch):
    monkeypatch.setattr(cascade_progress, "_runs", {})


def test_progress_uses_actual_events_and_returns_detached_snapshots():
    cascade_progress.start("run", 1, 10, 20, "awg")
    initial = cascade_progress.snapshot("run", 1)
    assert initial["sides"]["entry"]["started_at"] is None
    cascade_progress.event("run", "exit", "building_image")
    snapshot = cascade_progress.snapshot("run", 1)
    assert snapshot["sides"]["exit"]["status"] == "running"
    assert snapshot["sides"]["exit"]["started_at"]
    assert initial["sides"]["exit"]["stage"] == "queued"
    snapshot["sides"]["exit"]["stage"] = "untrusted"
    assert cascade_progress.snapshot("run", 1)["sides"]["exit"]["stage"] == "building_image"
    with pytest.raises(HTTPException) as exc:
        cascade_progress.snapshot("run", 2)
    assert exc.value.status_code == 404
    with pytest.raises(ValueError):
        cascade_progress.event("run", "entry", "raw remote log")
    assert "raw remote log" not in json.dumps(cascade_progress.snapshot("run", 1))


def test_progress_bound_expiry_does_not_evict_running_work(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(cascade_progress.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(cascade_progress, "MAX_RUNS", 2)
    cascade_progress.start("active", 1, 10, 20, "gre")
    cascade_progress.start("done", 1, 30, 40, "gre")
    cascade_progress.finish("done", "done")
    with pytest.raises(HTTPException) as exc:
        cascade_progress.start("overflow", 1, 50, 60, "gre")
    assert exc.value.status_code == 429
    with pytest.raises(HTTPException) as exc:
        cascade_progress.start("active", 2, 10, 20, "gre")
    assert exc.value.status_code == 409
    clock[0] += cascade_progress.TERMINAL_TTL + 1
    cascade_progress.start("new", 1, 50, 60, "gre")
    assert cascade_progress.snapshot("active", 1)["status"] == "running"
    with pytest.raises(HTTPException) as exc:
        cascade_progress.snapshot("done", 1)
    assert exc.value.status_code == 404


def test_peer_preparation_failure_preserves_successful_side():
    cascade_progress.start("run", 1, 10, 20, "awg")
    cascade_progress.event("run", "entry", "ready")
    cascade_progress.event("run", "exit", "failed", "error")
    cascade_progress.finish("run", "error")
    snapshot = cascade_progress.snapshot("run", 1)
    assert snapshot["sides"]["entry"]["status"] == "done"
    assert snapshot["sides"]["exit"]["status"] == "error"


def test_cancellation_finishes_active_side_without_claiming_peer_started():
    cascade_progress.start("run", 1, 10, 20, "awg")
    cascade_progress.event("run", "exit", "pulling_image")
    cascade_progress.finish("run", "cancelled")
    snapshot = cascade_progress.snapshot("run", 1)
    assert snapshot["status"] == "cancelled"
    assert snapshot["sides"]["exit"]["stage"] == "cancelled"
    assert snapshot["sides"]["entry"]["started_at"] is None
