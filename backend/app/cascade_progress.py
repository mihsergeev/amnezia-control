"""Small, log-free snapshots of actual cascade work, scoped to its caller."""

import copy
import time
from datetime import datetime, timezone

from fastapi import HTTPException

MAX_RUNS = 128
TERMINAL_TTL = 15 * 60
SIDES = ("entry", "exit")
STAGES = frozenset({
    "queued", "connecting", "checking_image", "building_image", "pulling_image",
    "preparing", "ready", "transferring", "cleanup", "completed", "failed", "cancelled",
    "installing",
})
_runs: dict[str, dict] = {}


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def pending() -> dict:
    return {side: {"status": "pending", "stage": "queued", "started_at": None,
                   "updated_at": None} for side in SIDES}


def update(sides: dict, side: str, stage: str, status: str = "running") -> None:
    if side not in SIDES or stage not in STAGES or status not in {"pending", "running", "done", "error"}:
        raise ValueError("Invalid cascade progress event")
    timestamp = now()
    item = sides[side]
    if item["started_at"] is None and status == "running":
        item["started_at"] = timestamp
    item.update(stage=stage, status=status, updated_at=timestamp)


def _expire() -> None:
    cutoff = time.monotonic() - TERMINAL_TTL
    for key, item in list(_runs.items()):
        if item["finished"] is not None and item["finished"] <= cutoff:
            del _runs[key]


def start(run_id: str, user_id: int, entry_id: int, exit_id: int, transport: str) -> None:
    _expire()
    if run_id in _runs:
        raise HTTPException(409, "Идентификатор проверки уже использован")
    if len(_runs) >= MAX_RUNS:
        raise HTTPException(429, "Слишком много проверок, повторите позже")
    timestamp = now()
    _runs[run_id] = {"user_id": user_id, "finished": None, "snapshot": {
        "run_id": run_id, "entry_server_id": entry_id, "exit_server_id": exit_id,
        "transport": transport, "status": "running", "started_at": timestamp,
        "updated_at": timestamp, "sides": pending(),
    }}


def event(run_id: str, side: str, stage: str, status: str = "running") -> None:
    item = _runs[run_id]["snapshot"]
    update(item["sides"], side, stage, status)
    item["updated_at"] = now()


def finish(run_id: str, status: str) -> None:
    item = _runs[run_id]
    snapshot = item["snapshot"]
    snapshot.update(status=status, updated_at=now())
    item["finished"] = time.monotonic()
    for side, value in snapshot["sides"].items():
        if value["status"] == "running":
            # Preparation can succeed on one node while its peer fails.
            complete = status == "done" or status == "error" and value["stage"] == "ready"
            event(run_id, side, "cancelled" if status == "cancelled" else
                  "completed" if complete else "failed", "done" if complete else "error")


def snapshot(run_id: str, user_id: int) -> dict:
    _expire()
    item = _runs.get(run_id)
    if item is None or item["user_id"] != user_id:
        raise HTTPException(404, "Ход проверки не найден")
    return copy.deepcopy(item["snapshot"])
