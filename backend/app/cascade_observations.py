"""Merge independent manual and watchdog observations without losing either."""

import json
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import String, cast, or_, update

from app.models import Cascade

WRITE_ATTEMPTS = 3


@dataclass(frozen=True)
class Generation:
    id: int
    entry_server_id: int
    exit_server_id: int
    transport: str
    status: str
    params: str
    created_at: datetime

    @classmethod
    def of(cls, row: Cascade) -> "Generation":
        return cls(row.id, row.entry_server_id, row.exit_server_id, row.transport,
                   row.status, row.params, row.created_at)


def newer_than(saved: dict, stamp: datetime) -> bool:
    try:
        at = datetime.fromisoformat(saved["checked_at"])
    except (KeyError, TypeError, ValueError):
        return False
    return (at if at.tzinfo else at.replace(tzinfo=timezone.utc)) > stamp


def merge_paths(result: dict, paths: dict, stamp: datetime) -> bool:
    # Keep the newest measured addresses and crypto state, regardless of which
    # check reached the database first.
    if newer_than(result, stamp):
        return False
    result.update(paths, checked_at=stamp.isoformat())
    return True


async def save(session, generation: Generation, old: str, result: dict) -> bool:
    created = Cascade.created_at == generation.created_at
    if session.get_bind().dialect.name == "sqlite" and not generation.created_at.microsecond:
        # SQLite CURRENT_TIMESTAMP has no fraction; SQLAlchemy's bound
        # datetime has .000000 even though both decode to the same timestamp.
        created = or_(
            created, cast(Cascade.created_at, String) == generation.created_at.strftime("%Y-%m-%d %H:%M:%S"),
        )
    saved = await session.execute(
        update(Cascade).where(
            Cascade.id == generation.id,
            Cascade.entry_server_id == generation.entry_server_id,
            Cascade.exit_server_id == generation.exit_server_id,
            Cascade.transport == generation.transport,
            Cascade.status == generation.status,
            Cascade.params == generation.params,
            created,
            Cascade.result == old,
        ).values(result=json.dumps(result)).execution_options(synchronize_session=False)
    )
    return saved.rowcount == 1
