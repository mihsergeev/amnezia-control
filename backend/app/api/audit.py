from fastapi import APIRouter, Query
from sqlalchemy import select

from app.deps import CurrentUser, SessionDep
from app.models import AuditLog
from app.schemas import AuditEntryOut

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("", response_model=list[AuditEntryOut])
async def list_audit(
    _: CurrentUser,
    session: SessionDep,
    limit: int = Query(default=200, ge=1, le=1000),
) -> list[AuditLog]:
    rows = await session.scalars(
        select(AuditLog).order_by(AuditLog.id.desc()).limit(limit)
    )
    return list(rows)
