"""Журнал действий: запись событий в audit_log."""

from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AuditLog


async def record(
    session: AsyncSession,
    username: str,
    action: str,
    target: str = "",
    detail: str = "",
) -> None:
    """Пишет запись в журнал (best-effort, не должно ронять основную операцию)."""
    try:
        session.add(
            AuditLog(
                username=username or "",
                action=action,
                target=str(target)[:255],
                detail=str(detail)[:2000],
            )
        )
        await session.commit()
    except Exception:  # noqa: BLE001 — журнал не критичен
        await session.rollback()
