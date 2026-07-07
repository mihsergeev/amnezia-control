from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.config import Settings
from app.models import User
from app.security import hash_password, verify_password


async def ensure_admin(
    session_factory: async_sessionmaker[AsyncSession], settings: Settings
) -> None:
    """Создаёт админа при первом старте; синхронизирует пароль с .env."""
    async with session_factory() as session:
        user = await session.scalar(
            select(User).where(User.username == settings.admin_user)
        )
        if user is None:
            session.add(
                User(
                    username=settings.admin_user,
                    password_hash=hash_password(settings.admin_password),
                )
            )
            await session.commit()
        elif not verify_password(settings.admin_password, user.password_hash):
            user.password_hash = hash_password(settings.admin_password)
            await session.commit()
