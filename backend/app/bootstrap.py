from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.config import Settings
from app.models import User
from app.security import hash_password


async def ensure_admin(
    session_factory: async_sessionmaker[AsyncSession], settings: Settings
) -> None:
    """Заводит админа ТОЛЬКО при первом старте (когда пользователя ещё нет).

    Пароль НЕ пересинхронизируется с .env на каждом запуске — иначе смена пароля
    через UI откатывалась бы при рестарте. Пароль из .env — только начальный;
    дальше меняется через POST /auth/password.
    """
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
