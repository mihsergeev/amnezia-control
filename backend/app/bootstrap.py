import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.config import Settings
from app.models import User
from app.security import hash_password

log = logging.getLogger("acontrol.bootstrap")


async def ensure_admin(
    session_factory: async_sessionmaker[AsyncSession], settings: Settings
) -> None:
    """Заводит админа ТОЛЬКО при первом старте (когда пользователя ещё нет).

    Пароль НЕ пересинхронизируется с .env на каждом запуске — иначе смена пароля
    через UI откатывалась бы при рестарте. Пароль из .env — только начальный;
    дальше меняется через POST /auth/password.

    Break-glass: если VPNPANEL_ADMIN_PASSWORD_RESET=1 — сбрасывает пароль на
    admin_password и отключает 2FA (на случай утери пароля И 2FA).
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
        elif settings.admin_password_reset:
            user.password_hash = hash_password(settings.admin_password)
            user.totp_enabled = False
            user.totp_secret = ""
            user.token_version += 1  # инвалидируем все старые токены
            await session.commit()
            log.warning(
                "АВАРИЙНЫЙ СБРОС пароля админа выполнен — удалите "
                "VPNPANEL_ADMIN_PASSWORD_RESET из .env и перезапустите"
            )
