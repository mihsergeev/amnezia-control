import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app import alerts, audit
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
            # Сменили ACONTROL_ADMIN_USER на уже работающей панели: переименовываем
            # единственного пользователя, а не заводим второго админа с паролем из .env
            users = list((await session.scalars(select(User))).all())
            if len(users) == 1:
                old = users[0].username
                users[0].username = settings.admin_user
                await session.commit()
                log.warning("админ %s переименован в %s по .env", old, settings.admin_user)
                user = users[0]
            elif users:
                log.warning(
                    "пользователя %s нет, в базе их %d, новый админ не создан",
                    settings.admin_user,
                    len(users),
                )
                return
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
                "АВАРИЙНЫЙ СБРОС пароля админа выполнен - уберите "
                "ACONTROL_ADMIN_PASSWORD_RESET из .env и пересоздайте контейнер"
            )
            # забытый флаг сбрасывает пароль и 2FA на каждом рестарте, пусть это видно
            await audit.record(session, "system", "admin_password_reset", user.username)
            await alerts.security_alert(
                session, settings,
                alerts.Card(
                    "warn", "🔑", alerts.t("Пароль «{user}» сброшен из .env", user=user.username),
                    alerts.t(
                        "2FA отключена. Уберите флаг сброса из .env, иначе это повторится "
                        "при каждом перезапуске"
                    ),
                ),
            )
