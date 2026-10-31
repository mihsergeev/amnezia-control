"""Степ-ап аутентификация: повторная проверка пароля перед опасным действием
(экспорт полного доступа с root-ключом, бэкап и восстановление, 2FA, смена
пароля, API-ключи, алерты, выгрузка сервера) с антибрутфорсом по IP - отдельным
ключом от лимитера входа, чтобы не блокировать сам вход.

При включенной 2FA нужен еще и код: пароль без кода по украденной сессии
опасное действие не открывает. Код приходит параметром otp или заголовком
X-Confirm-OTP (так его передают ручки, у которых тело занято или задано без
поля кода)."""

from fastapi import HTTPException, Request, status
from sqlalchemy import update
from sqlalchemy.ext.asyncio import async_object_session

from app import ratelimit, totp
from app.clientip import client_ip
from app.models import User
from app.security import averify_password

# машиночитаемый признак для фронта: показать поле кода 2FA
OTP_HEADER = {"X-Need-OTP": "1"}


def _key(request: Request) -> str:
    return f"stepup:{ratelimit.ip_key(client_ip(request))}"


def _user_key(user: User) -> str:
    # отдельный счетчик на пользователя: с разных адресов (меш, мобильный
    # интернет) пароль иначе перебирался бы по MAX_FAILURES с каждого
    return f"stepup-user:{getattr(user, 'username', '')}"


async def consume_otp(session, user: User, otp: str) -> bool:
    """Проверяет код и атомарно помечает его использованным (защита от повтора).

    Счетчик двигается одним UPDATE с условием: два параллельных запроса с одним
    кодом раньше оба проходили между проверкой и записью."""
    counter = totp.matched_counter(user.totp_secret, otp)
    if counter is None:
        return False
    res = await session.execute(
        update(User)
        .where(User.id == user.id, User.totp_last_counter < counter)
        .values(totp_last_counter=counter)
    )
    await session.commit()  # фиксируем счётчик ДО audit (у audit свой rollback)
    return res.rowcount == 1


def _fail(keys: tuple[str, str]) -> None:
    for k in keys:
        ratelimit.record_failure(k)


async def verify(
    user: User, password: str, request: Request, otp: str | None = None
) -> None:
    """Проверяет пароль (и код 2FA, если она включена). 429 при блокировке
    (слишком много попыток), 403 при неверном пароле или коде. При успехе -
    тихо возвращает и сбрасывает счётчики."""
    keys = (_key(request), _user_key(user))
    if any(ratelimit.is_locked(k) for k in keys):
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Слишком много неверных попыток — подождите немного.",
        )
    if not await averify_password(password or "", user.password_hash):
        _fail(keys)
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Неверный пароль")
    if getattr(user, "totp_enabled", False):
        if otp is None:
            headers = getattr(request, "headers", None)
            otp = headers.get("x-confirm-otp", "") if headers is not None else ""
        otp = (otp or "").strip()[:16]
        if not otp:
            # без записи неудачи: пароль верный, просто окно еще не спросило код
            raise HTTPException(
                status.HTTP_403_FORBIDDEN, "Нужен код 2FA", headers=OTP_HEADER
            )
        session = async_object_session(user)
        if session is None or not await consume_otp(session, user, otp):
            _fail(keys)
            raise HTTPException(
                status.HTTP_403_FORBIDDEN, "Неверный код 2FA", headers=OTP_HEADER
            )
    for k in keys:
        ratelimit.clear(k)
