"""Степ-ап аутентификация: повторная проверка пароля перед опасным действием
(экспорт полного доступа с root-ключом, смена пароля) с антибрутфорсом по IP —
отдельным ключом от лимитера входа, чтобы не блокировать сам вход."""

from fastapi import HTTPException, Request, status

from app import ratelimit
from app.clientip import client_ip
from app.models import User
from app.security import verify_password


def _key(request: Request) -> str:
    return f"stepup:{client_ip(request)}"


def verify(user: User, password: str, request: Request) -> None:
    """Проверяет пароль. 429 при блокировке (слишком много попыток), 403 при
    неверном пароле. При успехе — тихо возвращает и сбрасывает счётчик."""
    key = _key(request)
    if ratelimit.is_locked(key):
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Слишком много неверных попыток — подождите немного.",
        )
    if not verify_password(password, user.password_hash):
        ratelimit.record_failure(key)
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Неверный пароль")
    ratelimit.clear(key)
