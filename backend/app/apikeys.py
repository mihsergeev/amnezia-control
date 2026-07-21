"""Ключи интеграционного API (/api/v1) — выпуск, проверка, отзыв.

Модель хранения как у паролей: в БД только bcrypt-хэш секрета, полный ключ
показывается один раз при создании и больше нигде не восстановим. Ключ состоит
из открытого префикса и секрета: `ack_<prefix>_<secret>`. Префикс лежит в БД
открытым и проиндексирован — по нему находим строку одним запросом и сверяем
хэш только с ней (иначе пришлось бы прогонять bcrypt по всей таблице).
"""

import secrets
from datetime import datetime, timezone

import bcrypt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import ApiKey

PREFIX_LEN = 8
SECRET_LEN = 32
_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"


def _token(n: int) -> str:
    return "".join(secrets.choice(_ALPHABET) for _ in range(n))


def generate() -> tuple[str, str, str]:
    """Возвращает (полный ключ, префикс, bcrypt-хэш секрета)."""
    prefix, secret = _token(PREFIX_LEN), _token(SECRET_LEN)
    key_hash = bcrypt.hashpw(secret.encode(), bcrypt.gensalt()).decode()
    return f"ack_{prefix}_{secret}", prefix, key_hash


def split(key: str) -> tuple[str, str] | None:
    """Разбирает `ack_<prefix>_<secret>`. None — формат не наш."""
    parts = (key or "").strip().split("_")
    if len(parts) != 3 or parts[0] != "ack" or not parts[1] or not parts[2]:
        return None
    return parts[1], parts[2]


async def authenticate(session: AsyncSession, key: str) -> ApiKey | None:
    """Ищет действующий ключ по префиксу и сверяет секрет. None — не подошёл.

    Отмечает last_used_at (для UI: видно, живёт ли интеграция). Отозванные
    ключи не проходят: проверяем revoked ДО сверки хэша.
    """
    parsed = split(key)
    if parsed is None:
        return None
    prefix, secret = parsed
    row = await session.scalar(select(ApiKey).where(ApiKey.prefix == prefix))
    if row is None or row.revoked:
        return None
    try:
        if not bcrypt.checkpw(secret.encode(), row.key_hash.encode()):
            return None
    except ValueError:  # битый хэш в БД — считаем ключ негодным, а не падаем
        return None
    row.last_used_at = datetime.now(timezone.utc)
    await session.commit()
    return row
