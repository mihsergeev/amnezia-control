"""Ключи интеграционного API (/api/v1) — выпуск, проверка, отзыв.

Модель хранения как у паролей: в БД только bcrypt-хэш секрета, полный ключ
показывается один раз при создании и больше нигде не восстановим. Ключ состоит
из открытого префикса и секрета: `ack_<prefix>_<secret>`. Префикс лежит в БД
открытым и проиндексирован — по нему находим строку одним запросом и сверяем
хэш только с ней (иначе пришлось бы прогонять bcrypt по всей таблице).
"""

import asyncio
import hashlib
import secrets
import time
from datetime import datetime, timezone

import bcrypt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import ApiKey

PREFIX_LEN = 8
SECRET_LEN = 32
_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"

# Кэш успешных проверок: sha256 ключа -> (id строки, хэш, назначение, срок кэша).
# bcrypt ~0.2 с на запрос, а интеграция ходит часто. Отзыв и срок проверяются
# по строке из БД на каждом запросе, так что кэш их не обходит.
CACHE_TTL = 300
CACHE_MAX = 1000
_ok_cache: dict[str, tuple[int, str, str, float]] = {}


def _token(n: int) -> str:
    return "".join(secrets.choice(_ALPHABET) for _ in range(n))


def _hash_input(secret: str, scope: str) -> bytes:
    # Older releases restored from a newer backup cannot use a monitoring
    # key: their token grammar does not allow an underscore inside the secret.
    return ("stats_" + secret if scope == "stats" else secret).encode()


def generate(scope: str = "clients") -> tuple[str, str, str]:
    """Возвращает (полный ключ, префикс, bcrypt-хэш секрета)."""
    prefix, secret = _token(PREFIX_LEN), _token(SECRET_LEN)
    key_hash = bcrypt.hashpw(_hash_input(secret, scope), bcrypt.gensalt()).decode()
    return f"ack_{prefix}_{secret}", prefix, key_hash


def expired(row: ApiKey, now: datetime | None = None) -> bool:
    if row.expires_at is None:
        return False
    exp = row.expires_at
    if exp.tzinfo is None:  # SQLite отдает дату без пояса
        exp = exp.replace(tzinfo=timezone.utc)
    return exp <= (now or datetime.now(timezone.utc))


def split(key: str) -> tuple[str, str] | None:
    """Разбирает `ack_<prefix>_<secret>`. None — формат не наш."""
    parts = (key or "").strip().split("_")
    if len(parts) != 3 or parts[0] != "ack" or not parts[1] or not parts[2]:
        return None
    return parts[1], parts[2]


def _check(secret: str, key_hash: str, scope: str) -> bool:
    try:
        return bcrypt.checkpw(_hash_input(secret, scope), key_hash.encode())
    except ValueError:  # битый хэш в БД — считаем ключ негодным, а не падаем
        return False


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
    if row is None or row.revoked or expired(row) or row.scope not in ("clients", "stats"):
        return None
    digest = hashlib.sha256(key.strip().encode()).hexdigest()
    now = time.monotonic()
    cached = _ok_cache.get(digest)
    identity = (row.id, row.key_hash, row.scope)
    if not (cached and cached[:3] == identity and cached[3] > now):
        # bcrypt в отдельном потоке: в event loop он вешал панель на время
        # перебора по известному префиксу
        if not await asyncio.to_thread(_check, secret, row.key_hash, row.scope):
            _ok_cache.pop(digest, None)
            return None
        if len(_ok_cache) >= CACHE_MAX:
            _ok_cache.clear()
        _ok_cache[digest] = (*identity, now + CACHE_TTL)
    row.last_used_at = datetime.now(timezone.utc)
    await session.commit()
    return row


async def forget_servers(session: AsyncSession, existing: set[int] | None = None,
                         removed: int | None = None) -> int:
    """Убирает из ограничений ключей серверы, которых больше нет. SQLite
    выдает id удаленного сервера заново, и ключ с устаревшим id получал бы
    доступ к новому серверу. Ключ, у которого не осталось серверов,
    отзывается: пустой список означает «все серверы», а не «ни одного».
    Возвращает число отозванных ключей. Коммит за вызывающим."""
    revoked = 0
    rows = (await session.scalars(
        select(ApiKey).where(ApiKey.revoked.is_(False), ApiKey.servers != "")
    )).all()
    for row in rows:
        ids = row.server_ids
        if removed is not None:
            keep = [i for i in ids if i != removed]
        else:
            keep = [i for i in ids if existing is not None and i in existing]
        if keep == ids:
            continue
        if keep:
            row.servers = ",".join(str(i) for i in keep)
        else:
            row.revoked = True
            revoked += 1
    return revoked
