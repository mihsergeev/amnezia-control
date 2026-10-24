from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from starlette.concurrency import run_in_threadpool


def _pw(password: str) -> bytes:
    # bcrypt учитывает только первые 72 байта. До 5.0 он молча обрезал длиннее,
    # с 5.0 бросает ValueError, и длинный пароль из .env ронял старт панели.
    # Обрезаем сами - так же, как раньше, поэтому старые хэши остаются валидными.
    return password.encode()[:72]


def hash_password(password: str) -> str:
    return bcrypt.hashpw(_pw(password), bcrypt.gensalt()).decode()


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(_pw(password), password_hash.encode())
    except ValueError:
        return False


async def averify_password(password: str, password_hash: str) -> bool:
    """verify_password вне event loop: bcrypt считает ~0.2 с, и поток входов
    иначе тормозил бы всю панель вместе с фоновыми задачами."""
    return await run_in_threadpool(verify_password, password, password_hash)


def create_access_token(
    username: str, secret: str, ttl_minutes: int, token_version: int = 0
) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "ver": token_version,
        "iat": now,
        "exp": now + timedelta(minutes=ttl_minutes),
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def decode_access_token(token: str, secret: str) -> dict | None:
    """Возвращает payload (sub/ver/…) при валидной подписи и сроке, иначе None."""
    try:
        payload = jwt.decode(token, secret, algorithms=["HS256"])
    except jwt.PyJWTError:
        return None
    if not isinstance(payload.get("sub"), str):
        return None
    return payload
