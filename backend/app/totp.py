"""TOTP (RFC 6238) на стандартной библиотеке — без внешних зависимостей."""

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote


def random_secret() -> str:
    """Base32-секрет (20 байт энтропии), без padding — как ждут authenticator-приложения."""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _hotp(secret_b32: str, counter: int, digits: int = 6) -> str:
    pad = "=" * ((8 - len(secret_b32) % 8) % 8)
    key = base64.b32decode(secret_b32.upper() + pad)
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    code = struct.unpack(">I", mac[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10**digits)).zfill(digits)


def verify(
    secret_b32: str, code: str, *, window: int = 1, now: float | None = None
) -> bool:
    """Проверяет код с допуском ±window шагов по 30с (клок-дрейф)."""
    if not secret_b32 or not code:
        return False
    code = code.strip()
    if not code.isdigit():
        return False
    step = int((time.time() if now is None else now) // 30)
    try:
        return any(
            hmac.compare_digest(_hotp(secret_b32, step + w), code)
            for w in range(-window, window + 1)
        )
    except (ValueError, TypeError):
        return False


def provisioning_uri(
    secret_b32: str, account: str, issuer: str = "Amnezia Control"
) -> str:
    label = quote(f"{issuer}:{account}")
    return (
        f"otpauth://totp/{label}?secret={secret_b32}"
        f"&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period=30"
    )
