"""Revocable browser proof for future password sign-ins to TOTP accounts."""

import hashlib
import math
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from fastapi import Request, Response
from sqlalchemy import and_, delete, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app import stepup
from app.models import TrustedDevice, User
from app.remembered_sessions import as_utc, valid_browser_request

COOKIE_NAME = "accontrol_trusted_device"
COOKIE_PATH = "/api/auth"
ABSOLUTE_TTL = timedelta(days=30)
MAX_DEVICES = 20
DEVICE_ID = re.compile(r"[0-9a-f]{32}")
_TOKEN = re.compile(r"([0-9a-f]{32})\.[A-Za-z0-9_-]{43}")


@dataclass(frozen=True)
class CookieProof:
    device_id: str
    digest: str


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def read_cookie(request: Request) -> CookieProof | None:
    if not valid_browser_request(request):
        return None
    token = request.cookies.get(COOKIE_NAME, "")
    match = _TOKEN.fullmatch(token)
    return CookieProof(match[1], _digest(token)) if match else None


def set_cookie(response: Response, token: str, deadline: datetime) -> None:
    response.set_cookie(
        COOKIE_NAME, token, max_age=max(0, math.ceil((deadline - utcnow()).total_seconds())),
        path=COOKIE_PATH, secure=True, httponly=True, samesite="strict",
    )


def clear_cookie(response: Response) -> None:
    response.delete_cookie(COOKIE_NAME, path=COOKIE_PATH, secure=True, httponly=True, samesite="strict")


def _matches(proof: CookieProof):
    return TrustedDevice.id == proof.device_id, TrustedDevice.token_digest == proof.digest


async def issue(
    session: AsyncSession, user: User, request: Request,
) -> tuple[TrustedDevice, str]:
    """Register after consuming a fresh OTP, in the same transaction."""
    now = utcnow()
    proof = read_cookie(request)
    stale = [TrustedDevice.expires_at <= now]
    if proof is not None:
        # A fresh OTP can renew this browser without leaving its previous proof active.
        stale.append(and_(*_matches(proof)))
    await session.execute(delete(TrustedDevice).where(
        TrustedDevice.user_id == user.id, or_(*stale),
    ))
    excess = select(TrustedDevice.id).where(TrustedDevice.user_id == user.id).order_by(
        TrustedDevice.created_at.desc(), TrustedDevice.id,
    ).offset(MAX_DEVICES - 1)
    await session.execute(delete(TrustedDevice).where(TrustedDevice.id.in_(excess)))
    device_id = secrets.token_hex(16)
    token = f"{device_id}.{secrets.token_urlsafe(32)}"
    row = TrustedDevice(
        id=device_id, user_id=user.id, token_digest=_digest(token),
        user_agent=request.headers.get("user-agent", "").replace("\x00", "")[:255],
        created_at=now, last_used_at=now, expires_at=now + ABSOLUTE_TTL,
    )
    session.add(row)
    return row, token


async def use(session: AsyncSession, user: User, request: Request) -> bool:
    proof = read_cookie(request)
    if proof is None:
        return False
    # Validate the password snapshot and serialize with account changes before
    # touching the device. Failed lookups roll back when login returns 401.
    user_id = await session.scalar(update(User).where(
        *stepup.credential_conditions(user),
    ).values(token_version=User.token_version).returning(User.id).execution_options(
        synchronize_session=False,
    ))
    if user_id is None:
        return False
    now = utcnow()
    device_id = await session.scalar(update(TrustedDevice).where(
        TrustedDevice.user_id == user_id, *_matches(proof), TrustedDevice.expires_at > now,
    ).values(last_used_at=now).returning(TrustedDevice.id))
    return device_id is not None


async def revoke_all(session: AsyncSession, user_id: int) -> None:
    """Clear the account's device proofs in the credential change transaction."""
    await session.execute(delete(TrustedDevice).where(TrustedDevice.user_id == user_id))


def is_current(row: TrustedDevice, proof: CookieProof | None) -> bool:
    return (
        proof is not None and row.id == proof.device_id
        and secrets.compare_digest(row.token_digest, proof.digest)
    )
