"""Persistent browser sessions. Access tokens keep their regular JWT lifetime."""

import hashlib
import hmac
import math
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from fastapi import Request, Response
from sqlalchemy import delete, exists, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import RememberedSession, User

COOKIE_NAME = "accontrol_refresh"
COOKIE_PATH = "/api/auth"
ABSOLUTE_TTL = timedelta(days=30)
IDLE_TTL = timedelta(days=7)
ROTATION_GRACE = timedelta(seconds=5)
SESSION_ID = re.compile(r"[0-9a-f]{32}")
_TOKEN = re.compile(r"([0-9a-f]{32})\.([1-9][0-9]{0,17})\.[A-Za-z0-9_-]{43}\.[0-9a-f]{64}")
_PURPOSE = b"acontrol:remembered-session:v1:"


@dataclass(frozen=True)
class CookieProof:
    session_id: str
    generation: int
    digest: str


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def as_utc(value: datetime) -> datetime:
    # SQLite returns timestamps without a timezone. All session times are UTC.
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def _tag(value: str, secret: str) -> str:
    return hmac.digest(secret.encode(), _PURPOSE + value.encode("ascii"), "sha256").hex()


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def _mint(session_id: str, generation: int, secret: str) -> str:
    value = f"{session_id}.{generation}.{secrets.token_urlsafe(32)}"
    return f"{value}.{_tag(value, secret)}"


def read_cookie(request: Request, secret: str) -> CookieProof | None:
    token = request.cookies.get(COOKIE_NAME, "")
    match = _TOKEN.fullmatch(token)
    if match is None:
        return None
    value, tag = token.rsplit(".", 1)
    if not hmac.compare_digest(tag, _tag(value, secret)):
        return None
    return CookieProof(match[1], int(match[2]), _digest(token))


def valid_browser_request(request: Request) -> bool:
    # The header cannot be set on a cross-origin browser request without an
    # approved CORS preflight. SameSite and Fetch Metadata also reject requests
    # from another origin on the same site.
    return request.headers.get("x-acontrol-session") == "1" and request.headers.get(
        "sec-fetch-site", "same-origin"
    ) == "same-origin"


def expires_at(row: RememberedSession) -> datetime:
    return min(as_utc(row.expires_at), as_utc(row.last_used_at) + IDLE_TTL)


def set_cookie(response: Response, token: str, deadline: datetime) -> None:
    # The HTTPS edge can forward via another HTTP proxy. The browser enforces
    # Secure on the public connection, independently of the internal scheme.
    response.set_cookie(
        COOKIE_NAME, token, max_age=max(0, math.ceil((deadline - utcnow()).total_seconds())),
        path=COOKIE_PATH, secure=True, httponly=True, samesite="strict",
    )


def clear_cookie(response: Response) -> None:
    response.delete_cookie(COOKIE_NAME, path=COOKIE_PATH, secure=True, httponly=True, samesite="strict")


def active_at(now: datetime):
    return (
        RememberedSession.expires_at > now,
        RememberedSession.last_used_at > now - IDLE_TTL,
    )


def _matches(proof: CookieProof):
    return (
        RememberedSession.id == proof.session_id,
        RememberedSession.generation == proof.generation,
        RememberedSession.token_digest == proof.digest,
    )


async def start_login(
    session: AsyncSession, user: User, request: Request, secret: str, remember: bool,
) -> tuple[RememberedSession, str] | None:
    proof = read_cookie(request, secret)
    if not remember and proof is None:
        return None
    now = utcnow()
    stale = [
        RememberedSession.token_version < user.token_version,
        RememberedSession.expires_at <= now,
        RememberedSession.last_used_at <= now - IDLE_TTL,
    ]
    if proof is not None:
        # The credential was authenticated before using the id. A pending
        # concurrent refresh must not keep the old browser session alive.
        stale.append(RememberedSession.id == proof.session_id)
    await session.execute(delete(RememberedSession).where(
        RememberedSession.user_id == user.id, or_(*stale),
    ))
    issued = None
    if remember:
        session_id = secrets.token_hex(16)
        token = _mint(session_id, 1, secret)
        row = RememberedSession(
            id=session_id, user_id=user.id, token_version=user.token_version,
            generation=1, token_digest=_digest(token),
            user_agent=request.headers.get("user-agent", "").replace("\x00", "")[:255],
            created_at=now, last_used_at=now, expires_at=now + ABSOLUTE_TTL,
        )
        session.add(row)
        issued = row, token
    await session.commit()
    return issued


async def authenticate_cookie(session: AsyncSession, proof: CookieProof) -> User | None:
    return await session.scalar(select(User).join(
        RememberedSession, RememberedSession.user_id == User.id,
    ).where(
        *_matches(proof), *active_at(utcnow()), RememberedSession.token_version == User.token_version,
    ))


async def rotate(
    session: AsyncSession, proof: CookieProof, secret: str,
) -> tuple[tuple[RememberedSession, str] | None, int | None]:
    """Return the rotated session/cookie pair and the user id of any revoked replay."""
    now = utcnow()
    new_generation = proof.generation + 1
    new_token = _mint(proof.session_id, new_generation, secret)
    usable = (
        *active_at(now),
        exists().where(User.id == RememberedSession.user_id, User.token_version == RememberedSession.token_version),
    )
    # The matching UPDATE is the first DB statement, so both PostgreSQL and
    # SQLite arbitrate concurrent refreshes before checking the losing token.
    row = await session.scalar(update(RememberedSession).where(
        *_matches(proof), *usable,
    ).values(
        generation=new_generation, token_digest=_digest(new_token), last_used_at=now,
    ).returning(RememberedSession))
    if row is not None:
        await session.commit()
        return (row, new_token), None

    # The HMAC proves this is a token we issued. A made-up verifier with a
    # known id never reaches this query. Give simultaneous requests a brief
    # window, without yielding any new credentials to callers of the old token.
    grace_cutoff = now - ROTATION_GRACE
    replayed_user = await session.scalar(delete(RememberedSession).where(
        RememberedSession.id == proof.session_id, RememberedSession.generation > proof.generation,
        RememberedSession.last_used_at <= grace_cutoff, *usable,
    ).returning(RememberedSession.user_id))
    predecessor = False
    if replayed_user is None:
        predecessor = await session.scalar(select(RememberedSession.id).where(
            RememberedSession.id == proof.session_id, RememberedSession.generation == new_generation,
            RememberedSession.last_used_at > grace_cutoff, *usable,
        )) is not None
    await session.commit()
    if predecessor:
        raise ConcurrentRotation
    return None, replayed_user


class ConcurrentRotation(Exception):
    """The immediately preceding browser request already rotated the token."""
