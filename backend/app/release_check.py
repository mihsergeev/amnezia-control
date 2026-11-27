import asyncio
import json
import re
from datetime import UTC, datetime
from time import monotonic

import httpx

from app.schemas import ReleaseCheckOut, ReleaseCheckStatus

_REPO = "mihsergeev/amnezia-control"
_LATEST_RELEASE_API = f"https://api.github.com/repos/{_REPO}/releases/latest"
_RELEASE_TAG_URL = f"https://github.com/{_REPO}/releases/tag/"
_VERSION = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
_HTTP_TIMEOUT = 5
_MAX_RESPONSE_BYTES = 256 * 1024
_SUCCESS_TTL = 6 * 60 * 60
_FAILURE_TTL = 5 * 60
_MANUAL_INTERVAL = 60


def _version_parts(version: str) -> tuple[int, ...] | None:
    match = _VERSION.fullmatch(version)
    if not match:
        return None
    try:
        return tuple(map(int, match.groups()))
    except ValueError:  # Python ограничивает размер входа для int().
        return None


async def _fetch_latest_tag() -> str | None:
    body = bytearray()
    try:
        async with asyncio.timeout(_HTTP_TIMEOUT):
            async with httpx.AsyncClient(
                timeout=_HTTP_TIMEOUT, verify=True, trust_env=False, follow_redirects=False,
                headers={"Accept": "application/vnd.github+json", "Accept-Encoding": "identity"},
            ) as client:
                async with client.stream("GET", _LATEST_RELEASE_API) as response:
                    response.raise_for_status()
                    if response.headers.get("Content-Encoding", "identity").lower() != "identity":
                        return None
                    async for chunk in response.aiter_raw():
                        if len(body) + len(chunk) > _MAX_RESPONSE_BYTES:
                            return None
                        body.extend(chunk)
        release = json.loads(body)
    except (httpx.HTTPError, TimeoutError, ValueError, RecursionError):
        return None

    if (
        not isinstance(release, dict)
        or release.get("draft") is not False
        or release.get("prerelease") is not False
    ):
        return None
    tag = release.get("tag_name")
    return tag if isinstance(tag, str) else None


class ReleaseCheck:
    def __init__(self, current_version: str, *, enabled: bool) -> None:
        self._current_parts = _version_parts(current_version.removeprefix("v"))
        self._lock = asyncio.Lock()
        self._automatic_check_at = float("-inf")
        self._manual_check_at = float("-inf")
        self._result = ReleaseCheckOut(
            current_version=current_version, status="unavailable" if enabled else "disabled",
        )

    async def check(self, *, manual: bool = False) -> ReleaseCheckOut:
        if self._result.status == "disabled":
            return self._result
        async with self._lock:
            now = monotonic()
            if now < self._manual_check_at or (not manual and now < self._automatic_check_at):
                return self._result

            tag = None
            try:
                tag = await _fetch_latest_tag()
            finally:
                # Отмена запроса тоже считается неудавшейся попыткой.
                self._finish_check(tag)
            return self._result

    def _finish_check(self, tag: str | None) -> None:
        now = monotonic()
        checked_at = datetime.now(UTC)
        latest_parts = _version_parts(tag[1:]) if tag and tag.startswith("v") else None
        if tag is None or latest_parts is None:
            self._automatic_check_at = self._manual_check_at = now + _FAILURE_TTL
            self._result = self._result.model_copy(update={
                "checked_at": checked_at,
                "stale": self._result.latest_version is not None,
            })
            return

        status: ReleaseCheckStatus
        if self._current_parts is None:
            status = "unknown"
        elif latest_parts > self._current_parts:
            status = "available"
        elif latest_parts < self._current_parts:
            status = "ahead"
        else:
            status = "up_to_date"
        self._automatic_check_at = now + _SUCCESS_TTL
        self._manual_check_at = now + _MANUAL_INTERVAL
        self._result = ReleaseCheckOut(
            current_version=self._result.current_version,
            latest_version=tag,
            release_url=f"{_RELEASE_TAG_URL}{tag}",
            status=status,
            checked_at=checked_at,
        )
