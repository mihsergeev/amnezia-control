import asyncio
import json
from unittest.mock import AsyncMock

import httpx
import pytest

from app import release_check
from app.config import get_settings


async def test_updates_require_user_authentication(client, monkeypatch):
    fetch = AsyncMock(return_value="v1.2.3")
    monkeypatch.setattr(release_check, "_fetch_latest_tag", fetch)

    assert (await client.get("/api/updates")).status_code == 401
    assert (await client.post("/api/updates/check", headers={"X-API-Key": "invalid"})).status_code == 401
    fetch.assert_not_awaited()


async def test_concurrent_updates_share_one_cached_check(client, auth_headers, monkeypatch):
    fetch_started = asyncio.Event()
    finish_fetch = asyncio.Event()

    async def fetch_version():
        fetch_started.set()
        await finish_fetch.wait()
        return "v1.2.3"

    fetch = AsyncMock(side_effect=fetch_version)
    monkeypatch.setattr(release_check, "_fetch_latest_tag", fetch)

    async with asyncio.TaskGroup() as group:
        requests = [group.create_task(client.get("/api/updates", headers=auth_headers)) for _ in range(4)]
        requests.append(group.create_task(client.post("/api/updates/check", headers=auth_headers)))
        await asyncio.wait_for(fetch_started.wait(), timeout=5)
        finish_fetch.set()

    fetch.assert_awaited_once()
    responses = [request.result() for request in requests]
    payload = responses[0].json()
    assert payload == {
        "current_version": get_settings().version,
        "latest_version": "v1.2.3",
        "release_url": "https://github.com/mihsergeev/amnezia-control/releases/tag/v1.2.3",
        "status": "available",
        "checked_at": payload["checked_at"],
        "stale": False,
    }
    assert payload["checked_at"] and payload["checked_at"].endswith("Z")
    for response in responses:
        assert response.status_code == 200
        assert response.headers["Cache-Control"] == "no-store"
        assert response.json() == payload


@pytest.mark.parametrize(("current_version", "status"), [
    ("1.9.9", "available"),
    ("v1.10.0", "up_to_date"),
    ("1.10.1", "ahead"),
    ("1.10.0-dev", "unknown"),
])
async def test_compare_versions_numerically(current_version, status, monkeypatch):
    monkeypatch.setattr(release_check, "_fetch_latest_tag", AsyncMock(return_value="v1.10.0"))
    result = await release_check.ReleaseCheck(current_version, enabled=True).check()
    assert result.current_version == current_version
    assert result.status == status


async def test_success_cache_manual_limit_and_failure_backoff(monkeypatch):
    now = 10
    monkeypatch.setattr(release_check, "monotonic", lambda: now)
    fetch = AsyncMock(side_effect=["v1.2.3", None, "v1.3.0", "v1.4.0"])
    monkeypatch.setattr(release_check, "_fetch_latest_tag", fetch)
    check = release_check.ReleaseCheck("1.2.0", enabled=True)

    first = await check.check()
    now += 59
    assert await check.check(manual=True) == first
    now += 1
    assert await check.check() == first
    fetch.assert_awaited_once()

    failure = await check.check(manual=True)
    assert failure.status == first.status
    assert failure.latest_version == first.latest_version
    assert failure.release_url == first.release_url
    assert failure.checked_at >= first.checked_at
    assert failure.stale
    now += 299
    assert await check.check(manual=True) == failure
    assert await check.check() == failure
    assert fetch.await_count == 2

    now += 1
    recovered = await check.check()
    assert recovered.latest_version == "v1.3.0"
    assert not recovered.stale
    now += 6 * 60 * 60 - 1
    assert await check.check() == recovered
    now += 1
    assert (await check.check()).latest_version == "v1.4.0"
    assert fetch.await_count == 4


@pytest.mark.parametrize("manual", [False, True])
async def test_cancelled_check_releases_lock_and_obeys_backoff(manual, monkeypatch):
    now = 10
    monkeypatch.setattr(release_check, "monotonic", lambda: now)
    pending = asyncio.Event()

    async def cancel_me():
        pending.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(release_check, "_fetch_latest_tag", cancel_me)
    check = release_check.ReleaseCheck("1.2.0", enabled=True)
    task = asyncio.create_task(check.check(manual=manual))
    try:
        await asyncio.wait_for(pending.wait(), timeout=5)
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    fetch = AsyncMock(return_value="v1.3.0")
    monkeypatch.setattr(release_check, "_fetch_latest_tag", fetch)
    unavailable = await asyncio.wait_for(check.check(manual=True), timeout=5)
    assert unavailable.status == "unavailable"
    assert unavailable.checked_at is not None
    assert not unavailable.stale
    fetch.assert_not_awaited()
    now += 300
    assert (await check.check()).status == "available"


async def test_disabled_check_skips_network(monkeypatch):
    fetch = AsyncMock(return_value="v1.2.3")
    monkeypatch.setattr(release_check, "_fetch_latest_tag", fetch)
    check = release_check.ReleaseCheck("1.2.0", enabled=False)
    result = await check.check()
    assert await check.check(manual=True) == result
    assert result.status == "disabled"
    assert result.checked_at is None
    assert result.latest_version is None
    assert result.release_url is None
    fetch.assert_not_awaited()


def _mock_github(monkeypatch, handler):
    real_client = httpx.AsyncClient

    def github_client(**kwargs):
        assert kwargs["verify"] is True
        assert kwargs["trust_env"] is False
        assert kwargs["follow_redirects"] is False
        return real_client(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(release_check.httpx, "AsyncClient", github_client)


async def test_release_url_is_assembled_from_validated_tag(monkeypatch):
    response = {
        "tag_name": "v1.2.3", "draft": False, "prerelease": False,
        "html_url": "https://example.com/untrusted",
    }

    def handler(request):
        assert request.method == "GET"
        assert str(request.url) == "https://api.github.com/repos/mihsergeev/amnezia-control/releases/latest"
        assert "Authorization" not in request.headers
        assert "Cookie" not in request.headers
        assert request.headers["Accept-Encoding"] == "identity"
        return httpx.Response(200, stream=httpx.ByteStream(json.dumps(response).encode()))

    _mock_github(monkeypatch, handler)
    result = await release_check.ReleaseCheck("1.2.0", enabled=True).check()
    assert result.release_url == "https://github.com/mihsergeev/amnezia-control/releases/tag/v1.2.3"


@pytest.mark.parametrize("payload", [
    {"tag_name": "1.2.3", "draft": False, "prerelease": False},
    {"tag_name": "v1.02.3", "draft": False, "prerelease": False},
    {"tag_name": "v1.2.3-rc.1", "draft": False, "prerelease": False},
    {"tag_name": "v1.2.3/../other", "draft": False, "prerelease": False},
    {"tag_name": "v1.2.3", "draft": False, "prerelease": True},
    {"tag_name": "v1.2.3", "draft": True, "prerelease": False},
    ["v1.2.3"],
])
async def test_invalid_release_metadata_is_rejected(payload, monkeypatch):
    def handler(request):
        return httpx.Response(200, stream=httpx.ByteStream(json.dumps(payload).encode()))

    _mock_github(monkeypatch, handler)
    result = await release_check.ReleaseCheck("1.2.0", enabled=True).check()
    assert result.status == "unavailable"
    assert result.latest_version is None
    assert result.release_url is None


async def test_redirect_is_not_followed(monkeypatch):
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(307, headers={"Location": "https://example.com/redirected"})

    _mock_github(monkeypatch, handler)
    result = await release_check.ReleaseCheck("1.2.0", enabled=True).check()
    assert result.status == "unavailable"
    assert len(requests) == 1


async def test_oversized_response_is_discarded(monkeypatch):
    payload = {
        "tag_name": "v1.2.3", "draft": False, "prerelease": False,
        "body": "a" * release_check._MAX_RESPONSE_BYTES,
    }

    def handler(request):
        return httpx.Response(200, stream=httpx.ByteStream(json.dumps(payload).encode()))

    _mock_github(monkeypatch, handler)
    result = await release_check.ReleaseCheck("1.2.0", enabled=True).check()
    assert result.status == "unavailable"


async def test_body_read_obeys_total_timeout(monkeypatch):
    class SlowBody(httpx.AsyncByteStream):
        closed = False

        async def __aiter__(self):
            await asyncio.Event().wait()
            yield b""

        async def aclose(self):
            self.closed = True

    stream = SlowBody()

    def handler(request):
        return httpx.Response(200, stream=stream)

    _mock_github(monkeypatch, handler)
    monkeypatch.setattr(release_check, "_HTTP_TIMEOUT", 0.05)
    check = release_check.ReleaseCheck("1.2.0", enabled=True)
    result = await asyncio.wait_for(check.check(), timeout=5)
    assert result.status == "unavailable"
    assert stream.closed
