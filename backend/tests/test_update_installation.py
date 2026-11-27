import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import httpx
import pytest
from sqlalchemy import select

from app import apikeys, release_check, totp, update_worker
from app.models import ApiKey, AuditLog


INSTALL = "/api/updates/installation"
VERSION = "1.2.3"
PASSWORD = "testpass"
BROWSER = {"X-Acontrol-Session": "1", "Sec-Fetch-Site": "same-origin", "Origin": "https://test"}
IDLE = {"phase": "idle", "version": None, "error": None}
QUEUED = {"phase": "queued", "version": VERSION, "error": None}


def _frame(status):
    return json.dumps(status).encode("ascii") + b"\n"


def _auth(response):
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


@pytest.fixture
def worker(monkeypatch):
    async def exchange(message):
        return _frame(IDLE if message["action"] == "status" else {**QUEUED, "accepted": True})

    call = AsyncMock(side_effect=exchange)
    monkeypatch.setattr(update_worker, "_exchange", call)
    return call


@pytest.fixture
def release(monkeypatch):
    fetch = AsyncMock(return_value=f"v{VERSION}")
    monkeypatch.setattr(release_check, "_fetch_latest_tag", fetch)
    return fetch


@pytest.fixture
async def trusted_session(client, auth_headers, monkeypatch):
    client.base_url = httpx.URL("https://test")
    counter = 60_000_000
    monkeypatch.setattr(totp, "time", SimpleNamespace(time=lambda: counter * 30))
    setup = await client.post("/api/auth/2fa/setup", headers=auth_headers, json={"password": PASSWORD})
    assert setup.status_code == 200, setup.text
    secret = setup.json()["secret"]

    def new_otp():
        nonlocal counter
        counter += 1
        return totp._hotp(secret, counter)

    enabled = await client.post("/api/auth/2fa/enable", headers=auth_headers, json={
        "password": PASSWORD, "otp": new_otp(),
    })
    assert enabled.status_code == 200, enabled.text
    login = {"username": "admin", "password": PASSWORD}
    enrolled = await client.post("/api/auth/login", headers=BROWSER, json={
        **login, "otp": new_otp(), "trust_device": True,
    })
    assert "accontrol_trusted_device" in enrolled.cookies
    trusted = await client.post("/api/auth/login", headers=BROWSER, json=login)
    return {**_auth(trusted), **BROWSER}, new_otp


async def test_install_and_status_require_a_user_session(client, session_factory, worker):
    key, prefix, key_hash = apikeys.generate()
    async with session_factory() as db:
        db.add(ApiKey(name="Integration", prefix=prefix, key_hash=key_hash))
        await db.commit()

    for headers in ({}, {"X-API-Key": key}):
        result = await client.get(INSTALL, headers=headers)
        assert result.status_code == 401
        assert result.headers["cache-control"] == "no-store"
        result = await client.post(INSTALL, headers={**headers, **BROWSER}, json={
            "version": VERSION, "password": PASSWORD, "otp": "123456",
        })
        assert result.status_code == 401
        assert result.headers["cache-control"] == "no-store"
    worker.assert_not_awaited()


async def test_status_without_2fa_and_missing_worker(client, auth_headers, worker):
    result = await client.get(INSTALL, headers=auth_headers)
    assert result.status_code == 200
    assert result.headers["cache-control"] == "no-store"
    assert result.json() == {"enabled": True, **IDLE}
    worker.assert_awaited_once_with({"action": "status"})

    worker.side_effect = None
    rolled_back = {"phase": "rolled_back", "version": VERSION, "error": "health_failed"}
    worker.return_value = _frame(rolled_back)
    result = await client.get(INSTALL, headers=auth_headers)
    assert result.status_code == 200
    assert result.json() == {"enabled": True, **rolled_back}

    worker.return_value = None
    result = await client.get(INSTALL, headers=auth_headers)
    assert result.status_code == 200
    assert result.json() == {"enabled": False, **IDLE}


@pytest.mark.parametrize(("headers", "detail"), [
    ({}, "2fa_setup_required"),
    ({"Origin": "http://test", "X-Forwarded-Proto": "https"}, "https_required"),
    ({"Origin": "https://other.example"}, "https_required"),
    ({"Origin": "null"}, "https_required"),
    ({"Sec-Fetch-Site": "same-site"}, "browser_request_required"),
    ({"X-Acontrol-Session": ""}, "browser_request_required"),
])
async def test_install_requires_2fa_and_a_same_origin_https_browser(
    client, auth_headers, release, worker, headers, detail,
):
    result = await client.post(INSTALL, headers={**auth_headers, **BROWSER, **headers}, json={
        "version": VERSION, "password": PASSWORD, "otp": "123456",
    })
    assert result.status_code == 403
    assert result.json() == {"detail": detail}
    assert result.headers["cache-control"] == "no-store"
    release.assert_not_awaited()
    worker.assert_not_awaited()


async def test_trusted_login_still_needs_password_and_one_fresh_otp(
    client, trusted_session, release, worker, session_factory,
):
    headers, new_otp = trusted_session
    # The internal nginx hop is HTTP and strips the external port from Host.
    client.base_url = httpx.URL("http://test")
    headers["Origin"] = "https://test:8443"
    valid_otp = new_otp()
    body = {"version": VERSION, "password": PASSWORD}
    result = await client.post(INSTALL, headers={**headers, "X-Confirm-OTP": valid_otp}, json=body)
    assert result.status_code == 403
    assert result.json() == {"detail": "2fa_required"}

    result = await client.post(INSTALL, headers=headers, json={**body, "password": "wrongpassword", "otp": valid_otp})
    assert result.status_code == 403
    assert result.json() == {"detail": "invalid_password"}
    worker.assert_not_awaited()

    valid_body = {**body, "otp": valid_otp}
    result = await client.post(INSTALL, headers=headers, json=valid_body)
    assert result.status_code == 202
    assert result.json() == {"enabled": True, **QUEUED}
    assert result.headers["cache-control"] == "no-store"
    worker.assert_awaited_once_with({"action": "install", "version": VERSION})
    release.assert_awaited_once()

    replay = await client.post(INSTALL, headers=headers, json=valid_body)
    assert replay.status_code == 403
    assert replay.json() == {"detail": "2fa_invalid"}
    worker.assert_awaited_once()
    async with session_factory() as db:
        entry = await db.scalar(select(AuditLog).where(AuditLog.action == "update_install_requested"))
    assert (entry.username, entry.target, entry.detail) == ("admin", VERSION, "")


@pytest.mark.parametrize("version", ["v1.2.3", "1.2.3-beta", "1.02.3", "1.2.3\n", "123456789.1.0"])
async def test_install_validation_does_not_echo_submitted_credentials(client, auth_headers, worker, version):
    result = await client.post(INSTALL, headers={**auth_headers, **BROWSER}, json={
        "version": version, "password": "sensitive-password", "otp": "sensitive-otp",
    })
    assert result.status_code == 422
    assert result.headers["cache-control"] == "no-store"
    assert "sensitive-password" not in result.text
    assert "sensitive-otp" not in result.text
    assert any(error["loc"] == ["body", "version"] for error in result.json()["detail"])
    worker.assert_not_awaited()


async def test_exact_latest_release_and_freshness(client, trusted_session, release, worker, monkeypatch):
    headers, new_otp = trusted_session
    clock = 0
    monkeypatch.setattr(release_check, "monotonic", lambda: clock)
    body = {"version": VERSION, "password": PASSWORD, "otp": new_otp()}
    assert (await client.get("/api/updates", headers=headers)).json()["latest_version"] == f"v{VERSION}"

    for version in ("0.0.1", "1.2.2", "1.2.4"):
        result = await client.post(INSTALL, headers=headers, json={**body, "version": version})
        assert result.status_code == 409
        assert result.json() == {"detail": "release_unavailable"}

    clock += 60
    release.return_value = None
    result = await client.post(INSTALL, headers=headers, json=body)
    assert result.status_code == 409
    assert result.json() == {"detail": "release_unavailable"}
    assert (await client.get("/api/updates", headers=headers)).json()["stale"] is True
    worker.assert_not_awaited()


@pytest.mark.parametrize(("reply", "code", "detail"), [
    (None, 503, "installer_unavailable"),
    ({**QUEUED, "accepted": False, "error": "busy"}, 409, "installation_busy"),
    ({**IDLE, "accepted": False, "error": "incompatible"}, 409, "incompatible"),
    ({**IDLE, "accepted": False, "error": "unrecognized_local_error"}, 409, "installation_rejected"),
    ({**QUEUED, "accepted": True, "version": "1.2.4"}, 503, "installer_unavailable"),
    ({**QUEUED, "accepted": True, "error": "/host/installer"}, 503, "installer_unavailable"),
])
async def test_worker_rejections_are_sanitized(client, trusted_session, release, worker, reply, code, detail):
    headers, new_otp = trusted_session
    worker.side_effect = None
    worker.return_value = _frame(reply) if reply is not None else None
    result = await client.post(INSTALL, headers=headers, json={
        "version": VERSION, "password": PASSWORD, "otp": new_otp(),
    })
    assert result.status_code == code
    assert result.json() == {"detail": detail}
    assert result.headers["cache-control"] == "no-store"
    worker.assert_awaited_once_with({"action": "install", "version": VERSION})


@pytest.mark.parametrize("payload", [
    b'{"phase":"idle","phase":"queued","version":null,"error":null}\n',
    _frame({**IDLE, "private": "/host/installer"}),
    _frame({**IDLE, "phase": "extended"}),
    _frame({**IDLE, "error": "details/at/host"}),
    _frame({**IDLE, "version": "1.2.3-beta"}),
])
async def test_invalid_worker_status_fails_closed(client, auth_headers, worker, payload):
    worker.side_effect = None
    worker.return_value = payload
    result = await client.get(INSTALL, headers=auth_headers)
    assert result.status_code == 200
    assert result.json() == {"enabled": False, **IDLE}


@pytest.mark.parametrize("response", [
    _frame(IDLE),
    b"",
    _frame(IDLE)[:-1],
    _frame({**IDLE, "error": "x" * 4096}),
], ids=["complete", "empty", "missing-newline", "oversized"])
async def test_socket_framing_and_closed_writer(monkeypatch, response):
    reader = asyncio.StreamReader(limit=4096)
    reader.feed_data(response)
    reader.feed_eof()
    writer = Mock(drain=AsyncMock())
    connect = AsyncMock(return_value=(reader, writer))
    monkeypatch.setattr(asyncio, "open_unix_connection", connect, raising=False)

    result = await update_worker.get_status()
    connect.assert_awaited_once_with("/run/acontrol-updater/control.sock", limit=4096)
    writer.write.assert_called_once_with(b'{"action":"status"}\n')
    writer.close.assert_called_once()
    assert (result.model_dump() if result else None) == (IDLE if response == _frame(IDLE) else None)


async def test_worker_read_timeout_closes_connection(monkeypatch):
    reader = asyncio.StreamReader(limit=4096)
    writer = Mock(drain=AsyncMock())
    connect = AsyncMock(return_value=(reader, writer))
    monkeypatch.setattr(asyncio, "open_unix_connection", connect, raising=False)
    monkeypatch.setattr(update_worker, "_IO_TIMEOUT", 0.01)

    result = await update_worker.request_install(VERSION)
    assert result is None
    writer.write.assert_called_once_with(b'{"action":"install","version":"1.2.3"}\n')
    writer.close.assert_called_once()


@pytest.mark.skipif(not hasattr(asyncio, "start_unix_server"), reason="requires AF_UNIX asyncio streams")
async def test_worker_uses_unix_socket_for_status_and_install(tmp_path, monkeypatch):
    path = tmp_path / "sock"
    monkeypatch.setattr(update_worker, "_SOCKET_PATH", str(path))
    messages = []

    async def serve(reader, writer):
        try:
            messages.append(await reader.readline())
            reply = IDLE if len(messages) == 1 else {**QUEUED, "accepted": True}
            writer.write(_frame(reply))
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_unix_server(serve, path)
    async with server:
        status = await update_worker.get_status()
        assert status is not None
        assert status.model_dump() == IDLE
        queued = await update_worker.request_install(VERSION)
        assert queued is not None
        assert queued.model_dump() == {**QUEUED, "accepted": True}
    assert messages == [b'{"action":"status"}\n', b'{"action":"install","version":"1.2.3"}\n']
