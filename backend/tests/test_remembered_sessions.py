"""Regression tests for remembered browser sessions."""

import asyncio
from datetime import datetime, timedelta
from http.cookies import SimpleCookie
from types import SimpleNamespace

import httpx
import pytest
from sqlalchemy import select

from app import remembered_sessions, totp
from app.models import RememberedSession, User
from app.security import hash_password


LOGIN = {"username": "admin", "password": "testpass"}
COOKIE_NAME = "accontrol_refresh"
REFRESH_HEADERS = {"X-Acontrol-Session": "1", "Sec-Fetch-Site": "same-origin"}


@pytest.fixture
def browser(client):
    client.base_url = httpx.URL("https://test")
    return client


@pytest.fixture
def otp_code(monkeypatch):
    counter = 60_000_000
    monkeypatch.setattr(totp, "time", SimpleNamespace(time=lambda: counter * 30))

    def code(secret: str, *, advance: bool = False) -> str:
        nonlocal counter
        if advance:
            counter += 1
        return totp._hotp(secret, counter)

    return code


def bearer(response: httpx.Response) -> dict[str, str]:
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def cookie_header(token: str) -> dict[str, str]:
    return {"Cookie": f"{COOKIE_NAME}={token}"}


def issued_cookie(response: httpx.Response) -> str:
    cookies: SimpleCookie = SimpleCookie()
    for header in response.headers.get_list("set-cookie"):
        cookies.load(header)
    morsel = cookies[COOKIE_NAME]
    assert morsel["secure"]
    assert morsel["httponly"]
    assert morsel["samesite"].lower() == "strict"
    assert morsel["path"] == "/api/auth"
    assert not morsel["domain"]
    assert int(morsel["max-age"]) > 0
    assert set(response.json()) == {"access_token", "token_type"}
    assert response.json()["token_type"] == "bearer"
    assert morsel.value and morsel.value not in response.text
    return morsel.value


async def remember(browser: httpx.AsyncClient, *, agent: str = "Test browser", **fields) -> httpx.Response:
    response = await browser.post(
        "/api/auth/login", json={**LOGIN, "remember": True, **fields},
        headers={"User-Agent": agent},
    )
    assert response.status_code == 200, response.text
    return response


async def refresh(browser: httpx.AsyncClient, token: str | None = None) -> httpx.Response:
    headers = dict(REFRESH_HEADERS)
    if token is not None:
        headers.update(cookie_header(token))
    return await browser.post("/api/auth/refresh", headers=headers)


async def assert_revoked(browser: httpx.AsyncClient, login: httpx.Response) -> None:
    assert (await browser.get("/api/auth/me", headers=bearer(login))).status_code == 401
    assert (await refresh(browser, login.cookies[COOKIE_NAME])).status_code == 401


async def enable_totp(browser, login, otp_code):
    setup = await browser.post(
        "/api/auth/2fa/setup", headers=bearer(login), json={"password": LOGIN["password"]},
    )
    assert setup.status_code == 200, setup.text
    secret = setup.json()["secret"]
    enabled = await browser.post(
        "/api/auth/2fa/enable", headers=bearer(login),
        json={"password": LOGIN["password"], "otp": otp_code(secret)},
    )
    assert enabled.status_code == 200, enabled.text
    return secret, enabled


@pytest.mark.parametrize("remember_field", [{}, {"remember": False}], ids=["omitted", "false"])
async def test_legacy_login_and_logout(browser, remember_field):
    body = {**LOGIN, **remember_field}
    first = await browser.post("/api/auth/login", json=body)
    second = await browser.post("/api/auth/login", json=body)
    for response in (first, second):
        assert response.status_code == 200
        assert response.json().keys() == {"access_token", "token_type"}
        assert "set-cookie" not in response.headers
        assert (await browser.get("/api/auth/me", headers=bearer(response))).status_code == 200
    assert (await browser.get("/api/auth/sessions", headers=bearer(first))).json() == []
    assert (await refresh(browser)).status_code == 401
    logout = await browser.post("/api/auth/logout", headers=bearer(first))
    assert logout.status_code == 204
    assert (await browser.get("/api/auth/me", headers=bearer(first))).status_code == 401
    assert (await browser.get("/api/auth/me", headers=bearer(second))).status_code == 401


async def test_login_without_remember_clears_previous_session_in_same_browser(browser):
    previous = await remember(browser)
    login = await browser.post("/api/auth/login", json={**LOGIN, "remember": False})
    assert login.status_code == 200, login.text
    assert COOKIE_NAME not in browser.cookies
    await assert_revoked(browser, previous)
    assert (await browser.get("/api/auth/me", headers=bearer(login))).status_code == 200


async def test_remember_issues_cookie_only_after_password_and_totp(browser, otp_code, session_factory):
    login = await browser.post("/api/auth/login", json=LOGIN)
    secret, _ = await enable_totp(browser, login, otp_code)

    body = {**LOGIN, "remember": True}
    wrong_password = await browser.post("/api/auth/login", json={**body, "password": "bad"})
    challenge = await browser.post("/api/auth/login", json=body)
    wrong_otp = await browser.post("/api/auth/login", json={**body, "otp": "9999999"})
    assert wrong_password.status_code == challenge.status_code == wrong_otp.status_code == 401
    assert challenge.json()["detail"] == "2fa_required"
    assert wrong_otp.json()["detail"] == "2fa_invalid"
    assert all("set-cookie" not in response.headers for response in (wrong_password, challenge, wrong_otp))
    async with session_factory() as db:
        assert await db.scalar(select(RememberedSession)) is None

    code = otp_code(secret, advance=True)
    success = await remember(browser, otp=code)
    token = issued_cookie(success)
    repeated = await browser.post("/api/auth/login", json={**body, "otp": code})
    assert repeated.status_code == 401
    assert "set-cookie" not in repeated.headers
    async with session_factory() as db:
        row = (await db.scalars(select(RememberedSession))).one()
        assert row.token_digest and row.token_digest != token


@pytest.mark.parametrize("rotations", [1, 2])
async def test_refresh_rotates_cookie_and_revokes_replayed_session(browser, monkeypatch, rotations):
    instant = remembered_sessions.utcnow()
    monkeypatch.setattr(remembered_sessions, "utcnow", lambda: instant)
    login = await remember(browser)
    first_cookie = latest_cookie = issued_cookie(login)
    for _ in range(rotations):
        instant += timedelta(seconds=1)
        renewed = await refresh(browser)
        assert renewed.status_code == 200, renewed.text
        rotated_cookie = issued_cookie(renewed)
        assert rotated_cookie != latest_cookie
        latest_cookie = rotated_cookie
    assert (await browser.get("/api/auth/me", headers=bearer(renewed))).status_code == 200

    instant += timedelta(seconds=10)
    reused = await refresh(browser, first_cookie)
    assert reused.status_code == 401
    assert "set-cookie" not in reused.headers
    assert (await refresh(browser, latest_cookie)).status_code == 401
    assert (await browser.get("/api/auth/me", headers=bearer(renewed))).status_code == 401


async def test_parallel_refresh_keeps_only_one_successor(browser):
    first_cookie = issued_cookie(await remember(browser))
    replies = await asyncio.gather(*(refresh(browser, first_cookie) for _ in range(2)))
    assert sorted(reply.status_code for reply in replies) == [200, 409]
    winner = next(reply for reply in replies if reply.status_code == 200)
    conflict = next(reply for reply in replies if reply.status_code == 409)
    winner_cookie = issued_cookie(winner)
    assert "set-cookie" not in conflict.headers
    assert browser.cookies[COOKIE_NAME] == winner_cookie
    assert (await browser.get("/api/auth/me", headers=bearer(winner))).status_code == 200
    next_refresh = await refresh(browser)
    assert next_refresh.status_code == 200
    assert issued_cookie(next_refresh) != winner_cookie


@pytest.mark.parametrize("expiry", ["idle", "absolute"])
async def test_expired_sessions_reject_refresh_and_access_tokens(browser, monkeypatch, expiry):
    instant = remembered_sessions.utcnow()
    monkeypatch.setattr(remembered_sessions, "utcnow", lambda: instant)
    login = await remember(browser)
    token = issued_cookie(login)
    if expiry == "idle":
        instant += timedelta(days=8)
    else:
        # Each refresh renews inactivity but the absolute expiry stays fixed.
        for _ in range(4):
            instant += timedelta(days=6)
            response = await refresh(browser)
            assert response.status_code == 200, response.text
            token = issued_cookie(response)
        instant += timedelta(days=6)
    assert (await refresh(browser, token)).status_code == 401
    assert (await browser.get("/api/auth/me", headers=bearer(login))).status_code == 401


async def test_session_list_and_revoke_only_owned_session(browser, session_factory):
    first = await remember(browser, agent="Test browser A")
    browser.cookies.clear()
    second = await remember(browser, agent="Test browser B")
    async with session_factory() as db:
        db.add(User(username="other", password_hash=hash_password("other-password")))
        await db.commit()
    browser.cookies.clear()
    other = await remember(browser, agent="Other user", username="other", password="other-password")

    response = await browser.get("/api/auth/sessions", headers=bearer(first))
    assert response.status_code == 200, response.text
    rows = {row["user_agent"]: row for row in response.json()}
    assert rows.keys() == {"Test browser A", "Test browser B"}
    current, target = rows["Test browser A"], rows["Test browser B"]
    assert current["current"] is True and target["current"] is False
    assert current["id"] != target["id"]
    assert current.keys() == {"id", "user_agent", "created_at", "last_used_at", "expires_at", "current"}
    assert (
        datetime.fromisoformat(current["created_at"])
        <= datetime.fromisoformat(current["last_used_at"])
        < datetime.fromisoformat(current["expires_at"])
    )

    target_url = f"/api/auth/sessions/{target['id']}"
    assert (await browser.delete(target_url, headers=bearer(other))).status_code == 404
    assert (await browser.get("/api/auth/me", headers=bearer(second))).status_code == 200
    assert (await browser.delete(target_url, headers=bearer(first))).status_code == 204
    await assert_revoked(browser, second)
    assert (await browser.get("/api/auth/me", headers=bearer(first))).status_code == 200
    assert (await browser.get("/api/auth/me", headers=bearer(other))).status_code == 200
    renewed = await refresh(browser, first.cookies[COOKIE_NAME])
    assert renewed.status_code == 200, renewed.text
    remaining = await browser.get("/api/auth/sessions", headers=bearer(first))
    assert [row["id"] for row in remaining.json()] == [current["id"]]

    current_url = f"/api/auth/sessions/{current['id']}"
    assert (await browser.delete(current_url, headers=bearer(renewed))).status_code == 204
    assert COOKIE_NAME not in browser.cookies
    await assert_revoked(browser, renewed)
    assert (await browser.get("/api/auth/me", headers=bearer(other))).status_code == 200


@pytest.mark.parametrize("credential", ["bearer", "refresh-cookie"])
async def test_logout_revokes_remembered_and_legacy_sessions(browser, credential):
    legacy = await browser.post("/api/auth/login", json=LOGIN)
    first = await remember(browser)
    browser.cookies.clear()
    second = await remember(browser)
    assert (await browser.get("/api/auth/me", headers=bearer(first))).status_code == 200
    if credential == "refresh-cookie":
        rejected = await browser.post("/api/auth/logout")
        assert rejected.status_code == 401
        rejected = await browser.post(
            "/api/auth/logout", headers={**REFRESH_HEADERS, "Sec-Fetch-Site": "cross-site"},
        )
        assert rejected.status_code == 401
        assert browser.cookies[COOKIE_NAME] == second.cookies[COOKIE_NAME]
        headers = REFRESH_HEADERS
    else:
        headers = bearer(second)
    result = await browser.post("/api/auth/logout", headers=headers)
    assert result.status_code == 204
    assert COOKIE_NAME not in browser.cookies
    for login in (first, second):
        await assert_revoked(browser, login)
    assert (await browser.get("/api/auth/me", headers=bearer(legacy))).status_code == 401


async def test_password_change_revokes_remembered_sessions(browser):
    login = await remember(browser)
    result = await browser.post(
        "/api/auth/password", headers=bearer(login),
        json={"current_password": LOGIN["password"], "new_password": "new-test-password"},
    )
    assert result.status_code == 200, result.text
    assert COOKIE_NAME not in browser.cookies
    await assert_revoked(browser, login)
    assert (await browser.get("/api/auth/me", headers=bearer(result))).status_code == 200


async def test_enabling_and_disabling_totp_revokes_remembered_sessions(browser, otp_code):
    before_enable = await remember(browser)
    secret, enabled = await enable_totp(browser, before_enable, otp_code)
    assert COOKIE_NAME not in browser.cookies
    await assert_revoked(browser, before_enable)
    assert (await browser.get("/api/auth/me", headers=bearer(enabled))).status_code == 200

    before_disable = await remember(browser, otp=otp_code(secret, advance=True))
    disabled = await browser.post(
        "/api/auth/2fa/disable", headers=bearer(before_disable),
        json={"password": LOGIN["password"], "otp": otp_code(secret, advance=True)},
    )
    assert disabled.status_code == 200, disabled.text
    assert COOKIE_NAME not in browser.cookies
    await assert_revoked(browser, before_disable)
    assert (await browser.get("/api/auth/me", headers=bearer(disabled))).status_code == 200


async def test_refresh_does_not_bypass_step_up(browser, otp_code):
    initial = await browser.post("/api/auth/login", json=LOGIN)
    secret, _ = await enable_totp(browser, initial, otp_code)
    last_code = otp_code(secret, advance=True)
    await remember(browser, otp=last_code)
    renewed = await refresh(browser)
    assert renewed.status_code == 200, renewed.text
    cookie = issued_cookie(renewed)
    headers = bearer(renewed)

    body = {"name": "test-integration", "password": LOGIN["password"]}
    cookie_only = await browser.post("/api/apikeys", headers=cookie_header(cookie), json=body)
    assert cookie_only.status_code == 401
    missing_otp = await browser.post("/api/apikeys", headers=headers, json=body)
    assert missing_otp.status_code == 403
    assert missing_otp.headers["X-Need-OTP"] == "1"
    reused_otp = await browser.post("/api/apikeys", headers=headers, json={**body, "otp": last_code})
    assert reused_otp.status_code == 403
    fresh_code = otp_code(secret, advance=True)
    wrong_password = await browser.post(
        "/api/apikeys", headers=headers, json={**body, "otp": fresh_code, "password": "bad"},
    )
    assert wrong_password.status_code == 403
    valid_otp = await browser.post(
        "/api/apikeys", headers=headers, json={**body, "otp": fresh_code},
    )
    assert valid_otp.status_code == 201, valid_otp.text


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"X-Acontrol-Session": "0"},
        {**REFRESH_HEADERS, "Sec-Fetch-Site": "cross-site", "Origin": "https://example.org"},
        {**REFRESH_HEADERS, "Sec-Fetch-Site": "same-site", "Origin": "https://other.test"},
    ],
    ids=["missing-header", "wrong-header", "cross-site", "same-site-other-origin"],
)
async def test_refresh_requires_same_origin_custom_header(browser, headers):
    token = issued_cookie(await remember(browser))
    blocked = await browser.post("/api/auth/refresh", headers=headers)
    assert blocked.status_code == 403
    assert "set-cookie" not in blocked.headers
    assert browser.cookies[COOKIE_NAME] == token
    allowed = await browser.post("/api/auth/refresh", headers={**REFRESH_HEADERS, "Origin": "https://test"})
    assert allowed.status_code == 200, allowed.text


async def test_refresh_disallows_cross_origin_preflight(browser):
    response = await browser.options(
        "/api/auth/refresh",
        headers={
            "Origin": "https://other.test",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "X-Acontrol-Session",
        },
    )
    assert "access-control-allow-origin" not in response.headers
    assert "access-control-allow-credentials" not in response.headers


async def test_browser_does_not_send_refresh_cookie_over_http(browser):
    token = issued_cookie(await remember(browser))
    plain_http = await browser.post("http://test/api/auth/refresh", headers=REFRESH_HEADERS)
    assert "cookie" not in plain_http.request.headers
    assert plain_http.status_code == 401
    allowed = await refresh(browser)
    assert allowed.status_code == 200
    assert issued_cookie(allowed) != token
