"""Trusted devices may satisfy only the second factor at password login."""

import io
import json
import tarfile
from datetime import datetime, timedelta, timezone
from http.cookies import SimpleCookie
from types import SimpleNamespace

import httpx
import pytest
from sqlalchemy import select

from app import config, ratelimit, totp, trusted_devices
from app.bootstrap import ensure_admin
from app.models import TrustedDevice, User
from app.security import hash_password

LOGIN = {"username": "admin", "password": "testpass"}
OTHER = {"username": "other", "password": "other-password"}
TRUSTED_COOKIE = "accontrol_trusted_device"
REFRESH_COOKIE = "accontrol_refresh"
BROWSER_HEADERS = {"X-Acontrol-Session": "1", "Sec-Fetch-Site": "same-origin"}
DEVICES = "/api/auth/trusted-devices"
LOGIN_URL = "/api/auth/login"


@pytest.fixture
def browser(client):
    client.base_url = httpx.URL("https://test")
    return client


@pytest.fixture
def otp_code(monkeypatch):
    counter = 60_000_000
    monkeypatch.setattr(totp, "time", SimpleNamespace(time=lambda: counter * 30))

    def issue(secret: str) -> str:
        nonlocal counter
        counter += 1
        return totp._hotp(secret, counter)

    return issue


def bearer(response):
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def response_cookie(response, name=TRUSTED_COOKIE):
    cookies = SimpleCookie()
    for header in response.headers.get_list("set-cookie"):
        cookies.load(header)
    return cookies.get(name)


def assert_otp_required(response):
    assert response.status_code == 401, response.text
    assert response.json()["detail"] == "2fa_required"


async def enable_totp(browser, otp_code, credentials=LOGIN):
    login = await browser.post(LOGIN_URL, json=credentials)
    assert login.status_code == 200, login.text
    setup = await browser.post(
        "/api/auth/2fa/setup", headers=bearer(login), json={"password": credentials["password"]},
    )
    assert setup.status_code == 200, setup.text
    secret = setup.json()["secret"]
    enabled = await browser.post(
        "/api/auth/2fa/enable", headers=bearer(login),
        json={"password": credentials["password"], "otp": otp_code(secret)},
    )
    assert enabled.status_code == 200, enabled.text
    return secret


async def trust(browser, otp_code, secret, credentials=LOGIN, *, agent="Test browser", **options):
    login = await browser.post(
        LOGIN_URL, headers={**BROWSER_HEADERS, "User-Agent": agent},
        json={**credentials, "otp": otp_code(secret), "trust_device": True, **options},
    )
    assert login.status_code == 200, login.text
    assert response_cookie(login)
    return login


async def devices(browser, login, **headers):
    response = await browser.get(DEVICES, headers={**bearer(login), **BROWSER_HEADERS, **headers})
    assert response.status_code == 200, response.text
    return response.json()


async def test_opt_in_requires_password_totp_and_browser_header(browser, otp_code, session_factory):
    no_totp = await browser.post(LOGIN_URL, headers=BROWSER_HEADERS, json={**LOGIN, "trust_device": True})
    assert no_totp.status_code == 200, no_totp.text
    assert response_cookie(no_totp) is None

    secret = await enable_totp(browser, otp_code)
    body = {**LOGIN, "trust_device": True}
    missing = await browser.post(LOGIN_URL, headers=BROWSER_HEADERS, json=body)
    assert_otp_required(missing)
    invalid = await browser.post(LOGIN_URL, headers=BROWSER_HEADERS, json={**body, "otp": "9999999"})
    assert invalid.status_code == 401 and invalid.json()["detail"] == "2fa_invalid"
    wrong_password = await browser.post(
        LOGIN_URL, headers=BROWSER_HEADERS,
        json={**body, "password": "wrong-pass", "otp": otp_code(secret)},
    )
    assert wrong_password.status_code == 401
    without_header = await browser.post(LOGIN_URL, json={**body, "otp": otp_code(secret)})
    no_opt_in = await browser.post(
        LOGIN_URL, headers=BROWSER_HEADERS, json={**LOGIN, "otp": otp_code(secret)},
    )
    assert without_header.status_code == no_opt_in.status_code == 200
    for response in (missing, invalid, wrong_password, without_header, no_opt_in):
        assert response_cookie(response) is None
    async with session_factory() as db:
        assert await db.scalar(select(TrustedDevice)) is None

    login = await trust(browser, otp_code, secret)
    cookie = response_cookie(login)
    assert cookie["secure"] and cookie["httponly"]
    assert cookie["samesite"].lower() == "strict"
    assert cookie["path"] == "/api/auth"
    assert not cookie["domain"]
    assert 0 < int(cookie["max-age"]) <= 30 * 24 * 60 * 60
    assert set(login.json()) == {"access_token", "token_type"}
    assert cookie.value and cookie.value not in login.text
    async with session_factory() as db:
        row = (await db.scalars(select(TrustedDevice))).one()
        assert row.token_digest and row.token_digest != cookie.value


async def test_trust_and_remember_are_independent_and_logout_preserves_trust(browser, otp_code):
    secret = await enable_totp(browser, otp_code)
    remembered = await browser.post(
        LOGIN_URL, headers=BROWSER_HEADERS,
        json={**LOGIN, "otp": otp_code(secret), "remember": True},
    )
    assert remembered.status_code == 200, remembered.text
    assert response_cookie(remembered, REFRESH_COOKIE)
    assert response_cookie(remembered) is None
    assert_otp_required(await browser.post(LOGIN_URL, headers=BROWSER_HEADERS, json=LOGIN))

    login = await trust(browser, otp_code, secret, remember=True)
    assert response_cookie(login, REFRESH_COOKIE)
    token = response_cookie(login).value
    logout = await browser.post("/api/auth/logout", headers={**bearer(login), **BROWSER_HEADERS})
    assert logout.status_code == 204, logout.text
    assert REFRESH_COOKIE not in browser.cookies
    assert browser.cookies[TRUSTED_COOKIE] == token
    assert (await browser.get("/api/auth/me", headers=bearer(login))).status_code == 401
    assert (await browser.post("/api/auth/refresh", headers=BROWSER_HEADERS)).status_code == 401

    password_only = await browser.post(LOGIN_URL, headers=BROWSER_HEADERS, json=LOGIN)
    assert password_only.status_code == 200, password_only.text
    assert "set-cookie" not in password_only.headers
    assert (await browser.get("/api/auth/me", headers=bearer(password_only))).status_code == 200


async def test_password_only_never_extends_the_absolute_trust_expiry(browser, otp_code, monkeypatch):
    instant = datetime.now(timezone.utc).replace(microsecond=0)
    monkeypatch.setattr(trusted_devices, "utcnow", lambda: instant)
    secret = await enable_totp(browser, otp_code)
    login = await trust(browser, otp_code, secret)
    first, = await devices(browser, login)
    assert datetime.fromisoformat(first["expires_at"]) == instant + timedelta(days=30)

    instant += timedelta(days=29)
    assert_otp_required(await browser.post(
        LOGIN_URL, headers=BROWSER_HEADERS, json={**LOGIN, "trust_device": True},
    ))
    password_only = await browser.post(LOGIN_URL, headers=BROWSER_HEADERS, json=LOGIN)
    assert password_only.status_code == 200, password_only.text
    assert response_cookie(password_only) is None
    same, = await devices(browser, password_only)
    assert same["id"] == first["id"]
    assert same["expires_at"] == first["expires_at"]
    assert datetime.fromisoformat(same["last_used_at"]) == instant

    instant += timedelta(days=1)
    assert_otp_required(await browser.post(LOGIN_URL, headers=BROWSER_HEADERS, json=LOGIN))
    assert await devices(browser, password_only) == []
    fresh = await trust(browser, otp_code, secret)
    assert response_cookie(fresh).value != response_cookie(login).value


async def test_explicit_wrong_or_repeated_otp_wins_over_valid_trust(browser, otp_code):
    secret = await enable_totp(browser, otp_code)
    await trust(browser, otp_code, secret)
    fresh = otp_code(secret)
    for code, expected in ((fresh, 200), (fresh, 401), ("9999999", 401)):
        response = await browser.post(LOGIN_URL, headers=BROWSER_HEADERS, json={**LOGIN, "otp": code})
        assert response.status_code == expected, response.text
        if expected == 401:
            assert response.json()["detail"] == "2fa_invalid"
    assert (await browser.post(LOGIN_URL, headers=BROWSER_HEADERS, json=LOGIN)).status_code == 200


async def test_valid_trust_preserves_password_rate_limit(browser, otp_code):
    secret = await enable_totp(browser, otp_code)
    await trust(browser, otp_code, secret)
    for _ in range(ratelimit.MAX_FAILURES):
        denied = await browser.post(
            LOGIN_URL, headers=BROWSER_HEADERS, json={**LOGIN, "password": "wrong-pass"},
        )
        assert denied.status_code == 401, denied.text
        assert denied.json()["detail"] != "2fa_required"
    locked = await browser.post(LOGIN_URL, headers=BROWSER_HEADERS, json=LOGIN)
    assert locked.status_code == 429


@pytest.mark.parametrize("headers", [
    {},
    {"X-Acontrol-Session": "0", "Sec-Fetch-Site": "same-origin"},
    {"X-Acontrol-Session": "1", "Sec-Fetch-Site": "same-site", "Origin": "https://other.test"},
    {"X-Acontrol-Session": "1", "Sec-Fetch-Site": "cross-site", "Origin": "https://other.example"},
], ids=["missing-header", "wrong-header", "another-subdomain", "cross-site"])
async def test_trusted_login_requires_same_origin_browser_header(browser, otp_code, headers):
    secret = await enable_totp(browser, otp_code)
    await trust(browser, otp_code, secret)
    blocked = await browser.post(LOGIN_URL, headers=headers, json=LOGIN)
    assert_otp_required(blocked)
    assert response_cookie(blocked) is None
    assert (await browser.post(LOGIN_URL, headers=BROWSER_HEADERS, json=LOGIN)).status_code == 200


async def test_trusted_cookie_is_not_sent_over_http_or_allowed_by_cross_origin_preflight(browser, otp_code):
    secret = await enable_totp(browser, otp_code)
    await trust(browser, otp_code, secret)
    insecure = await browser.post("http://test/api/auth/login", headers=BROWSER_HEADERS, json=LOGIN)
    assert TRUSTED_COOKIE not in insecure.request.headers.get("cookie", "")
    assert_otp_required(insecure)

    preflight = await browser.options(LOGIN_URL, headers={
        "Origin": "https://other.test",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "content-type,x-acontrol-session",
    })
    assert "access-control-allow-origin" not in preflight.headers
    assert "access-control-allow-credentials" not in preflight.headers


async def test_list_and_revoke_respect_ownership_and_leave_other_devices_active(
    browser, otp_code, session_factory,
):
    secret = await enable_totp(browser, otp_code)
    first = await trust(browser, otp_code, secret, agent="First browser")
    first_token = response_cookie(first).value
    first_jar = httpx.Cookies(browser.cookies)
    browser.cookies.clear()
    second = await trust(browser, otp_code, secret, agent="Second browser")
    second_token = response_cookie(second).value

    async with session_factory() as db:
        db.add(User(username=OTHER["username"], password_hash=hash_password(OTHER["password"])))
        await db.commit()
    browser.cookies.clear()
    other_secret = await enable_totp(browser, otp_code, OTHER)
    other = await trust(browser, otp_code, other_secret, OTHER, agent="Other account")

    assert_otp_required(await browser.post(LOGIN_URL, headers=BROWSER_HEADERS, json=LOGIN))
    with_first_cookie = {"Cookie": f"{TRUSTED_COOKIE}={first_token}"}
    rows = {row["user_agent"]: row for row in await devices(browser, first, **with_first_cookie)}
    assert rows.keys() == {"First browser", "Second browser"}
    current = rows["First browser"]
    target = rows["Second browser"]
    assert current["current"] is True and target["current"] is False
    assert set(current) == {"id", "user_agent", "created_at", "last_used_at", "expires_at", "current"}
    assert (
        datetime.fromisoformat(current["created_at"])
        <= datetime.fromisoformat(current["last_used_at"])
        < datetime.fromisoformat(current["expires_at"])
    )
    no_proof = await browser.get(DEVICES, headers={**bearer(first), **with_first_cookie})
    assert no_proof.status_code == 200
    assert all(not row["current"] for row in no_proof.json())
    assert (await browser.get(DEVICES, headers=BROWSER_HEADERS)).status_code == 401

    foreign_url = f"{DEVICES}/{target['id']}"
    assert (await browser.delete(foreign_url, headers=bearer(other))).status_code == 404
    assert (await browser.delete(foreign_url, headers=BROWSER_HEADERS)).status_code == 401
    revoked = await browser.delete(foreign_url, headers={**bearer(first), **BROWSER_HEADERS, **with_first_cookie})
    assert revoked.status_code == 204, revoked.text
    assert response_cookie(revoked) is None
    assert (await browser.get("/api/auth/me", headers=bearer(second))).status_code == 200

    revoked_cookie = {"Cookie": f"{TRUSTED_COOKIE}={second_token}"}
    denied = await browser.post(LOGIN_URL, headers={**BROWSER_HEADERS, **revoked_cookie}, json=LOGIN)
    assert_otp_required(denied)
    allowed = await browser.post(LOGIN_URL, headers={**BROWSER_HEADERS, **with_first_cookie}, json=LOGIN)
    assert allowed.status_code == 200, allowed.text
    remaining, = await devices(browser, first, **with_first_cookie)
    assert remaining["id"] == current["id"]
    other_row, = await devices(browser, other)
    assert other_row["user_agent"] == "Other account"

    browser.cookies = first_jar
    current_revoke = await browser.delete(
        f"{DEVICES}/{current['id']}", headers={**bearer(first), **BROWSER_HEADERS},
    )
    assert current_revoke.status_code == 204, current_revoke.text
    assert response_cookie(current_revoke)["max-age"] == "0"
    assert TRUSTED_COOKIE not in browser.cookies


async def test_revoking_trust_leaves_the_remembered_session_active(browser, otp_code):
    secret = await enable_totp(browser, otp_code)
    login = await trust(browser, otp_code, secret, remember=True)
    current, = await devices(browser, login)
    revoked = await browser.delete(f"{DEVICES}/{current['id']}", headers={**bearer(login), **BROWSER_HEADERS})
    assert revoked.status_code == 204, revoked.text
    assert TRUSTED_COOKIE not in browser.cookies and REFRESH_COOKIE in browser.cookies
    assert (await browser.get("/api/auth/me", headers=bearer(login))).status_code == 200
    refreshed = await browser.post("/api/auth/refresh", headers=BROWSER_HEADERS)
    assert refreshed.status_code == 200, refreshed.text
    assert response_cookie(refreshed, REFRESH_COOKIE)
    assert response_cookie(refreshed) is None


async def test_trusted_login_still_requires_password_and_fresh_totp_for_step_up(browser, otp_code):
    secret = await enable_totp(browser, otp_code)
    await trust(browser, otp_code, secret)
    login = await browser.post(LOGIN_URL, headers=BROWSER_HEADERS, json=LOGIN)
    assert login.status_code == 200, login.text

    headers = {**bearer(login), **BROWSER_HEADERS}
    body = {"name": "test-integration", "password": LOGIN["password"]}
    cookie_only = await browser.post("/api/apikeys", headers=BROWSER_HEADERS, json=body)
    assert cookie_only.status_code == 401
    missing_otp = await browser.post("/api/apikeys", headers=headers, json=body)
    assert missing_otp.status_code == 403 and missing_otp.headers["X-Need-OTP"] == "1"
    code = otp_code(secret)
    wrong_password = await browser.post(
        "/api/apikeys", headers=headers, json={**body, "password": "wrong", "otp": code},
    )
    assert wrong_password.status_code == 403
    valid = await browser.post("/api/apikeys", headers=headers, json={**body, "otp": code})
    assert valid.status_code == 201, valid.text


@pytest.mark.parametrize("event", ["password", "disable-and-reenable-totp", "break-glass-reset", "backup-restore"])
async def test_security_changes_invalidate_old_trust(browser, otp_code, session_factory, event):
    secret = await enable_totp(browser, otp_code)
    login = await trust(browser, otp_code, secret)
    old_cookie = response_cookie(login).value
    body = LOGIN
    if event == "password":
        new_password = "new-test-password"
        response = await browser.post(
            "/api/auth/password", headers={**bearer(login), "X-Confirm-OTP": otp_code(secret)},
            json={"current_password": LOGIN["password"], "new_password": new_password},
        )
        assert response.status_code == 200, response.text
        body = {**LOGIN, "password": new_password}
    elif event == "backup-restore":
        archive = await browser.post(
            "/api/backup/download", headers={**bearer(login), "X-Confirm-OTP": otp_code(secret)},
            json={"password": LOGIN["password"]},
        )
        assert archive.status_code == 200, archive.text
        with tarfile.open(fileobj=io.BytesIO(archive.content), mode="r:gz") as tar:
            assert TrustedDevice.__tablename__ not in json.load(tar.extractfile("db.json"))
        response = await browser.post(
            "/api/backup/restore", content=archive.content,
            headers={**bearer(login), "X-Confirm-Password": LOGIN["password"], "X-Confirm-OTP": otp_code(secret)},
        )
        assert response.status_code == 200, response.text
    else:
        if event == "break-glass-reset":
            settings = config.get_settings().model_copy(update={"admin_password_reset": True})
            await ensure_admin(session_factory, settings)
        else:
            response = await browser.post(
                "/api/auth/2fa/disable", headers=bearer(login),
                json={"password": LOGIN["password"], "otp": otp_code(secret)},
            )
            assert response.status_code == 200, response.text
        await enable_totp(browser, otp_code)

    async with session_factory() as db:
        assert await db.scalar(select(TrustedDevice)) is None
    assert (await browser.get("/api/auth/me", headers=bearer(login))).status_code == 401
    replay = await browser.post(
        LOGIN_URL, json=body, headers={**BROWSER_HEADERS, "Cookie": f"{TRUSTED_COOKIE}={old_cookie}"},
    )
    assert_otp_required(replay)
