import time

import httpx

from app import totp


def _code(secret: str) -> str:
    return totp._hotp(secret, int(time.time() // 30))


def test_totp_verify_roundtrip():
    secret = totp.random_secret()
    assert totp.verify(secret, _code(secret)) is True
    assert totp.verify(secret, "000000") is False
    assert totp.verify(secret, "") is False
    assert totp.verify(secret, "abc") is False


def test_totp_window_tolerates_drift():
    secret = totp.random_secret()
    now = 1_000_000_000.0
    step = int(now // 30)
    prev = totp._hotp(secret, step - 1)
    assert totp.verify(secret, prev, now=now) is True  # ±1 шаг допускается


def test_provisioning_uri():
    uri = totp.provisioning_uri("ABCDEF", "admin")
    assert uri.startswith("otpauth://totp/")
    assert "secret=ABCDEF" in uri and "issuer=Amnezia" in uri


async def test_2fa_full_flow(client: httpx.AsyncClient, auth_headers):
    # изначально выключена
    r = await client.get("/api/auth/2fa", headers=auth_headers)
    assert r.status_code == 200 and r.json()["enabled"] is False

    # setup → секрет
    r = await client.post("/api/auth/2fa/setup", headers=auth_headers)
    assert r.status_code == 200
    secret = r.json()["secret"]
    assert r.json()["otpauth_uri"].startswith("otpauth://")

    # enable с неверным кодом → 400
    r = await client.post(
        "/api/auth/2fa/enable", headers=auth_headers, json={"otp": "000000"}
    )
    assert r.status_code == 400

    # enable с верным кодом → включено
    r = await client.post(
        "/api/auth/2fa/enable", headers=auth_headers, json={"otp": _code(secret)}
    )
    assert r.status_code == 200 and r.json()["enabled"] is True

    # логин без кода → 401 «2fa_required»
    r = await client.post(
        "/api/auth/login", json={"username": "admin", "password": "testpass"}
    )
    assert r.status_code == 401 and r.json()["detail"] == "2fa_required"

    # логин с кодом → токен
    r = await client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "testpass", "otp": _code(secret)},
    )
    assert r.status_code == 200 and "access_token" in r.json()

    # неверный код при логине → «2fa_invalid»
    r = await client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "testpass", "otp": "000000"},
    )
    assert r.status_code == 401 and r.json()["detail"] == "2fa_invalid"

    # disable с верным кодом
    r = await client.post(
        "/api/auth/2fa/disable", headers=auth_headers, json={"otp": _code(secret)}
    )
    assert r.status_code == 200 and r.json()["enabled"] is False

    # снова можно логиниться без кода
    r = await client.post(
        "/api/auth/login", json={"username": "admin", "password": "testpass"}
    )
    assert r.status_code == 200
