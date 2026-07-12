"""Степ-ап: экспорт «полного доступа» и смена пароля требуют верного пароля и
защищены от брутфорса (общий ключ лимитера)."""

from types import SimpleNamespace

import httpx
import pytest
from fastapi import HTTPException

from app import ratelimit, stepup
from app.security import hash_password


def _req(ip="1.2.3.4"):
    return SimpleNamespace(client=SimpleNamespace(host=ip))


def test_stepup_verify_and_lockout():
    ratelimit._failures.clear()
    user = SimpleNamespace(password_hash=hash_password("correct-pass"))
    req = _req()

    stepup.verify(user, "correct-pass", req)  # верный пароль — без исключения

    with pytest.raises(HTTPException) as ei:
        stepup.verify(user, "wrong", req)
    assert ei.value.status_code == 403  # неверный пароль

    # добиваем до блокировки — дальше даже верный пароль даёт 429
    for _ in range(ratelimit.MAX_FAILURES):
        try:
            stepup.verify(user, "wrong", req)
        except HTTPException:
            pass
    with pytest.raises(HTTPException) as ei2:
        stepup.verify(user, "correct-pass", req)
    assert ei2.value.status_code == 429
    ratelimit._failures.clear()


async def test_fullaccess_requires_password(
    client: httpx.AsyncClient, auth_headers: dict[str, str]
):
    r = await client.post(
        "/api/servers",
        headers=auth_headers,
        json={"name": "srv", "host": "203.0.113.9", "ssh_port": 2221,
              "ssh_user": "acontrol"},
    )
    sid = r.json()["id"]

    # без пароля — 422 (тело обязательно)
    r = await client.post(f"/api/servers/{sid}/fullaccess", headers=auth_headers)
    assert r.status_code == 422

    # неверный пароль — 403, до всякого SSH
    r = await client.post(
        f"/api/servers/{sid}/fullaccess", headers=auth_headers,
        json={"password": "definitely-wrong"},
    )
    assert r.status_code == 403
    # (верный пароль прошёл бы степ-ап и упёрся в реальный SSH — не проверяем,
    # чтобы не ждать таймаут подключения к несуществующему серверу)


async def test_password_change_wrong_current_is_rate_limited(
    client: httpx.AsyncClient, auth_headers: dict[str, str]
):
    # неверный текущий пароль — 400
    for _ in range(ratelimit.MAX_FAILURES):
        r = await client.post(
            "/api/auth/password", headers=auth_headers,
            json={"current_password": "nope", "new_password": "brandnew123"},
        )
        assert r.status_code == 400
    # после лимита — 429 (даже с верным текущим паролем)
    r = await client.post(
        "/api/auth/password", headers=auth_headers,
        json={"current_password": "testpass", "new_password": "brandnew123"},
    )
    assert r.status_code == 429
