"""Закрытые дыры авторизации: степ-ап на API-ключи, алерты и выгрузку сервера,
код 2FA в степ-апе, лимиты по пользователю, известные адреса входа, размер
лимитера, кэш ключей, версии токенов после restore, версия в OpenAPI."""

import time
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from sqlalchemy import select, update

from app import apikeys, clientip, config, ratelimit, stepup, totp
from app.models import ApiKey, User
from app.security import hash_password

PW = "testpass"


async def _server(client, headers, host="203.0.113.31") -> int:
    r = await client.post(
        "/api/servers",
        json={"name": host, "host": host, "ssh_port": 22, "ssh_user": "amn"},
        headers=headers,
    )
    assert r.status_code == 201, r.text
    return r.json()["id"]


@pytest.fixture
def sent(monkeypatch):
    """Перехват security-алертов (и без похода в сеть)."""
    cards = []

    async def fake(session, settings, card):
        cards.append(card)

    monkeypatch.setattr("app.alerts.security_alert", fake)
    return cards


async def _enable_2fa(client) -> str:
    secret = totp.random_secret()
    async with client.session_factory() as s:
        await s.execute(
            update(User).values(totp_secret=secret, totp_enabled=True, totp_last_counter=0)
        )
        await s.commit()
    return secret


def _code(secret: str, shift: int = 0) -> str:
    return totp._hotp(secret, int(time.time() // 30) + shift)


# --- 1. API-ключи ----------------------------------------------------------

async def test_apikey_create_and_update_need_password(client, auth_headers, sent):
    r = await client.post("/api/apikeys", json={"name": "x"}, headers=auth_headers)
    assert r.status_code == 422
    r = await client.post(
        "/api/apikeys", json={"name": "x", "password": "nope"}, headers=auth_headers
    )
    assert r.status_code == 403
    async with client.session_factory() as s:
        assert (await s.scalars(select(ApiKey))).all() == []

    r = await client.post(
        "/api/apikeys", json={"name": "billing", "password": PW}, headers=auth_headers
    )
    assert r.status_code == 201, r.text
    kid = r.json()["id"]
    assert any("billing" in str(c.title.kw) for c in sent)

    r = await client.put(f"/api/apikeys/{kid}", json={"server_ids": []}, headers=auth_headers)
    assert r.status_code == 422
    r = await client.put(
        f"/api/apikeys/{kid}", json={"server_ids": [], "password": "nope"},
        headers=auth_headers,
    )
    assert r.status_code == 403


# --- 10. пустой список серверов только явным "все" ---------------------------

async def test_apikey_all_servers_explicit(client, auth_headers, sent):
    sid = await _server(client, auth_headers)
    r = await client.post(
        "/api/apikeys", json={"name": "k", "password": PW}, headers=auth_headers
    )
    kid = r.json()["id"]
    assert r.json()["all_servers"] is True
    url = f"/api/apikeys/{kid}"
    r = await client.put(url, json={"server_ids": [sid], "all_servers": False, "password": PW},
                         headers=auth_headers)
    assert r.status_code == 200 and r.json()["all_servers"] is False
    # снятие последней галки не дает доступ ко всем
    r = await client.put(url, json={"server_ids": [], "all_servers": False, "password": PW},
                         headers=auth_headers)
    assert r.status_code == 400
    r = await client.put(url, json={"server_ids": [sid], "all_servers": True, "password": PW},
                         headers=auth_headers)
    assert r.status_code == 200
    assert r.json()["server_ids"] == [] and r.json()["all_servers"] is True


# --- 2. алерты и выгрузка сервера ---------------------------------------------

async def test_alerts_put_needs_password(client, auth_headers):
    body = {"telegram_token": "", "telegram_chat": "", "webhook": "https://ex/hook"}
    r = await client.put("/api/alerts", json=body, headers=auth_headers)
    assert r.status_code == 403
    r = await client.put("/api/alerts", json={**body, "password": "nope"}, headers=auth_headers)
    assert r.status_code == 403
    assert (await client.get("/api/alerts", headers=auth_headers)).json()["webhook"] == ""


async def test_server_export_needs_password(client, auth_headers, sent):
    sid = await _server(client, auth_headers)
    url = f"/api/servers/{sid}/export"
    assert (await client.get(url, headers=auth_headers)).status_code == 403
    r = await client.get(url, headers={**auth_headers, "X-Confirm-Password": "nope"})
    assert r.status_code == 403
    r = await client.get(url, headers={**auth_headers, "X-Confirm-Password": PW})
    assert r.status_code == 200
    assert sent  # выгрузку видно в security-алертах


# --- 3. код 2FA в степ-апе, лимит по пользователю ----------------------------

async def test_stepup_requires_totp_when_enabled(client, auth_headers, sent):
    secret = await _enable_2fa(client)
    body = {"name": "k", "password": PW}
    r = await client.post("/api/apikeys", json=body, headers=auth_headers)
    assert r.status_code == 403
    assert r.headers.get("x-need-otp") == "1"
    assert r.json()["detail"] == "Нужен код 2FA"

    r = await client.post("/api/apikeys", json={**body, "otp": "000000"}, headers=auth_headers)
    assert r.status_code == 403 and r.json()["detail"] == "Неверный код 2FA"

    code = _code(secret)
    r = await client.post("/api/apikeys", json={**body, "otp": code}, headers=auth_headers)
    assert r.status_code == 201, r.text
    # повтор того же кода не проходит
    r = await client.post("/api/apikeys", json={**body, "otp": code}, headers=auth_headers)
    assert r.status_code == 403

    # код заголовком - для ручек без поля в теле
    sid = await _server(client, auth_headers)
    r = await client.get(
        f"/api/servers/{sid}/export",
        headers={**auth_headers, "X-Confirm-Password": PW, "X-Confirm-OTP": _code(secret, 1)},
    )
    assert r.status_code == 200, r.text


async def test_stepup_limit_per_user_across_ips():
    user = SimpleNamespace(username="admin", password_hash=hash_password("right"))
    for i in range(ratelimit.MAX_FAILURES):
        req = SimpleNamespace(client=SimpleNamespace(host=f"8.8.{i}.1"))
        with pytest.raises(Exception):
            await stepup.verify(user, "wrong", req)
    fresh = SimpleNamespace(client=SimpleNamespace(host="9.9.9.9"))
    with pytest.raises(Exception) as ei:
        await stepup.verify(user, "right", fresh)
    assert ei.value.status_code == 429


# --- 4. блокировка логина не запирает известный адрес ------------------------

async def test_user_lockout_spares_known_ip(client):
    ok = await client.post("/api/auth/login", json={"username": "admin", "password": PW})
    assert ok.status_code == 200
    # чужой перебор с разных адресов запер логин
    for i in range(30):
        await client.post(
            "/api/auth/login", json={"username": "admin", "password": "bad"},
            headers={"X-Forwarded-For": f"8.8.{i}.8"},
        )
    other = await client.post(
        "/api/auth/login", json={"username": "admin", "password": PW},
        headers={"X-Forwarded-For": "9.9.9.9"},
    )
    assert other.status_code == 429
    # с адреса прошлого успешного входа админ входит
    r = await client.post("/api/auth/login", json={"username": "admin", "password": PW})
    assert r.status_code == 200
    # и этим не открывает логин остальным
    other = await client.post(
        "/api/auth/login", json={"username": "admin", "password": PW},
        headers={"X-Forwarded-For": "9.9.9.9"},
    )
    assert other.status_code == 429


# --- 5. размеры: логин и лимитер ---------------------------------------------

async def test_login_fields_are_bounded(client):
    r = await client.post("/api/auth/login", json={"username": "a" * 129, "password": "x"})
    assert r.status_code == 422
    r = await client.post("/api/auth/login", json={"username": "admin", "password": "x" * 129})
    assert r.status_code == 422


def test_ratelimit_prunes_and_caps(monkeypatch):
    monkeypatch.setattr(ratelimit, "MAX_KEYS", 50)
    t0 = 1_000_000.0
    for i in range(200):
        ratelimit.record_failure(f"user:{i}", now=t0)
    assert len(ratelimit._failures) <= 51
    # протухшие записи вычищаются при следующей неудаче после окна
    ratelimit.record_failure("user:late", now=t0 + ratelimit.WINDOW + 1)
    assert list(ratelimit._failures) == ["user:late"]


# --- 7. кэш проверок API-ключа и лимит неудач --------------------------------

async def test_apikey_bcrypt_cached_and_bad_keys_limited(client, auth_headers, monkeypatch):
    r = await client.post("/api/apikeys", json={"name": "k", "password": PW}, headers=auth_headers)
    key = r.json()["key"]
    calls = []
    real = apikeys._check
    monkeypatch.setattr(apikeys, "_check", lambda s, h: calls.append(1) or real(s, h))
    for _ in range(3):
        assert (await client.get("/api/v1/servers", headers={"X-API-Key": key})).status_code == 200
    assert len(calls) == 1

    prefix = apikeys.split(key)[0]
    bad = {"X-API-Key": f"ack_{prefix}_{'x' * 32}"}
    codes = [(await client.get("/api/v1/servers", headers=bad)).status_code for _ in range(31)]
    assert codes[0] == 401 and codes[-1] == 429


async def test_password_change_revokes_cached_api_keys(client, auth_headers, sent):
    created = await client.post(
        "/api/apikeys", json={"name": "integration", "password": PW}, headers=auth_headers
    )
    assert created.status_code == 201
    key_headers = {"X-API-Key": created.json()["key"]}
    assert (await client.get("/api/v1/servers", headers=key_headers)).status_code == 200
    assert apikeys._ok_cache
    changed = await client.post(
        "/api/auth/password", headers=auth_headers,
        json={"current_password": PW, "new_password": "new-test-password"},
    )
    assert changed.status_code == 200
    assert apikeys._ok_cache == {}
    assert (await client.get("/api/v1/servers", headers=key_headers)).status_code == 401
    fresh = {"Authorization": "Bearer " + changed.json()["access_token"]}
    keys = (await client.get("/api/apikeys", headers=fresh)).json()
    assert keys[0]["revoked"] is True


# --- 8. restore не оживляет старые токены и отозванные ключи ------------------

@pytest.mark.parametrize("restore_older_first", [False, True])
async def test_restore_bumps_token_version_and_keeps_revoked(
    client, auth_headers, sent, restore_older_first
):
    if restore_older_first:
        older_archive = (await client.post(
            "/api/backup/download", headers=auth_headers, json={"password": PW}
        )).content
    r = await client.post("/api/apikeys", json={"name": "k", "password": PW}, headers=auth_headers)
    kid, key = r.json()["id"], r.json()["key"]
    stolen = dict(auth_headers)
    archive = (await client.post(
        "/api/backup/download", headers=auth_headers, json={"password": PW}
    )).content
    # после бэкапа: выход (токен отозван) и отзыв ключа
    login = await client.post("/api/auth/login", json={"username": "admin", "password": PW})
    h = {"Authorization": f"Bearer {login.json()['access_token']}"}
    assert (await client.post("/api/auth/logout", headers=stolen)).status_code == 204
    login = await client.post("/api/auth/login", json={"username": "admin", "password": PW})
    h = {"Authorization": f"Bearer {login.json()['access_token']}"}
    assert (await client.delete(f"/api/apikeys/{kid}", headers=h)).status_code == 204

    if restore_older_first:
        older = await client.post(
            "/api/backup/restore", content=older_archive,
            headers={**h, "X-Confirm-Password": PW},
        )
        assert older.status_code == 200, older.text
        h = {"Authorization": f"Bearer {older.json()['access_token']}"}
        keys = (await client.get("/api/apikeys", headers=h)).json()
        assert len(keys) == 1 and keys[0]["revoked"] is True

    r = await client.post(
        "/api/backup/restore", content=archive, headers={**h, "X-Confirm-Password": PW}
    )
    assert r.status_code == 200, r.text
    assert (await client.get("/api/auth/me", headers=stolen)).status_code == 401
    assert (await client.get("/api/auth/me", headers=h)).status_code == 401
    fresh = {"Authorization": f"Bearer {r.json()['access_token']}"}
    assert (await client.get("/api/auth/me", headers=fresh)).status_code == 200
    assert (await client.get("/api/v1/servers", headers={"X-API-Key": key})).status_code == 401


# --- 9. OpenAPI без версии панели --------------------------------------------

async def test_openapi_hides_panel_version(client):
    r = await client.get("/api/openapi.json")
    assert r.status_code == 200
    assert r.json()["info"]["version"] != config.get_settings().version


# --- 6. шлюз docker-сети и исключения в trusted_proxies -----------------------

def _req(host, xff):
    return SimpleNamespace(client=SimpleNamespace(host=host), headers={"x-forwarded-for": xff})


@pytest.mark.parametrize(
    "spec,bind,expected",
    [
        ("", "127.0.0.1:8080", "1.1.1.1"),  # прокси на хосте через шлюз - верим
        ("", "0.0.0.0:8080", "172.18.0.1"),  # порт открыт наружу - шлюзу не верим
        ("127.0.0.0/8 172.16.0.0/12 !gateway", "", "172.18.0.1"),
        ("127.0.0.0/8 172.16.0.0/12 !172.18.0.1", "", "172.18.0.1"),
    ],
)
def test_gateway_trust(monkeypatch, spec, bind, expected):
    monkeypatch.setattr(clientip, "_default_gateway", lambda: "172.18.0.1")
    monkeypatch.setattr(
        clientip, "get_settings", lambda: SimpleNamespace(trusted_proxies=spec, panel_bind=bind)
    )
    clientip._networks.cache_clear()
    try:
        # nginx (172.18.0.3) дописал адрес шлюза, левее - подделка клиента
        assert clientip.client_ip(_req("172.18.0.3", "1.1.1.1, 172.18.0.1")) == expected
    finally:
        clientip._networks.cache_clear()


def test_compose_passes_bind_to_proxy_trust_detection():
    compose = (Path(__file__).resolve().parents[2] / "compose.yml").read_text(encoding="utf-8")
    assert "VPNPANEL_PANEL_BIND: ${ACONTROL_BIND:-127.0.0.1:8080}" in compose
