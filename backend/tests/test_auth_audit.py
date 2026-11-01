import time
from contextlib import asynccontextmanager
from types import SimpleNamespace

from sqlalchemy import select

from app import totp
from app.api import auth
from app.models import AwgConfig, User


async def test_2fa_new_secret_has_its_own_replay_counter(client, auth_headers):
    # Старый authenticator мог опережать часы на допустимое окно.
    async with client.session_factory() as s:
        user = await s.scalar(select(User))
        user.totp_last_counter = int(time.time() // 30) + 1
        await s.commit()
    setup = await client.post(
        "/api/auth/2fa/setup", headers=auth_headers, json={"password": "testpass"}
    )
    secret = setup.json()["secret"]
    code = totp._hotp(secret, int(time.time() // 30))
    enabled = await client.post(
        "/api/auth/2fa/enable", headers=auth_headers,
        json={"password": "testpass", "otp": code},
    )
    assert enabled.status_code == 200
    login = await client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "testpass", "otp": code},
    )
    assert login.status_code == 200, login.text


async def test_concurrent_logout_revokes_session_created_after_first_logout(client, auth_headers):
    req = SimpleNamespace(client=SimpleNamespace(host="203.0.113.10"), headers={})
    async with client.session_factory() as first, client.session_factory() as second:
        # Два запроса уже прошли авторизацию и загрузили одну версию пользователя.
        a = await first.scalar(select(User))
        b = await second.scalar(select(User))
        await auth.logout(req, a, first)
        login = await client.post(
            "/api/auth/login", json={"username": "admin", "password": "testpass"}
        )
        fresh = {"Authorization": "Bearer " + login.json()["access_token"]}
        await auth.logout(req, b, second)
    assert (await client.get("/api/auth/me", headers=fresh)).status_code == 401


async def test_v1_config_does_not_return_another_awg_protocol(client, auth_headers, monkeypatch):
    created = await client.post(
        "/api/servers", headers=auth_headers,
        json={"name": "vpn-a", "host": "203.0.113.10"},
    )
    sid = created.json()["id"]
    key = await client.post(
        "/api/apikeys", headers=auth_headers,
        json={"name": "integration", "password": "testpass"},
    )
    async with client.session_factory() as s:
        s.add(AwgConfig(
            server_id=sid, protocol="awg3", public_key="foreign-key",
            name="other-protocol", config="[Interface]\nPrivateKey = other-secret\n",
        ))
        await s.commit()
    # Изоляция проверяется до сборки ссылки, не зависит от формата протокола.
    monkeypatch.setattr("app.api.v1._amnezia_link", lambda config, server: "vpn://test")
    response = await client.get(
        f"/api/v1/servers/{sid}/clients/config", params={"public_key": "foreign-key"},
        headers={"X-API-Key": key.json()["key"]},
    )
    assert response.status_code == 404, response.text


async def test_v1_revoke_preserves_another_protocol_config(client, auth_headers, monkeypatch):
    created = await client.post(
        "/api/servers", headers=auth_headers,
        json={"name": "vpn-a", "host": "203.0.113.10"},
    )
    sid = created.json()["id"]
    key = await client.post(
        "/api/apikeys", headers=auth_headers,
        json={"name": "integration", "password": "testpass"},
    )
    async with client.session_factory() as s:
        s.add(AwgConfig(
            server_id=sid, protocol="awglegacy", public_key="foreign-key",
            name="other-protocol", config="test-config",
        ))
        await s.commit()

    @asynccontextmanager
    async def connect(server):
        yield object()

    async def read_state(conn, host):
        return SimpleNamespace(container="amnezia-awg2", interface="awg0")

    async def revoke(*args):
        pass

    monkeypatch.setattr("app.api.v1._connect", connect)
    monkeypatch.setattr("app.api.v1.awg.read_state", read_state)
    monkeypatch.setattr("app.api.v1.awg.revoke_client", revoke)
    response = await client.delete(
        f"/api/v1/servers/{sid}/clients", params={"public_key": "foreign-key"},
        headers={"X-API-Key": key.json()["key"]},
    )
    assert response.status_code == 204
    async with client.session_factory() as s:
        assert await s.scalar(select(AwgConfig).where(AwgConfig.public_key == "foreign-key"))
