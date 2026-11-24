"""Login, step-up and API-key scope hardening."""
import asyncio
import time
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy import select

from app import config, ratelimit, stepup, totp
from app.api import auth
from app.bootstrap import ensure_admin, prune_api_key_scopes
from app.models import ApiKey, AuditLog, Server, User

NEW_SERVER = {"name": "lab-a", "host": "203.0.113.10", "ssh_port": 2221, "ssh_user": "ms-dev"}


async def test_parallel_wrong_passwords_stop_at_the_limit(client):
    attempts = ratelimit.MAX_FAILURES * 3
    replies = await asyncio.gather(*(
        client.post("/api/auth/login", json={"username": "admin", "password": f"bad{i}"})
        for i in range(attempts)
    ))
    codes = [r.status_code for r in replies]
    assert codes.count(401) == ratelimit.MAX_FAILURES
    assert codes.count(429) == attempts - ratelimit.MAX_FAILURES
    assert not ratelimit._queues


async def test_parallel_second_factor_guesses_stop_at_the_limit(client, session_factory):
    secret = totp.random_secret()
    async with session_factory() as s:
        user = await s.scalar(select(User))
        user.totp_secret, user.totp_enabled = secret, True
        await s.commit()
    good = totp.matched_counter(secret, totp._hotp(secret, int(time.time() // 30)))
    wrong = [f"{(i * 7919) % 1000000:06d}" for i in range(ratelimit.MAX_FAILURES * 3)]
    wrong = [c for c in wrong if totp.matched_counter(secret, c) is None]
    assert good is not None
    replies = await asyncio.gather(*(
        client.post("/api/auth/login", json={"username": "admin", "password": "testpass", "otp": c})
        for c in wrong
    ))
    assert [r.json()["detail"] for r in replies].count("2fa_invalid") == ratelimit.MAX_FAILURES
    assert all(r.status_code in (401, 429) for r in replies)


async def test_parallel_step_up_guesses_stop_at_the_limit(client, session_factory):
    request = SimpleNamespace(client=SimpleNamespace(host="198.51.100.20"), headers={})
    async with session_factory() as s:
        user = await s.scalar(select(User))

        async def attempt(i):
            try:
                await stepup.verify(user, f"bad{i}", request)
            except HTTPException as exc:
                return exc.status_code
            return 200

        codes = await asyncio.gather(*(attempt(i) for i in range(ratelimit.MAX_FAILURES * 3)))
    assert codes.count(403) == ratelimit.MAX_FAILURES
    assert codes.count(429) == ratelimit.MAX_FAILURES * 2


async def test_queue_entries_are_dropped_after_errors_and_cancellation():
    with pytest.raises(RuntimeError):
        async with ratelimit.serialized("a", "b"):
            raise RuntimeError
    holder = asyncio.Event()

    async def hold():
        async with ratelimit.serialized("a"):
            holder.set()
            await asyncio.sleep(10)

    first = asyncio.create_task(hold())
    await holder.wait()

    async def wait():
        async with ratelimit.serialized("b", "a"):
            pass

    second = asyncio.create_task(wait())
    await asyncio.sleep(0)
    second.cancel()
    first.cancel()
    await asyncio.gather(first, second, return_exceptions=True)
    assert not ratelimit._queues


async def test_known_address_survives_a_restart(client, session_factory, monkeypatch):
    peer = "127.0.0.1"
    async with session_factory() as s:
        s.add(AuditLog(username="admin", action="login_ok", target=peer))
        await s.commit()
    auth._known_ips.clear()
    monkeypatch.setattr(auth, "_known_loaded", False)
    for _ in range(auth.USER_MAX_FAILURES):
        ratelimit.record_failure(auth._user_key("admin"), max_failures=auth.USER_MAX_FAILURES)
    assert ratelimit.is_locked(auth._user_key("admin"))
    r = await client.post("/api/auth/login", json={"username": "admin", "password": "testpass"})
    assert r.status_code == 200, r.text
    # the login stays locked for everyone else
    assert ratelimit.is_locked(auth._user_key("admin"))


async def test_old_and_foreign_logins_are_not_trusted(session_factory, client, monkeypatch):
    from datetime import datetime, timedelta, timezone
    old = datetime.now(timezone.utc) - timedelta(seconds=auth.KNOWN_IP_TTL + 60)
    async with session_factory() as s:
        s.add(AuditLog(username="admin", action="login_ok", target="198.51.100.1", ts=old))
        s.add(AuditLog(username="admin", action="login_fail", target="198.51.100.2"))
        s.add(AuditLog(username="admin", action="login_ok", target="2001:db8::5"))
        await s.commit()
        auth._known_ips.clear()
        monkeypatch.setattr(auth, "_known_loaded", False)
        await auth._load_known_ips(s)
    assert not auth._known_ip("admin", "198.51.100.1")
    assert not auth._known_ip("admin", "198.51.100.2")
    assert auth._known_ip("admin", ratelimit.ip_key("2001:db8::77"))


async def test_long_login_is_kept_in_the_journal(client, session_factory):
    name = "x" * 128
    r = await client.post("/api/auth/login", json={"username": name, "password": "bad"})
    assert r.status_code == 401
    async with session_factory() as s:
        row = await s.scalar(select(AuditLog).where(AuditLog.action == "login_fail"))
    assert row is not None and row.username == name[:64]


async def test_break_glass_reset_revokes_api_keys(client, auth_headers, session_factory, monkeypatch):
    r = await client.post("/api/apikeys", json={"name": "ci", "password": "testpass"}, headers=auth_headers)
    assert r.status_code == 201, r.text
    key = r.json()["key"]
    assert (await client.get("/api/v1/servers", headers={"X-API-Key": key})).status_code == 200
    monkeypatch.setenv("VPNPANEL_ADMIN_PASSWORD_RESET", "1")
    config.get_settings.cache_clear()
    await ensure_admin(session_factory, config.get_settings())
    async with session_factory() as s:
        assert all(k.revoked for k in (await s.scalars(select(ApiKey))).all())
    assert (await client.get("/api/v1/servers", headers={"X-API-Key": key})).status_code == 401


async def _key_for(client, headers, server_ids):
    r = await client.post("/api/apikeys", json={"name": "k", "password": "testpass"}, headers=headers)
    assert r.status_code == 201, r.text
    key_id = r.json()["id"]
    r = await client.put(f"/api/apikeys/{key_id}", headers=headers,
                         json={"server_ids": server_ids, "all_servers": False, "password": "testpass"})
    assert r.status_code == 200, r.text
    return key_id


async def test_deleted_server_leaves_api_key_scopes(client, auth_headers, session_factory):
    a = (await client.post("/api/servers", json=NEW_SERVER, headers=auth_headers)).json()["id"]
    b = (await client.post("/api/servers", json={**NEW_SERVER, "name": "lab-b", "host": "203.0.113.11"},
                           headers=auth_headers)).json()["id"]
    both = await _key_for(client, auth_headers, [a, b])
    only_b = await _key_for(client, auth_headers, [b])
    assert (await client.delete(f"/api/servers/{b}", headers=auth_headers)).status_code == 200
    async with session_factory() as s:
        rows = {k.id: k for k in (await s.scalars(select(ApiKey))).all()}
        actions = [r.action for r in (await s.scalars(select(AuditLog))).all()]
    assert rows[both].server_ids == [a] and not rows[both].revoked
    # an empty list would mean "all servers": the key is revoked instead
    assert rows[only_b].revoked
    assert "apikey_revoke" in actions
    c = (await client.post("/api/servers", json={**NEW_SERVER, "name": "lab-c", "host": "203.0.113.12"},
                           headers=auth_headers)).json()["id"]
    async with session_factory() as s:
        assert c not in (await s.get(ApiKey, both)).server_ids


async def test_startup_drops_ids_of_servers_deleted_before_the_fix(client, auth_headers, session_factory):
    a = (await client.post("/api/servers", json=NEW_SERVER, headers=auth_headers)).json()["id"]
    async with session_factory() as s:
        s.add(ApiKey(name="mixed", prefix="aaaaaaaa", key_hash="x", servers=f"{a},999"))
        s.add(ApiKey(name="gone", prefix="bbbbbbbb", key_hash="x", servers="998,999"))
        s.add(ApiKey(name="all", prefix="cccccccc", key_hash="x", servers=""))
        await s.commit()
    await prune_api_key_scopes(session_factory)
    async with session_factory() as s:
        rows = {k.name: k for k in (await s.scalars(select(ApiKey))).all()}
        assert await s.get(Server, a) is not None
    assert rows["mixed"].server_ids == [a] and not rows["mixed"].revoked
    assert rows["gone"].revoked
    assert rows["all"].servers == "" and not rows["all"].revoked
