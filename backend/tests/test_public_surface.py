"""What a caller without a login or an API key can reach or cause."""
import asyncio

from fastapi import HTTPException

from app import alerts, ratelimit
from app.api import auth
from app.deps import APIKEY_MAX_FAILURES
from app.models import ApiKey


async def test_parallel_wrong_api_keys_stop_at_the_limit(client):
    attempts = APIKEY_MAX_FAILURES * 2
    replies = await asyncio.gather(*(
        client.get("/api/v1/servers", headers={"X-API-Key": f"ack_aaaaaaaa_{i:032d}"})
        for i in range(attempts)
    ))
    codes = [r.status_code for r in replies]
    assert codes.count(401) == APIKEY_MAX_FAILURES
    assert codes.count(429) == attempts - APIKEY_MAX_FAILURES
    assert not ratelimit._queues


def test_unparsable_server_scope_allows_nothing():
    assert ApiKey(servers="").allows(5)
    assert ApiKey(servers="5,7").allows(7) and not ApiKey(servers="5,7").allows(6)
    for junk in ("x", " , ", "all", "5;7"):
        assert not ApiKey(servers=junk).allows(5), junk


async def test_unauthenticated_noise_stays_out_of_the_diagnostics(client, auth_headers):
    for _ in range(3):
        r = await client.post("/api/servers", content=b"{", headers={"Content-Type": "application/json"})
        assert r.status_code in (401, 422)
    r = await client.post("/api/servers", json={"name": "x"})
    assert r.status_code == 401
    assert (await client.get("/api/debug-logs", headers=auth_headers)).json()["events"] == []
    # the same mistake with a login is still recorded
    r = await client.post("/api/servers", json={"name": "x"}, headers=auth_headers)
    assert r.status_code == 422
    events = (await client.get("/api/debug-logs", headers=auth_headers)).json()["events"]
    assert [e["code"] for e in events] == ["validation"]


async def test_lockout_alerts_are_rate_limited_and_skip_unknown_logins(client, monkeypatch):
    sent = []

    async def capture(session, settings, card):
        sent.append(card)

    monkeypatch.setattr(alerts, "security_alert", capture)
    # an unknown login locked from many addresses: journal only, no alert text from the request
    for _ in range(auth.USER_MAX_FAILURES - 1):
        ratelimit.record_failure(auth._user_key("https://evil.example/unlock"), max_failures=auth.USER_MAX_FAILURES)
    r = await client.post("/api/auth/login", json={"username": "https://evil.example/unlock", "password": "x"})
    assert r.status_code == 401
    assert not any("evil" in alerts._text(c.title, "ru") for c in sent)
    sent.clear()
    ratelimit.clear("127.0.0.1")

    # address lockouts: the first one alerts, the next ones are counted into the following alert
    for round_ in range(3):
        for _ in range(ratelimit.MAX_FAILURES):
            await client.post("/api/auth/login", json={"username": "admin", "password": "bad"})
        ratelimit.clear("127.0.0.1")
        ratelimit.clear(auth._user_key("admin"))
    titles = [alerts._text(c.title, "ru") for c in sent]
    assert titles.count("Подбор пароля к панели") == 1
    assert auth._alert_skipped["ip"] == 2
    auth._alert_last["ip"] -= auth.ALERT_EVERY
    for _ in range(ratelimit.MAX_FAILURES):
        await client.post("/api/auth/login", json={"username": "admin", "password": "bad"})
    assert "Еще блокировок после прошлого алерта: 2" in alerts._text(sent[-1].detail, "ru")
    assert "More lockouts since the previous alert: 2" in alerts._text(sent[-1].detail, "en")
