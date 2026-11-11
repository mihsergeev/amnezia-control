import asyncio
import json

import pytest

from app import geo, server_ops, sshops
from app.models import Server


TARGET = {"name": "203.0.113.10", "host": "203.0.113.10", "ssh_user": "ms-dev"}
ONBOARDING = "/api/servers?reuse_ssh_endpoint=true&name_from_hostname=true"


def mock_check(monkeypatch, *, ok=True, hostname="entry.example.com", country="fi"):
    lookups = []

    async def check(*_args):
        return sshops.CheckResult(ok=ok, hostname=hostname, error="" if ok else "SSH failed")

    async def lookup(host):
        lookups.append(host)
        return country

    monkeypatch.setattr(sshops, "check_server", check)
    monkeypatch.setattr(geo, "country_code", lookup)
    return lookups


async def test_unnamed_wizard_server_gets_verified_hostname_and_flag_once(client, auth_headers, monkeypatch):
    created = await client.post(ONBOARDING, json=TARGET, headers=auth_headers)
    assert created.status_code == 201
    sid = created.json()["id"]
    assert created.json()["name"] == TARGET["host"]
    assert json.loads(created.json()["last_check_info"])[server_ops.ONBOARDING_NAME_PENDING] is True
    lookups = mock_check(monkeypatch)
    checked = await client.post(f"/api/servers/{sid}/check", headers=auth_headers)
    assert checked.status_code == 200
    assert checked.json()["name"] == "entry.example.com"
    assert checked.json()["country"] == "FI"
    assert server_ops.ONBOARDING_NAME_PENDING not in json.loads(checked.json()["last_check_info"])
    assert lookups == [TARGET["host"]]

    # The name and geography survive a subsequent observation of another hostname.
    lookups = mock_check(monkeypatch, hostname="changed.example.com", country="DE")
    checked = await client.post(f"/api/servers/{sid}/check", headers=auth_headers)
    assert checked.json()["name"] == "entry.example.com"
    assert checked.json()["country"] == "FI"
    assert lookups == []


@pytest.mark.parametrize("hostname", ["", "   ", "bad\nname", "x" * 129])
async def test_unusable_hostname_keeps_address_fallback(client, auth_headers, monkeypatch, hostname):
    created = await client.post(ONBOARDING, json=TARGET, headers=auth_headers)
    sid = created.json()["id"]
    mock_check(monkeypatch, hostname=hostname, country="")
    checked = await client.post(f"/api/servers/{sid}/check", headers=auth_headers)
    assert checked.json()["name"] == TARGET["host"]
    assert checked.json()["country"] == ""
    assert server_ops.ONBOARDING_NAME_PENDING not in json.loads(checked.json()["last_check_info"])


async def test_failed_and_periodic_checks_preserve_pending_onboarding(client, auth_headers, monkeypatch):
    created = await client.post(ONBOARDING, json=TARGET, headers=auth_headers)
    sid = created.json()["id"]
    lookups = mock_check(monkeypatch, ok=False, hostname="unverified.example.com")
    checked = await client.post(f"/api/servers/{sid}/check", headers=auth_headers)
    assert checked.json()["name"] == TARGET["host"]
    assert checked.json()["country"] == ""
    assert json.loads(checked.json()["last_check_info"])[server_ops.ONBOARDING_NAME_PENDING] is True
    assert lookups == []

    # The collector also writes metadata through this shared persistence path.
    async with client.session_factory() as session:
        server = await session.get(Server, sid)
        await server_ops.store_check_info(session, server, {"hostname": "periodic.example.com"})
        await session.commit()
        assert json.loads(server.last_check_info)[server_ops.ONBOARDING_NAME_PENDING] is True
        assert server.name == TARGET["host"]

    mock_check(monkeypatch)
    checked = await client.post(f"/api/servers/{sid}/check", headers=auth_headers)
    assert checked.json()["name"] == "entry.example.com" and checked.json()["country"] == "FI"


@pytest.mark.parametrize("name", ["My entry", TARGET["host"]])
async def test_reused_existing_server_name_is_never_changed(client, auth_headers, monkeypatch, name):
    original = await client.post("/api/servers", json=TARGET | {"name": name}, headers=auth_headers)
    retry = await client.post(ONBOARDING, json=TARGET, headers=auth_headers)
    assert retry.status_code == 200
    assert retry.json()["id"] == original.json()["id"]
    assert server_ops.ONBOARDING_NAME_PENDING not in json.loads(retry.json()["last_check_info"] or "{}")
    mock_check(monkeypatch)
    checked = await client.post(f"/api/servers/{original.json()['id']}/check", headers=auth_headers)
    assert checked.json()["name"] == name
    assert checked.json()["country"] == "FI"


async def test_explicit_wizard_name_and_later_manual_edit_take_precedence(client, auth_headers, monkeypatch):
    explicit = await client.post("/api/servers?reuse_ssh_endpoint=true", json=TARGET | {"name": "Custom entry"}, headers=auth_headers)
    sid = explicit.json()["id"]
    mock_check(monkeypatch)
    checked = await client.post(f"/api/servers/{sid}/check", headers=auth_headers)
    assert checked.json()["name"] == "Custom entry"
    pending = await client.post(ONBOARDING, json={"name": "203.0.113.11", "host": "203.0.113.11"}, headers=auth_headers)
    pending_id = pending.json()["id"]
    edited = await client.patch(f"/api/servers/{pending_id}", json={"name": "Manual name"}, headers=auth_headers)
    assert server_ops.ONBOARDING_NAME_PENDING not in json.loads(edited.json()["last_check_info"])
    checked = await client.post(f"/api/servers/{pending_id}/check", headers=auth_headers)
    assert checked.json()["name"] == "Manual name"


@pytest.mark.parametrize("country", ["XX", "not-a-country", None])
async def test_unknown_geo_does_not_invent_a_flag(client, auth_headers, monkeypatch, country):
    created = await client.post(ONBOARDING, json=TARGET, headers=auth_headers)
    mock_check(monkeypatch, country=country)
    checked = await client.post(f"/api/servers/{created.json()['id']}/check", headers=auth_headers)
    assert checked.json()["last_check_ok"] is True
    assert checked.json()["name"] == "entry.example.com"
    assert checked.json()["country"] == ""


@pytest.mark.parametrize("pause_at", ["ssh", "geo"])
@pytest.mark.parametrize("changes", [
    {"name": "Manual name"},
    {"host": "203.0.113.20"},
    {"ssh_port": 2222},
    {"ssh_user": "operator"},
])
async def test_concurrent_manual_edit_discards_stale_check(
    client, auth_headers, monkeypatch, pause_at, changes,
):
    created = await client.post(ONBOARDING, json=TARGET, headers=auth_headers)
    sid = created.json()["id"]
    paused, resume = asyncio.Event(), asyncio.Event()

    async def pause(stage):
        if stage == pause_at:
            paused.set()
            await resume.wait()

    async def check(*_args):
        await pause("ssh")
        return sshops.CheckResult(ok=True, hostname="old-target.example.com")

    async def country(_host):
        await pause("geo")
        return "FI"

    monkeypatch.setattr(sshops, "check_server", check)
    monkeypatch.setattr(geo, "country_code", country)
    task = asyncio.create_task(client.post(f"/api/servers/{sid}/check", headers=auth_headers))
    try:
        await asyncio.wait_for(paused.wait(), timeout=5)
        # PATCH must finish while the network lookup remains paused.
        edited = await asyncio.wait_for(client.patch(
            f"/api/servers/{sid}", json=changes, headers=auth_headers,
        ), timeout=5)
        assert edited.status_code == 200
        expected = edited.json()
    finally:
        resume.set()
    checked = await asyncio.wait_for(task, timeout=5)
    assert checked.status_code == 200
    persisted = (await client.get(f"/api/servers/{sid}", headers=auth_headers)).json()
    for record in (checked.json(), persisted):
        for field in ("name", "host", "ssh_port", "ssh_user", "last_check_info", "last_check_ok", "last_check_at", "country"):
            assert record[field] == expected[field]
        assert server_ops.ONBOARDING_NAME_PENDING not in json.loads(record["last_check_info"])
