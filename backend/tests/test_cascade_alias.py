import json

import pytest

from app import cascade_alias, geo, sshops
from app.models import AppSetting, Server

ROUTE = {"transport": "vless", "security": "reality", "network": "xhttp",
         "exit_host": "203.0.113.20", "exit_port": 443}


async def seed(client, headers):
    response = await client.post("/api/servers", headers=headers, json={
        "name": "vpn-entry", "host": "198.51.100.10", "ssh_user": "ms-dev",
    })
    server_id = response.json()["id"]
    async with client.session_factory() as session:
        server = await session.get(Server, server_id)
        server.last_check_info = json.dumps({"manual_cascade": ROUTE})
        await session.commit()
    return server_id


async def test_alias_survives_checks_only_for_same_endpoint(client, auth_headers, monkeypatch):
    server_id = await seed(client, auth_headers)
    url = f"/api/servers/{server_id}"
    response = await client.patch(url, headers=auth_headers, json={
        "name": "vpn-entry", "host": "198.51.100.10", "ssh_port": 22,
        "ssh_user": "ms-dev", "manual_exit_name": "  vpn-exit  ",
    })
    assert response.status_code == 200
    assert json.loads(response.json()["last_check_info"])["manual_cascade"]["exit_name"] == "vpn-exit"
    assert "manual_exit_name" not in response.json()
    observed = dict(ROUTE)
    looked_up = []

    async def country(host):
        looked_up.append(host)
        return "FI" if host == "203.0.113.21" else "KZ"

    async def check(*args):
        return sshops.CheckResult(ok=True, manual_cascade=dict(observed))

    monkeypatch.setattr(sshops, "check_server", check)
    monkeypatch.setattr(geo, "country_code", country)
    response = await client.post(url + "/check", headers=auth_headers)
    assert json.loads(response.json()["last_check_info"])["manual_cascade"]["exit_name"] == "vpn-exit"
    assert json.loads(response.json()["last_check_info"])["manual_cascade"]["exit_country"] == "KZ"
    observed["exit_port"] = 8443
    response = await client.post(url + "/check", headers=auth_headers)
    assert "exit_name" not in json.loads(response.json()["last_check_info"])["manual_cascade"]
    assert looked_up == ["203.0.113.20"]
    observed["exit_host"] = "203.0.113.21"
    response = await client.post(url + "/check", headers=auth_headers)
    peer = json.loads(response.json()["last_check_info"])["manual_cascade"]
    assert peer["exit_country"] == "FI" and "exit_name" not in peer
    assert looked_up == ["203.0.113.20", "203.0.113.21"]


async def test_alias_clear_null_and_delete(client, auth_headers):
    server_id = await seed(client, auth_headers)
    url = f"/api/servers/{server_id}"
    for body in ({"manual_exit_name": "vpn-exit"}, {"manual_exit_name": None}):
        assert (await client.patch(url, headers=auth_headers, json=body)).status_code == 200
    response = await client.patch(url, headers=auth_headers, json={"manual_exit_name": ""})
    assert "exit_name" not in json.loads(response.json()["last_check_info"])["manual_cascade"]
    await client.patch(url, headers=auth_headers, json={"manual_exit_name": "vpn-exit"})
    assert (await client.delete(url, headers=auth_headers)).status_code == 200
    async with client.session_factory() as session:
        assert await session.get(AppSetting, cascade_alias._key(server_id)) is None


async def test_host_change_invalidates_manual_peer(client, auth_headers):
    server_id = await seed(client, auth_headers)
    url = f"/api/servers/{server_id}"
    await client.patch(url, headers=auth_headers, json={"manual_exit_name": "vpn-exit"})
    response = await client.patch(url, headers=auth_headers, json={
        "host": "198.51.100.11", "manual_exit_name": "wrong-peer",
    })
    assert response.status_code == 409
    response = await client.patch(url, headers=auth_headers, json={"host": "198.51.100.11"})
    assert "manual_cascade" not in json.loads(response.json()["last_check_info"])
    async with client.session_factory() as session:
        assert await session.get(AppSetting, cascade_alias._key(server_id)) is None


async def test_alias_auth_and_validation(client, auth_headers):
    server_id = await seed(client, auth_headers)
    url = f"/api/servers/{server_id}"
    assert (await client.patch(url, json={"manual_exit_name": "vpn-exit"})).status_code == 401
    assert (await client.patch(url, headers=auth_headers, json={"manual_exit_name": "x" * 129})).status_code == 422
    async with client.session_factory() as session:
        server = await session.get(Server, server_id)
        server.last_check_info = "{}"
        await session.commit()
    assert (await client.patch(url, headers=auth_headers, json={"manual_exit_name": "vpn-exit"})).status_code == 409


@pytest.mark.parametrize("raw", ["[]", "not-json", '{"name": "old", "endpoint": null}'])
async def test_corrupt_alias_does_not_break_checks(client, auth_headers, raw):
    server_id = await seed(client, auth_headers)
    async with client.session_factory() as session:
        session.add(AppSetting(key=cascade_alias._key(server_id), value=raw))
        await session.commit()
        server = await session.get(Server, server_id)
        result = await cascade_alias.merge(session, server, {"manual_cascade": dict(ROUTE)})
        assert "exit_name" not in result["manual_cascade"]
