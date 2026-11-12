"""Bulk grouping changes presentation metadata without touching VPN profiles."""

import asyncio
from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException
from sqlalchemy import select

from app import client_metadata, native_vpn, nodelock
from app.api import awg, awg3, awg_legacy, native_vpn as native_api, openvpn, xray
from app.models import AuditLog, AwgConfig, ClientMetadata, ClientName, NativeVpnConfig, OvpnConfig, PausedClient, Server

PROTOCOLS = ("awg", "awg3", "awglegacy", "wireguard", "xray", "openvpn", "openvpn-native")
READERS = {"awg": (awg, "get_awg"), "awg3": (awg3, "get_awg3"),
           "awglegacy": (awg_legacy, "get_legacy"), "openvpn": (openvpn, "get_openvpn"),
           "xray": (xray, "get_xray")}


async def prepare(session_factory, protocol, ids=("first", "second", "third")):
    async with session_factory() as session:
        server = Server(name="private node name", host="203.0.113.10")
        session.add(server)
        await session.flush()
        for cid in ids:
            session.add(ClientName(server_id=server.id, protocol=protocol, client_id=cid, name="private name"))
        await client_metadata.set_labels(session, server.id, protocol, ids[0], "Previous person", "Phone")
        if len(ids) > 1:
            await client_metadata.set_labels(session, server.id, protocol, ids[1], "Previous person", "")
        await session.commit()
        return server.id


def node_reader(monkeypatch, protocol, ids=(), error=None):
    if protocol in READERS:
        module, name = READERS[protocol]
        reader = AsyncMock(return_value=SimpleNamespace(clients=[SimpleNamespace(client_id=cid) for cid in ids]),
                           side_effect=error)
        monkeypatch.setattr(module, name, reader)
    else:
        @asynccontextmanager
        async def connection(*args):
            yield object()
        monkeypatch.setattr(native_api, "connection", connection)
        reader = AsyncMock(return_value={"clients": [{"client_id": cid} for cid in ids]}, side_effect=error)
        monkeypatch.setattr(native_vpn, "state", reader)
    return reader


def endpoint(sid):
    return f"/api/servers/{sid}/client-metadata/bulk"


@pytest.mark.parametrize("protocol", PROTOCOLS)
async def test_bulk_group_idempotent_remove_keeps_devices_and_scopes_profiles(
    client, auth_headers, session_factory, monkeypatch, protocol,
):
    sid = await prepare(session_factory, protocol)
    reader = node_reader(monkeypatch, protocol, error=AssertionError("cached clients need no SSH"))
    async with session_factory() as session:
        await client_metadata.set_labels(session, sid, "other", "first", "Unrelated person", "Tablet")
        session.add(AwgConfig(server_id=sid, protocol="awg", public_key="profile", name="vpn name", config="unchanged private config"))
        await session.commit()
    payload = {"protocol": protocol, "client_ids": ["first", "second", "third"], "group_name": " New person "}
    for _ in range(2):
        response = await client.post(endpoint(sid), headers=auth_headers, json=payload)
        assert response.status_code == 204, response.text
    async with session_factory() as session:
        assert await client_metadata.labels_map(session, sid, protocol) == {
            "first": {"group_name": "New person", "device_name": "Phone"},
            "second": {"group_name": "New person", "device_name": ""},
            "third": {"group_name": "New person", "device_name": ""},
        }
        assert (await client_metadata.labels_map(session, sid, "other"))["first"]["device_name"] == "Tablet"
        profile = await session.scalar(select(AwgConfig))
        assert (profile.public_key, profile.name, profile.config) == ("profile", "vpn name", "unchanged private config")
        logs = list(await session.scalars(select(AuditLog).where(AuditLog.action == "clients_bulk_group")))
        assert len(logs) == 2
        assert all(row.target == f"server_id={sid};protocol={protocol}" and row.detail == "count=3" for row in logs)
    response = await client.post(endpoint(sid), headers=auth_headers, json={**payload, "group_name": " "})
    assert response.status_code == 204
    async with session_factory() as session:
        assert await client_metadata.labels_map(session, sid, protocol) == {"first": {"group_name": "", "device_name": "Phone"}}
    reader.assert_not_awaited()


@pytest.mark.parametrize("protocol", PROTOCOLS)
async def test_bulk_resolves_paused_stored_and_external_clients_with_one_node_read(
    client, auth_headers, session_factory, monkeypatch, protocol,
):
    sid = await prepare(session_factory, protocol, ("cached",))
    async with session_factory() as session:
        session.add(PausedClient(server_id=sid, protocol=protocol, client_id="paused", name="Paused", data="{}"))
        if protocol.startswith("awg"):
            stored = AwgConfig(server_id=sid, protocol=protocol, public_key="stored", name="Stored", config="original")
        elif protocol == "openvpn":
            stored = OvpnConfig(server_id=sid, client_id="stored", name="Stored", config_amnezia="original")
        elif protocol in ("wireguard", "openvpn-native"):
            stored = NativeVpnConfig(server_id=sid, protocol=protocol, client_id="stored", name="Stored", config="original")
        else:
            stored = ClientName(server_id=sid, protocol=protocol, client_id="stored", name="Stored")
        session.add(stored)
        await session.commit()
    reader = node_reader(monkeypatch, protocol, ["external-one", "external-two"])
    payload = {"protocol": protocol, "client_ids": ["cached", "paused", "stored", "external-one", "external-two"], "group_name": "Person"}
    response = await client.post(endpoint(sid), headers=auth_headers, json=payload)
    assert response.status_code == 204, response.text
    reader.assert_awaited_once()
    async with session_factory() as session:
        assert set(await client_metadata.labels_map(session, sid, protocol)) == set(payload["client_ids"])


@pytest.mark.parametrize("protocol", PROTOCOLS)
async def test_missing_middle_client_does_not_mutate_any_labels(
    client, auth_headers, session_factory, monkeypatch, protocol,
):
    sid = await prepare(session_factory, protocol)
    reader = node_reader(monkeypatch, protocol)
    response = await client.post(endpoint(sid), headers=auth_headers, json={
        "protocol": protocol, "client_ids": ["first", "missing", "second"], "group_name": "Person"})
    assert response.status_code == 404
    reader.assert_awaited_once()
    async with session_factory() as session:
        assert await client_metadata.labels_map(session, sid, protocol) == {
            "first": {"group_name": "Previous person", "device_name": "Phone"},
            "second": {"group_name": "Previous person", "device_name": ""}}
        assert not list(await session.scalars(select(AuditLog).where(AuditLog.action == "clients_bulk_group")))


@pytest.mark.parametrize("change", [
    {"protocol": "awg2"}, {"client_ids": []}, {"client_ids": ["same", "same"]},
    {"client_ids": [str(i) for i in range(101)]}, {"client_ids": [""]},
    {"client_ids": ["x" * 129]}, {"group_name": "x" * 129}, {"group_name": "a\nb"},
    {"group_name": "a\u202eb"}, {"group_name": None},
])
async def test_bulk_invalid_body_rejected_before_node_access(client, auth_headers, change):
    response = await client.post(endpoint(1), headers=auth_headers, json={
        "protocol": "awg", "client_ids": ["first"], "group_name": "Person", **change})
    assert response.status_code == 422


async def test_bulk_requires_auth_and_existing_server(client, auth_headers):
    payload = {"protocol": "awg", "client_ids": ["first"], "group_name": "Person"}
    assert (await client.post(endpoint(1), json=payload)).status_code == 401
    assert (await client.post(endpoint(1), headers=auth_headers, json=payload)).status_code == 404


async def test_bulk_xray_uuid_aliases_resolve_existing_metadata_and_reject_duplicates(
    client, auth_headers, session_factory, monkeypatch,
):
    cid = "a12b3456-7890-4abc-8def-123456789abc"
    sid = await prepare(session_factory, "xray", (cid,))
    reader = node_reader(monkeypatch, "xray", error=AssertionError("no node read"))
    payload = {"protocol": "xray", "client_ids": ["{" + cid.upper() + "}"], "group_name": "Person"}
    response = await client.post(endpoint(sid), headers=auth_headers, json=payload)
    assert response.status_code == 204, response.text
    async with session_factory() as session:
        assert await client_metadata.labels_map(session, sid, "xray") == {cid: {"group_name": "Person", "device_name": "Phone"}}
    response = await client.post(endpoint(sid), headers=auth_headers, json={**payload, "client_ids": [cid, cid.replace("-", "").upper()]})
    assert response.status_code == 422
    reader.assert_not_awaited()


async def test_bulk_xray_preserves_device_when_cache_and_metadata_use_different_uuid_aliases(
    client, auth_headers, session_factory, monkeypatch,
):
    cid = "a12b3456-7890-4abc-8def-123456789abc"
    sid = await prepare(session_factory, "xray", (cid.upper(),))
    async with session_factory() as session:
        await client_metadata.clear(session, sid, "xray", cid.upper())
        await client_metadata.set_labels(session, sid, "xray", cid, "Previous person", "Laptop")
        await session.commit()
    reader = node_reader(monkeypatch, "xray", error=AssertionError("no node read"))
    payload = {"protocol": "xray", "client_ids": ["{" + cid + "}"], "group_name": "Person"}
    for _ in range(2):
        response = await client.post(endpoint(sid), headers=auth_headers, json=payload)
        assert response.status_code == 204, response.text
    async with session_factory() as session:
        assert await client_metadata.labels_map(session, sid, "xray") == {cid: {"group_name": "Person", "device_name": "Laptop"}}
    reader.assert_not_awaited()
    @asynccontextmanager
    async def connection(*args):
        yield object()
    monkeypatch.setattr(xray, "_connect", connection)
    monkeypatch.setattr(xray.xray, "detect_container", AsyncMock(return_value="amnezia-xray"))
    monkeypatch.setattr(xray.xray, "read_clients_and_stats", AsyncMock(return_value=(
        [SimpleNamespace(client_id=cid.upper(), name="vpn name", creation_date="")], {}, None)))
    listed = await client.get(f"/api/servers/{sid}/xray", headers=auth_headers)
    assert listed.status_code == 200, listed.text
    assert listed.json()["clients"][0]["group_name"] == "Person"
    assert listed.json()["clients"][0]["device_name"] == "Laptop"


async def test_bulk_xray_keeps_visible_device_when_uuid_alias_rows_disagree(
    client, auth_headers, session_factory,
):
    cid = "a12b3456-7890-4abc-8def-123456789abc"
    sid = await prepare(session_factory, "xray", (cid.upper(),))
    async with session_factory() as session:
        await client_metadata.set_labels(session, sid, "xray", cid, "Canonical person", "Hidden device")
        # Direct rows represent metadata saved before UUID aliases were unified.
        session.add(ClientMetadata(server_id=sid, protocol="xray", client_id=cid.upper(),
                                   group_name="Previous person", device_name="Phone"))
        await session.commit()
        visible = [{"client_id": cid.upper()}]
        await client_metadata.enrich(session, sid, "xray", visible)
        assert visible[0]["device_name"] == "Phone"
    response = await client.post(endpoint(sid), headers=auth_headers, json={
        "protocol": "xray", "client_ids": [cid.upper()], "group_name": "Person"})
    assert response.status_code == 204, response.text
    async with session_factory() as session:
        visible = [{"client_id": cid.upper()}]
        await client_metadata.enrich(session, sid, "xray", visible)
        assert visible[0]["device_name"] == "Phone"
        assert await client_metadata.labels_map(session, sid, "xray") == {cid: {"group_name": "Person", "device_name": "Phone"}}


@pytest.mark.parametrize("action", ["revoke", "reissue"])
async def test_bulk_xray_uuid_alias_metadata_follows_revoke_and_reissue(
    client, auth_headers, session_factory, monkeypatch, action,
):
    cid = "a12b3456-7890-4abc-8def-123456789abc"
    raw_id = cid.upper()
    new_id = "b12b3456-7890-4abc-8def-123456789abc"
    sid = await prepare(session_factory, "xray", (raw_id,))
    response = await client.post(endpoint(sid), headers=auth_headers, json={
        "protocol": "xray", "client_ids": [raw_id], "group_name": "Person"})
    assert response.status_code == 204, response.text
    async with session_factory() as session:
        assert await client_metadata.labels_map(session, sid, "xray") == {cid: {"group_name": "Person", "device_name": "Phone"}}
        if action == "revoke":
            # Older single-client edits can leave another spelling behind.
            session.add(ClientMetadata(server_id=sid, protocol="xray", client_id="{" + cid + "}",
                                       group_name="Person", device_name="Phone"))
            await session.commit()

    @asynccontextmanager
    async def connection(*args):
        yield object()

    monkeypatch.setattr(xray, "_connect", connection)
    monkeypatch.setattr(xray.xray, "detect_container", AsyncMock(return_value="amnezia-xray"))
    monkeypatch.setattr(xray.xray, "read_clients", AsyncMock(return_value=[
        SimpleNamespace(client_id=raw_id, name="vpn name", creation_date="")]))
    revoke = AsyncMock()
    monkeypatch.setattr(xray.xray, "revoke_client", revoke)
    issue = AsyncMock(return_value=(
        SimpleNamespace(client_id=new_id, name="vpn name", creation_date=""),
        [{"key": "vision", "label": "Vision", "amnezia": "synthetic profile", "uri": "vless://synthetic"}]))
    monkeypatch.setattr(xray.xray, "issue_client", issue)
    response = await client.post(f"/api/servers/{sid}/xray/{action}", headers=auth_headers,
                                 json={"client_id": raw_id})
    assert response.status_code == (201 if action == "reissue" else 204), response.text
    revoke.assert_awaited_once()
    assert revoke.await_args.args[-1] == raw_id
    async with session_factory() as session:
        labels = await client_metadata.labels_map(session, sid, "xray")
        if action == "reissue":
            assert labels == {new_id: {"group_name": "Person", "device_name": "Phone"}}
            assert response.json()["client"]["group_name"] == "Person"
            assert response.json()["client"]["device_name"] == "Phone"
            issue.assert_awaited_once()
        else:
            assert labels == {}
            issue.assert_not_awaited()


async def test_xray_metadata_move_prefers_exact_visible_label_and_clears_all_old_aliases(session_factory):
    cid = "a12b3456-7890-4abc-8def-123456789abc"
    new_id = "b12b3456-7890-4abc-8def-123456789abc"
    async with session_factory() as session:
        session.add_all([
            ClientMetadata(server_id=1, protocol="xray", client_id=cid, group_name="Canonical person", device_name="Canonical device"),
            ClientMetadata(server_id=1, protocol="xray", client_id=cid.upper(), group_name="Visible person", device_name="Visible device"),
            ClientMetadata(server_id=1, protocol="xray", client_id="{" + cid + "}", group_name="Alias person", device_name="Alias device"),
        ])
        await client_metadata.set_labels(session, 1, "awg", cid, "Other protocol", "Tablet")
        await client_metadata.move(session, 1, "xray", cid.upper(), new_id)
        assert await client_metadata.labels_map(session, 1, "xray") == {
            new_id: {"group_name": "Visible person", "device_name": "Visible device"}}
        assert (await client_metadata.labels_map(session, 1, "awg"))[cid]["device_name"] == "Tablet"


async def test_bulk_xray_single_edit_and_clear_accept_raw_uuid_alias_after_grouping(
    client, auth_headers, session_factory, monkeypatch,
):
    cid = "a12b3456-7890-4abc-8def-123456789abc"
    raw_id = cid.upper()
    sid = await prepare(session_factory, "xray", (raw_id,))
    response = await client.post(endpoint(sid), headers=auth_headers, json={
        "protocol": "xray", "client_ids": [raw_id], "group_name": "Person"})
    assert response.status_code == 204, response.text

    @asynccontextmanager
    async def connection(*args):
        yield object()

    monkeypatch.setattr(xray, "_connect", connection)
    monkeypatch.setattr(xray.xray, "detect_container", AsyncMock(return_value="amnezia-xray"))
    monkeypatch.setattr(xray.xray, "read_clients_and_stats", AsyncMock(return_value=(
        [SimpleNamespace(client_id=raw_id, name="vpn name", creation_date="")], {}, None)))
    for group, device in [("Edited person", "Laptop"), ("", "")]:
        async with session_factory() as session:
            session.add(ClientMetadata(server_id=sid, protocol="xray", client_id="{" + cid + "}",
                                       group_name="Old alias", device_name="Old device"))
            await session.commit()
        response = await client.post(f"/api/servers/{sid}/client-metadata", headers=auth_headers,
                                     json={"protocol": "xray", "client_id": raw_id,
                                           "group_name": group, "device_name": device})
        assert response.status_code == 204, response.text
        listed = await client.get(f"/api/servers/{sid}/xray", headers=auth_headers)
        assert listed.status_code == 200, listed.text
        assert listed.json()["clients"][0]["group_name"] == group
        assert listed.json()["clients"][0]["device_name"] == device
        async with session_factory() as session:
            assert await client_metadata.labels_map(session, sid, "xray") == (
                {cid: {"group_name": group, "device_name": device}} if group or device else {})


@pytest.mark.parametrize("protocol", PROTOCOLS)
async def test_bulk_node_failure_has_no_partial_writes_or_sensitive_error(
    client, auth_headers, session_factory, monkeypatch, protocol, caplog,
):
    sid = await prepare(session_factory, protocol)
    secret = "synthetic-private-config-token"
    reader = node_reader(monkeypatch, protocol, error=HTTPException(502, secret))
    response = await client.post(endpoint(sid), headers=auth_headers, json={
        "protocol": protocol, "client_ids": ["first", "external"], "group_name": "Private person"})
    assert response.status_code == 502
    assert secret not in response.text and secret not in caplog.text and "Private person" not in caplog.text
    reader.assert_awaited_once()
    async with session_factory() as session:
        assert (await client_metadata.labels_map(session, sid, protocol))["first"]["group_name"] == "Previous person"


async def test_bulk_rolls_back_if_database_flush_fails_after_partial_change(
    client, auth_headers, session_factory, monkeypatch,
):
    sid = await prepare(session_factory, "awg")
    original = client_metadata.set_group

    async def failing_group(session, server_id, protocol, ids, group):
        await original(session, server_id, protocol, ids[:1], group)
        raise HTTPException(503, "synthetic database failure")

    monkeypatch.setattr(client_metadata, "set_group", failing_group)
    response = await client.post(endpoint(sid), headers=auth_headers, json={
        "protocol": "awg", "client_ids": ["first", "second"], "group_name": "Person"})
    assert response.status_code == 503
    async with session_factory() as session:
        assert {row["group_name"] for row in (await client_metadata.labels_map(session, sid, "awg")).values()} == {"Previous person"}


async def test_bulk_waits_for_shared_awg_node_lock(client, auth_headers, session_factory):
    sid = await prepare(session_factory, "awg3")
    async with nodelock.hold("awg", sid):
        request = asyncio.create_task(client.post(endpoint(sid), headers=auth_headers, json={
            "protocol": "awg3", "client_ids": ["first", "second"], "group_name": "Person"}))
        try:
            with pytest.raises(TimeoutError):
                await asyncio.wait_for(asyncio.shield(request), 0.1)
            async with session_factory() as session:
                assert (await client_metadata.labels_map(session, sid, "awg3"))["first"]["group_name"] == "Previous person"
        except BaseException:
            request.cancel()
            await asyncio.gather(request, return_exceptions=True)
            raise
    assert (await request).status_code == 204
