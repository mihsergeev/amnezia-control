"""Presentation labels must not alter any VPN identity or issued profile."""

from contextlib import asynccontextmanager
import asyncio
import io
import json
import tarfile
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import func, select

from app import awg, client_metadata, expiry, native_snapshots, native_vpn, nodelock, openvpn, protoremove, xray
from app.api import awg as awg_api, awg3, awg_legacy, native_vpn as native_api
from app.api import openvpn as ovpn_api, xray as xray_api
from app.models import AwgConfig, ClientLimit, ClientMetadata, ClientName, NativeVpnConfig, Server

PROTOCOLS = ("awg", "awg3", "awglegacy", "openvpn", "xray", "wireguard", "openvpn-native")


@asynccontextmanager
async def connection(*args):
    yield object()


async def add_server(session_factory):
    async with session_factory() as session:
        server = Server(name="node", host="203.0.113.10")
        session.add(server)
        await session.commit()
        return server.id


@pytest.mark.parametrize("protocol", PROTOCOLS)
async def test_create_list_edit_clear_roundtrip_preserves_identity_and_config(
    client, auth_headers, session_factory, monkeypatch, protocol,
):
    sid = await add_server(session_factory)
    key_field = "public_key" if protocol in ("awg", "awg3", "awglegacy", "wireguard") else "client_id"
    cid = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=" if protocol == "wireguard" else "profile-identity"
    peer = awg.AwgClient(name="phone", public_key=cid, address="192.0.2.2/32")
    old = awg.AwgClient(name="preexisting", public_key="existing", address="192.0.2.1/32")
    created = {key_field: cid, "name": "phone", "creation_date": ""}
    profile = "exact-private-profile"
    state = awg.AwgState(container="amnezia-awg2", interface="awg0", listen_port=51820,
                         server_public_key="server", endpoint="203.0.113.10:51820",
                         address="192.0.2.0/24", clients=[old, peer])
    if protocol.startswith("awg"):
        for module in (awg_api, awg3, awg_legacy):
            monkeypatch.setattr(module, "_connect", connection)
        monkeypatch.setattr(awg, "detect_awg_containers", AsyncMock(return_value={"new": "amnezia-awg2", "legacy": None}))
        monkeypatch.setattr(awg, "read_state", AsyncMock(return_value=state))
        monkeypatch.setattr(awg3, "_state", AsyncMock(return_value=state))
        monkeypatch.setattr(awg_legacy, "_legacy_state", AsyncMock(return_value=state))
        issue = AsyncMock(return_value=(peer, profile))
        monkeypatch.setattr(awg, "create_client", issue)
    elif protocol in ("wireguard", "openvpn-native"):
        monkeypatch.setattr(native_api, "connection", connection)
        monkeypatch.setattr(native_api.deploy, "ensure_idle", AsyncMock())
        issue = AsyncMock(return_value=(created.copy(), profile))
        monkeypatch.setattr(native_vpn, "issue", issue)
        monkeypatch.setattr(native_vpn, "state", AsyncMock(return_value={"clients": [created.copy()]}))
        monkeypatch.setattr(native_vpn, "version", AsyncMock(return_value="test"))
    elif protocol == "openvpn":
        monkeypatch.setattr(ovpn_api, "_connect", connection)
        monkeypatch.setattr(openvpn, "detect_container", AsyncMock(return_value="amnezia-openvpn"))
        issue = AsyncMock(return_value=(SimpleNamespace(**created), profile))
        monkeypatch.setattr(openvpn, "issue_client", issue)
        monkeypatch.setattr(openvpn, "read_clients", AsyncMock(return_value=[SimpleNamespace(**created)]))
        monkeypatch.setattr(openvpn, "read_status_map", AsyncMock(return_value={}))
    else:
        monkeypatch.setattr(xray_api, "_connect", connection)
        monkeypatch.setattr(xray, "detect_container", AsyncMock(return_value="amnezia-xray"))
        issue = AsyncMock(return_value=(SimpleNamespace(**created), [{"key": "vision", "label": "Vision", "amnezia": profile, "uri": "vless://test"}]))
        monkeypatch.setattr(xray, "issue_client", issue)
        monkeypatch.setattr(xray, "read_clients_and_stats", AsyncMock(return_value=([SimpleNamespace(**created)], {}, None)))

    path = f"/api/servers/{sid}/{"awg-legacy" if protocol == "awglegacy" else protocol}"
    response = await client.post(path + "/clients", headers=auth_headers,
                                 json={"name": "phone", "group_name": " Person ", "device_name": " Phone "})
    assert response.status_code == 201, response.text
    issued = response.json()
    assert issued["client"][key_field] == cid
    assert issued["client"]["group_name"] == "Person"
    assert issued["client"]["device_name"] == "Phone"
    assert issued["client"]["expires_at"] is None
    config_path = path + "/config"
    if protocol == "xray":
        # The Xray profile is generated from node state; metadata never writes it.
        monkeypatch.setattr(xray, "read_clients", AsyncMock(return_value=[SimpleNamespace(**created)]))
        monkeypatch.setattr(xray, "build_client_link", AsyncMock(return_value=issued["configs"]))
    config_before = await client.post(config_path, headers=auth_headers, json={key_field: cid})
    assert config_before.status_code == 200, config_before.text
    payload = {"protocol": protocol, "client_id": cid, "group_name": "Person 2", "device_name": "Laptop"}
    for _ in range(2):
        response = await client.post(f"/api/servers/{sid}/client-metadata", headers=auth_headers, json=payload)
        assert response.status_code == 204, response.text
    response = await client.get(path, headers=auth_headers)
    assert response.status_code == 200, response.text
    row = next(c for c in response.json()["clients"] if c[key_field] == cid)
    assert row["group_name"] == "Person 2" and row["device_name"] == "Laptop"
    assert row["expires_at"] is None
    if protocol.startswith("awg"):
        existing = next(c for c in response.json()["clients"] if c[key_field] == "existing")
        assert existing["group_name"] == existing["device_name"] == ""
        assert existing["address"] == old.address
    config_after = await client.post(config_path, headers=auth_headers, json={key_field: cid})
    assert config_after.json() == config_before.json()
    assert issue.await_count == 1
    async with session_factory() as session:
        assert await session.scalar(select(func.count()).select_from(ClientMetadata)) == 1
        assert await session.scalar(select(func.count()).select_from(ClientLimit)) == 0
    payload.update(group_name="", device_name="")
    assert (await client.post(f"/api/servers/{sid}/client-metadata", headers=auth_headers, json=payload)).status_code == 204
    async with session_factory() as session:
        assert await session.scalar(select(func.count()).select_from(ClientMetadata)) == 0


@pytest.mark.parametrize("bad", ["a\nb", "a\x00b", "a\u202eb", "a" * 129])
async def test_metadata_rejects_invalid_labels_before_node_access(client, auth_headers, bad):
    response = await client.post("/api/servers/1/client-metadata", headers=auth_headers,
                                 json={"protocol": "awg", "client_id": "key", "group_name": bad})
    assert response.status_code == 422
    response = await client.post("/api/servers/1/awg/clients", headers=auth_headers,
                                 json={"name": "phone", "device_name": bad})
    assert response.status_code == 422


async def test_metadata_requires_jwt_and_does_not_accept_protocol_aliases(client, auth_headers):
    payload = {"protocol": "awg", "client_id": "key", "group_name": "person"}
    assert (await client.post("/api/servers/1/client-metadata", json=payload)).status_code == 401
    for protocol in ("awg2", "wg", "../awg"):
        response = await client.post("/api/servers/1/client-metadata", headers=auth_headers,
                                     json={**payload, "protocol": protocol})
        assert response.status_code == 422


async def test_metadata_is_protocol_scoped_and_removed_with_client_or_protocol(session_factory):
    async with session_factory() as session:
        for proto in PROTOCOLS:
            await client_metadata.set_labels(session, 1, proto, "same", "Person", proto)
        await session.commit()
        await expiry.cleanup_client_db(session, 1, "wireguard", "same")
        await session.commit()
        assert await client_metadata.labels_map(session, 1, "wireguard") == {}
        assert (await client_metadata.labels_map(session, 1, "awg"))["same"]["device_name"] == "awg"
        await protoremove.cleanup_db(session, 1, {"awg"})
        assert await client_metadata.labels_map(session, 1, "awg") == {}
        assert (await client_metadata.labels_map(session, 1, "xray"))["same"]["group_name"] == "Person"


async def test_native_snapshot_retains_labels_and_reads_older_schema_one(session_factory):
    async with session_factory() as session:
        server = Server(name="node", host="203.0.113.10")
        session.add(server)
        await session.flush()
        await client_metadata.set_labels(session, server.id, "wireguard", "key", "Person", "Phone")
        await native_snapshots.save(session, server, "wireguard", "20261112-120000", {"port": 51820, "transport": "udp"})
        manifest = await native_snapshots.load(session, server, "wireguard", "20261112-120000")
        assert manifest["rows"]["labels"][0]["group_name"] == "Person"
        await client_metadata.set_labels(session, server.id, "wireguard", "key", "Changed", "")
        await native_snapshots.apply(session, server.id, "wireguard", manifest)
        assert (await client_metadata.labels_map(session, server.id, "wireguard"))["key"]["device_name"] == "Phone"
        del manifest["rows"]["labels"]
        await native_snapshots.apply(session, server.id, "wireguard", manifest)
        assert await client_metadata.labels_map(session, server.id, "wireguard") == {}


async def test_transfer_remaps_labels_and_server_delete_cleans_them(client, auth_headers, session_factory):
    sid = await add_server(session_factory)
    async with session_factory() as session:
        await client_metadata.set_labels(session, sid, "awg3", "public-key", "Person", "Phone")
        await session.commit()
    response = await client.get(f"/api/servers/{sid}/export",
                                 headers={**auth_headers, "X-Confirm-Password": "testpass"})
    assert response.status_code == 200
    dump = response.json()
    assert dump["tables"]["client_metadata"] == [{"protocol": "awg3", "client_id": "public-key",
                                                 "group_name": "Person", "device_name": "Phone"}]
    dump["server"]["host"] = "203.0.113.11"
    response = await client.post("/api/servers/import-file", headers=auth_headers, json=dump)
    assert response.status_code == 200, response.text
    new_id = response.json()["server_id"]
    assert new_id != sid
    async with session_factory() as session:
        assert (await client_metadata.labels_map(session, new_id, "awg3"))["public-key"]["device_name"] == "Phone"
        assert (await client_metadata.labels_map(session, sid, "awg3"))["public-key"]["group_name"] == "Person"
    assert (await client.delete(f"/api/servers/{new_id}", headers=auth_headers)).status_code == 200
    async with session_factory() as session:
        assert await client_metadata.labels_map(session, new_id, "awg3") == {}
        assert len(await client_metadata.labels_map(session, sid, "awg3")) == 1


def metadata_archive(dump):
    data = json.dumps(dump).encode()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        info = tarfile.TarInfo("db.json")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


@pytest.mark.parametrize("legacy", [False, True])
async def test_backup_restores_labels_or_clears_them_for_pre_metadata_archive(
    client, auth_headers, session_factory, legacy,
):
    sid = await add_server(session_factory)
    async with session_factory() as session:
        await client_metadata.set_labels(session, sid, "awg", "key", "Archived person", "Phone")
        await session.commit()
    response = await client.post("/api/backup/download", headers=auth_headers,
                                 json={"password": "testpass"})
    assert response.status_code == 200, response.text
    with tarfile.open(fileobj=io.BytesIO(response.content), mode="r:gz") as tar:
        dump = json.loads(tar.extractfile("db.json").read())
    if legacy:
        del dump["client_metadata"]
    async with session_factory() as session:
        await client_metadata.set_labels(session, sid, "awg", "key", "Unrelated live person", "Laptop")
        await session.commit()
    response = await client.post("/api/backup/restore", content=metadata_archive(dump),
                                 headers={**auth_headers, "X-Confirm-Password": "testpass"})
    assert response.status_code == 200, response.text
    async with session_factory() as session:
        labels = await client_metadata.labels_map(session, sid, "awg")
        assert labels == ({} if legacy else {"key": {"group_name": "Archived person", "device_name": "Phone"}})


@pytest.mark.parametrize("invalid", [{"group_name": "a\nb"}, {"device_name": "a" * 129}, {"protocol": "awg2"}])
async def test_backup_rejects_invalid_labels_before_mutating_live_state(
    client, auth_headers, session_factory, invalid,
):
    sid = await add_server(session_factory)
    async with session_factory() as session:
        await client_metadata.set_labels(session, sid, "awg", "key", "Live person", "Phone")
        await session.commit()
    dump = {"servers": [], "client_metadata": [{"server_id": sid, "protocol": "awg", "client_id": "key",
                                               "group_name": "Archived person", "device_name": "", **invalid}]}
    response = await client.post("/api/backup/restore", content=metadata_archive(dump),
                                 headers={**auth_headers, "X-Confirm-Password": "testpass"})
    assert response.status_code == 400, response.text
    async with session_factory() as session:
        assert await session.get(Server, sid) is not None
        assert (await client_metadata.labels_map(session, sid, "awg"))["key"]["group_name"] == "Live person"


@pytest.mark.parametrize("protocol", ["openvpn", "openvpn-native"])
async def test_server_delete_waits_for_protocol_metadata_writer(
    client, auth_headers, session_factory, protocol,
):
    sid = await add_server(session_factory)
    async with nodelock.hold(protocol, sid):
        deletion = asyncio.create_task(client.delete(f"/api/servers/{sid}", headers=auth_headers))
        try:
            with pytest.raises(TimeoutError):
                await asyncio.wait_for(asyncio.shield(deletion), 0.1)
            async with session_factory() as session:
                await client_metadata.set_labels(session, sid, protocol, "key", "Person", "Phone")
                await session.commit()
        except BaseException:
            deletion.cancel()
            await asyncio.gather(deletion, return_exceptions=True)
            raise
    response = await deletion
    assert response.status_code == 200, response.text
    async with session_factory() as session:
        assert await session.get(Server, sid) is None
        assert await client_metadata.labels_map(session, sid, protocol) == {}


@pytest.mark.parametrize("protocol", ["wireguard", "openvpn-native"])
@pytest.mark.parametrize("error,status", [(native_vpn.NativeNotDeployed("not deployed"), 409),
                                          (OSError("synthetic SSH failure"), 502)])
async def test_metadata_native_node_failure_is_mapped_without_writing_labels(
    client, auth_headers, session_factory, monkeypatch, protocol, error, status,
):
    sid = await add_server(session_factory)
    monkeypatch.setattr(native_api, "connection", connection)
    monkeypatch.setattr(native_vpn, "state", AsyncMock(side_effect=error))
    response = await client.post(f"/api/servers/{sid}/client-metadata", headers=auth_headers,
                                 json={"protocol": protocol, "client_id": "external", "group_name": "Person"})
    assert response.status_code == status, response.text
    async with session_factory() as session:
        assert await client_metadata.labels_map(session, sid, protocol) == {}
