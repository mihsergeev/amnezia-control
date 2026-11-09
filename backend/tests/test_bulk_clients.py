import asyncio
import base64
import io
import json
import socket
import struct
import tarfile
import uuid
import zipfile
from contextlib import asynccontextmanager

from sqlalchemy import select

from app import awg, bulk_archive, bulk_issue_state, pausestore, wg_bulk
from app.api import bulk_clients
from app.models import AuditLog, BulkClientIssue, NativeVpnConfig, Server


async def _server(client, auth):
    response = await client.post("/api/servers", headers=auth, json={
        "host": "192.0.2.5", "name": "VPN test", "ssh_port": 22,
    })
    assert response.status_code == 201
    return response.json()["id"]


async def test_issue_resume_cancel_and_replay(client, auth_headers, session_factory, monkeypatch):
    sid = await _server(client, auth_headers)
    url = f"/api/servers/{sid}/bulk-clients/wireguard"
    base = {"request_id": str(uuid.uuid4()), "prefix": "Lab", "count": 2, "confirmed": True}
    keys = [awg.generate_keypair()[1] for _ in range(2)]
    planned = [{"client_id": key, "name": f"Lab-{i:03}", "ip": f"10.2.0.{i + 1}", "config": f"test{i}"}
               for i, key in enumerate(keys, 1)]
    plans = []
    applied = []
    revoked = []

    @asynccontextmanager
    async def connection(*args, **kwargs):
        yield object()

    async def read(*args):
        return object()

    async def plan(conn, node, paused, names, dns, native=False):
        assert names == ["Lab-001", "Lab-002"] and native
        plans.append(names)
        return planned

    async def apply(conn, state, paused, items):
        applied.append([item["client_id"] for item in items])
        if len(applied) == 1:
            raise OSError("synthetic response loss")

    async def revoke(conn, state, ids):
        revoked.extend(ids)
        if len(revoked) == 1:
            raise OSError("synthetic revoke response loss")

    monkeypatch.setattr(bulk_clients, "_connection", connection)
    monkeypatch.setattr(bulk_clients, "_wg_state", read)
    monkeypatch.setattr(wg_bulk, "read", read)
    monkeypatch.setattr(wg_bulk, "plan", plan)
    monkeypatch.setattr(wg_bulk, "apply", apply)
    monkeypatch.setattr(wg_bulk, "revoke", revoke)

    assert (await client.post(url + "/issue", json=base)).status_code == 401
    assert (await client.post(url + "/issue", headers=auth_headers,
                              json=base | {"confirmed": False})).status_code == 422
    first = await client.post(url + "/issue", headers=auth_headers, json=base)
    assert first.status_code == 502
    assert "synthetic response loss" not in first.text
    pending = await client.get(url + "/issue/pending", headers=auth_headers)
    assert pending.json() == {**{key: base[key] for key in ("request_id", "prefix", "count")}, "client_ids": keys}
    assert pending.headers["cache-control"] == "no-store"
    async with session_factory() as session:
        assert await pausestore.paused_ips(session, sid, "wireguard") == {"10.2.0.2", "10.2.0.3"}
        assert not list(await session.scalars(select(NativeVpnConfig)))
    conflict = await client.post(url + "/issue", headers=auth_headers,
                                 json=base | {"request_id": str(uuid.uuid4())})
    assert conflict.status_code == 409

    revoke_body = {"client_ids": [keys[0]], "confirmed": True}
    unknown = await client.post(url + "/revoke", headers=auth_headers, json=revoke_body)
    assert unknown.json()["failed"] == 1
    # A response lost after removing the peer must not let a concurrent issue
    # retry resurrect it before the operator confirms the same revoke.
    assert (await client.post(url + "/issue", headers=auth_headers, json=base)).status_code == 409
    removed = await client.post(url + "/revoke", headers=auth_headers, json=revoke_body)
    assert removed.json()["revoked"] == 1
    assert revoked == [keys[0], keys[0]]

    second = await client.post(url + "/issue", headers=auth_headers, json=base)
    assert second.status_code == 200, second.text
    assert second.json() == {"items": [{"client_id": keys[1], "name": "Lab-002"}], "cancelled": 1}
    assert (await client.post(url + "/issue", headers=auth_headers, json=base)).json() == second.json()
    assert (await client.post(url + "/issue", headers=auth_headers,
                              json=base | {"count": 3})).status_code == 409
    assert applied == [keys, [keys[1]]]
    assert len(plans) == 1
    assert (await client.get(url + "/issue/pending", headers=auth_headers)).json() is None
    async with session_factory() as session:
        assert not await pausestore.paused_ips(session, sid, "wireguard")
        issued = await session.scalar(select(BulkClientIssue))
        assert issued.complete and all("config" not in item for item in issued.items)
        saved = list(await session.scalars(select(NativeVpnConfig)))
        assert [row.client_id for row in saved] == [keys[1]]
        assert len(list(await session.scalars(select(AuditLog).where(
            AuditLog.action == "clients_bulk_issue")))) == 1


async def test_saved_wireguard_archive_uses_exact_config_and_safe_names(client, auth_headers, session_factory):
    sid = await _server(client, auth_headers)
    private, cid = awg.generate_keypair()
    _, peer = awg.generate_keypair()
    config = f"[Interface]\r\nPrivateKey = {private}\r\n[Peer]\r\nPublicKey = {peer}\r\nEndpoint = saved.example:1111\r\n"
    async with session_factory() as session:
        session.add(NativeVpnConfig(server_id=sid, protocol="wireguard",
                                    client_id=cid, name="../../trick", config=config))
        await session.commit()
    response = await client.post(f"/api/servers/{sid}/bulk-clients/wireguard/export", headers=auth_headers,
                                 json={"client_ids": [cid, "unavailable", cid]})
    assert response.status_code == 200
    assert response.headers["x-bulk-exported"] == "1" and response.headers["x-bulk-missing"] == "1"
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["content-disposition"].startswith("attachment")
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        assert archive.testzip() is None
        assert archive.read("0001-trick/client.conf").decode() == config
        assert archive.read("0001-trick/wireguard-qr.png").startswith(b"\x89PNG")
        assert json.loads(archive.read("manifest.json"))["items"][1] == {
            "client_id": "unavailable", "status": "profile_missing",
        }
        assert all(".." not in path and "\\" not in path for path in archive.namelist())


async def test_wireguard_zip_rejects_unresolved_client_endpoint(client, auth_headers, session_factory, monkeypatch):
    sid = await _server(client, auth_headers)
    async with session_factory() as session:
        server = await session.get(Server, sid)
        server.client_endpoint = "missing.example"
        await session.commit()

    async def nxdomain(host, *args, **kwargs):
        assert host == "missing.example"
        raise socket.gaierror(socket.EAI_NONAME)

    monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", nxdomain)
    response = await client.post(f"/api/servers/{sid}/bulk-clients/wireguard/export",
                                 headers=auth_headers, json={"client_ids": ["peer"]})
    assert response.status_code == 422
    assert "DNS" in response.json()["detail"]


async def test_restore_never_replays_archived_pending_issue(client, auth_headers, session_factory):
    sid = await _server(client, auth_headers)
    request_id = str(uuid.uuid4())
    archived = {"request_id": request_id, "server_id": sid, "owner_id": 1, "protocol": "xray",
                "prefix": "Lab", "count": 1, "complete": False,
                "items": [{"client_id": str(uuid.uuid4()), "name": "Lab-001"}]}
    data = json.dumps({"bulk_client_issues": [archived]}).encode()
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w:gz") as tar:
        entry = tarfile.TarInfo("db.json")
        entry.size = len(data)
        tar.addfile(entry, io.BytesIO(data))

    async with session_factory() as session:
        session.add(BulkClientIssue(**archived))
        await session.commit()

    downloaded = await client.post("/api/backup/download", headers=auth_headers, json={"password": "testpass"})
    assert downloaded.status_code == 200
    with tarfile.open(fileobj=io.BytesIO(downloaded.content)) as tar:
        saved = json.load(tar.extractfile("db.json"))["bulk_client_issues"]
        assert len(saved) == 1 and saved[0]["complete"] and saved[0]["items"] == []

    async def restore():
        return await client.post("/api/backup/restore", content=archive.getvalue(),
                                 headers=auth_headers | {"X-Confirm-Password": "testpass"})

    assert (await restore()).status_code == 409
    async with session_factory() as session:
        await bulk_issue_state.request_cancel(session, sid, "xray", [archived["items"][0]["client_id"].upper()])
        operation = await session.get(BulkClientIssue, request_id)
        assert operation.items[0]["revoke_pending"]
        await bulk_issue_state.cancel_clients(session, sid, "xray", [archived["items"][0]["client_id"].upper()])
        assert operation.complete and operation.items[0]["cancelled"]
        await session.commit()

    result = await restore()
    assert result.status_code == 200, result.text
    auth_headers = {"Authorization": f"Bearer {result.json()['access_token']}"}
    response = await client.post(f"/api/servers/{sid}/bulk-clients/xray/issue", headers=auth_headers,
                                 json={"request_id": request_id, "prefix": "Lab", "count": 1, "confirmed": True})
    assert response.status_code == 409
    assert "восстановления" in response.json()["detail"]
    async with session_factory() as session:
        operation = await session.get(BulkClientIssue, request_id)
        assert operation.complete and operation.items == []


def test_amnezia_qr_frames_use_app_import_wire_format():
    source = b"t" * 900
    link = "vpn://" + base64.urlsafe_b64encode(source).decode().rstrip("=")
    frames = bulk_archive.amnezia_frames(link)
    contents = [base64.urlsafe_b64decode(frame + b"=" * (-len(frame) % 4)) for frame in frames]
    assert [struct.unpack(">HBBI", data[:8]) for data in contents] == [
        (1984, 2, 0, 850), (1984, 2, 1, 50),
    ]
    assert b"".join(data[8:] for data in contents) == source
