"""Invalid archived endpoints must fail before replacing protected records."""
import io
import json
import tarfile

import pytest
from sqlalchemy import event, select

from app.models import AwgConfig, Server
from app.ssh_archives import validate_endpoint


INVALID_ENDPOINTS = [
    {"host": None}, {"host": True}, {"host": ["192.0.2.10"]},
    {"host": ""}, {"host": "node name.example"}, {"host": "node/other"},
    {"ssh_port": None}, {"ssh_port": True}, {"ssh_port": "22"},
    {"ssh_port": 0}, {"ssh_port": 65536}, {"ssh_port": 2147483648},
]


def archive(dump):
    output = io.BytesIO()
    data = json.dumps(dump).encode()
    with tarfile.open(fileobj=output, mode="w:gz") as tar:
        member = tarfile.TarInfo("db.json")
        member.size = len(data)
        tar.addfile(member, io.BytesIO(data))
    return output.getvalue()


@pytest.mark.parametrize("fields", INVALID_ENDPOINTS)
async def test_restore_rejects_invalid_endpoint_before_delete(client, auth_headers, session_factory, fields):
    async with session_factory() as session:
        session.add(Server(id=1, name="original", host="192.0.2.1", ssh_user="acontrol"))
        session.add(AwgConfig(server_id=1, public_key="fixture-client", name="stored-client", config="stored profile"))
        await session.commit()
    writes = []
    engine = session_factory.kw["bind"].sync_engine
    def capture(_conn, _cursor, statement, *_args):
        if statement.lstrip().upper().startswith(("DELETE FROM SERVERS", "DELETE FROM AWG_CONFIGS", "INSERT INTO SERVERS")):
            writes.append(statement)
    event.listen(engine, "before_cursor_execute", capture)
    try:
        response = await client.post("/api/backup/restore", headers=auth_headers | {"X-Confirm-Password": "testpass"}, content=archive({
            "servers": [{"id": 1, "name": "replacement", "host": "192.0.2.2", "ssh_port": 22, "ssh_user": "acontrol", **fields}],
            "awg_configs": [],
        }))
        assert response.status_code == 400
        assert not writes
        async with session_factory() as session:
            assert (await session.get(Server, 1)).name == "original"
            assert await session.scalar(select(AwgConfig.config)) == "stored profile"
    finally:
        event.remove(engine, "before_cursor_execute", capture)


@pytest.mark.parametrize("fields", INVALID_ENDPOINTS)
async def test_transfer_rejects_invalid_host_without_insert(client, auth_headers, session_factory, fields):
    response = await client.post("/api/servers/import-file", headers=auth_headers, content=json.dumps({
        "format": "acontrol-server-export", "format_version": 1,
        "server": {"name": "target", "host": "192.0.2.2", "ssh_user": "acontrol", **fields}, "tables": {},
    }).encode())
    assert response.status_code == 400, response.text
    async with session_factory() as session:
        assert await session.scalar(select(Server.id)) is None


@pytest.mark.parametrize("host", ["192.0.2.10", "2001:db8::10", "node.example", "node.example.", "node", "пример.example", "relay_node.example.test"])
def test_archive_valid_endpoint_retains_original_bytes_and_legacy_default(host):
    row = {"host": host}
    validate_endpoint(row)
    assert row == {"host": host}
    for port in (1, 22, 2221, 65535):
        validate_endpoint({"host": host, "ssh_port": port})


@pytest.mark.parametrize("operation", ["restore", "transfer"])
async def test_archive_roundtrip_preserves_local_alias_and_profile(client, auth_headers, session_factory, operation):
    host = "vpn_node"
    headers = auth_headers | {"X-Confirm-Password": "testpass"}
    created = await client.post("/api/servers", headers=auth_headers, json={"name": "fixture", "host": host})
    assert created.status_code == 201, created.text
    server_id = created.json()["id"]
    async with session_factory() as session:
        session.add(AwgConfig(server_id=server_id, public_key="fixture-client", name="fixture", config="stored profile"))
        await session.commit()

    if operation == "restore":
        exported = await client.post("/api/backup/download", headers=auth_headers, json={"password": "testpass"})
    else:
        exported = await client.get(f"/api/servers/{server_id}/export", headers=headers)
    assert exported.status_code == 200, exported.text

    async with session_factory() as session:
        original = await session.get(Server, server_id)
        original.host = "original.example.test"
        await session.commit()
    if operation == "restore":
        imported = await client.post("/api/backup/restore", headers=headers, content=exported.content)
    else:
        imported = await client.post("/api/servers/import-file", headers=auth_headers, content=exported.content)
    assert imported.status_code == 200, imported.text
    async with session_factory() as session:
        restored = await session.scalar(select(Server).where(Server.host == host))
        assert restored.ssh_port == 22
        assert await session.scalar(select(AwgConfig.config).where(AwgConfig.server_id == restored.id)) == "stored profile"


@pytest.mark.parametrize("fields", INVALID_ENDPOINTS)
async def test_transfer_rejects_invalid_jump_endpoint(client, auth_headers, session_factory, fields):
    response = await client.post("/api/servers/import-file", headers=auth_headers, content=json.dumps({
        "format": "acontrol-server-export", "format_version": 1,
        "server": {"name": "target", "host": "192.0.2.2", "ssh_jump": {"host": "192.0.2.3", "ssh_port": 22, **fields}}, "tables": {},
    }).encode())
    assert response.status_code == 400
    async with session_factory() as session:
        assert await session.scalar(select(Server.id)) is None
