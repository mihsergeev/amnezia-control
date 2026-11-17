"""Inventory IDs and forwarding keys must stay local to their own panel."""
import json

import pytest
from sqlalchemy import delete, select

from app.models import Server, SshAccessChange


async def test_transfer_binds_hop_by_address_never_foreign_id(client, auth_headers, session_factory):
    async with session_factory() as session:
        session.add_all([
            Server(id=1, name="relay", host="203.0.113.41", ssh_port=2221, ssh_user="acontrol"),
            Server(id=2, name="target", host="203.0.113.42", ssh_port=2221, ssh_user="acontrol",
                   ssh_jump_server_id=1, ssh_source_mode="custom", ssh_source_ips=["203.0.113.41"], ssh_firewall_mode="preserve"),
        ])
        await session.commit()
    exported = await client.get("/api/servers/2/export", headers=auth_headers | {"X-Confirm-Password": "testpass"})
    assert exported.status_code == 200, exported.text
    data = exported.json()
    assert "ssh_jump_server_id" not in data["server"]
    assert data["server"]["ssh_jump"]["host"] == "203.0.113.41"
    assert "ssh_access_changes" not in data["tables"]
    async with session_factory() as session:
        await session.execute(delete(Server))
        session.add_all([
            Server(id=1, name="unrelated", host="203.0.113.49", ssh_port=2221, ssh_user="acontrol"),
            Server(id=77, name="local-relay", host="203.0.113.41", ssh_port=2221, ssh_user="acontrol"),
        ])
        await session.commit()
    imported = await client.post("/api/servers/import-file", headers=auth_headers, content=exported.content)
    assert imported.status_code == 200, imported.text
    assert imported.json()["warnings"]
    async with session_factory() as session:
        target = await session.get(Server, imported.json()["server_id"])
        assert target.ssh_jump_server_id == 77
        assert target.ssh_source_mode == "custom" and target.ssh_source_ips == ["203.0.113.41"]
        assert target.ssh_firewall_mode == "preserve"


@pytest.mark.parametrize("fields,status", [
    ({"ssh_jump_server_id": 1}, 400),
    ({"ssh_jump": {"host": "203.0.113.41", "ssh_port": 22}}, 409),
    ({"ssh_jump": {"host": "203.0.113.41", "ssh_port": True}}, 400),
    ({"ssh_source_mode": "custom", "ssh_source_ips": ["203.0.113.4;id"]}, 400),
    ({"ssh_firewall_mode": None}, 400),
])
async def test_bad_transfer_does_not_create_or_rebind_nodes(client, auth_headers, session_factory, fields, status):
    payload = {"format": "acontrol-server-export", "format_version": 1,
               "server": {"host": "203.0.113.42", "name": "target", **fields}, "tables": {}}
    result = await client.post("/api/servers/import-file", headers=auth_headers, content=json.dumps(payload).encode())
    assert result.status_code == status, result.text
    async with session_factory() as session:
        assert await session.scalar(select(Server.id)) is None


async def test_import_cannot_bind_a_jump_with_unresolved_change(client, auth_headers, session_factory):
    async with session_factory() as session:
        session.add(Server(id=1, name="relay", host="203.0.113.41", ssh_user="acontrol"))
        session.add(SshAccessChange(id="c" * 32, server_id=1, phase="applying", payload={}))
        await session.commit()
    payload = {"format": "acontrol-server-export", "format_version": 1,
               "server": {"host": "203.0.113.42", "name": "target", "ssh_jump": {"host": "203.0.113.41", "ssh_port": 22}}, "tables": {}}
    result = await client.post("/api/servers/import-file", headers=auth_headers, content=json.dumps(payload).encode())
    assert result.status_code == 409, result.text
    async with session_factory() as session:
        assert list(await session.scalars(select(Server.id))) == [1]
