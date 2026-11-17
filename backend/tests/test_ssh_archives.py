"""Restore must retain SSH identity and reject unsafe graphs before mutation."""
import io
import json
import os
import tarfile

import asyncssh
import pytest
from sqlalchemy import select

from app import config, ssh_archives
from app.models import Server, SshAccessChange
from app.sshkeys import ensure_jump_key, ensure_panel_key, key_paths


def server(sid, **kwargs):
    return {"id": sid, "name": "test-node", "host": "203.0.113.10", "ssh_user": "acontrol", **kwargs}


@pytest.mark.parametrize("rows", [
    [server(True)], [server(1), server(1)],
    [server(1, ssh_jump_server_id=True)], [server(1, ssh_jump_server_id="2"), server(2)],
    [server(1, ssh_jump_server_id=1)], [server(1, ssh_jump_server_id=9)],
    [server(1, ssh_jump_server_id=2), server(2, ssh_jump_server_id=1)],
    [server(1, ssh_jump_server_id=2), server(2, ssh_jump_server_id=3), server(3)],
    [server(1, ssh_source_mode="invalid")], [server(1, ssh_source_mode=None)],
    [server(1, ssh_source_mode="custom", ssh_source_ips=[])],
    [server(1, ssh_source_mode="custom", ssh_source_ips=["203.0.113.1; id"])],
    [server(1, ssh_source_ips="203.0.113.1")], [server(1, ssh_firewall_mode="disable")],
])
def test_archive_rejects_unsafe_access_graph(rows):
    with pytest.raises(ValueError):
        ssh_archives.validate_servers(rows)


def test_legacy_defaults_and_valid_one_hop_are_preserved():
    rows = [server(1), server(2, ssh_jump_server_id=1, ssh_source_mode="custom", ssh_source_ips=["203.0.113.9/32", "2001:db8::/64"], ssh_firewall_mode="preserve")]
    ssh_archives.validate_servers(rows)
    assert rows[0]["ssh_source_mode"] == "panel"
    assert rows[0]["ssh_firewall_mode"] == "add"
    assert rows[1]["ssh_jump_server_id"] == 1
    assert rows[1]["ssh_source_ips"] == ["203.0.113.9", "2001:db8::/64"]


def archive_with_key(name, payload):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz") as archive:
        item = tarfile.TarInfo("data/ssh/" + name)
        item.size = len(payload)
        item.mode = 0o666
        archive.addfile(item, io.BytesIO(payload))
    return out.getvalue()


def test_private_jump_restore_is_atomic_and_private(tmp_path, monkeypatch):
    original = asyncssh.generate_private_key("ssh-ed25519").export_private_key()
    new = asyncssh.generate_private_key("ssh-ed25519").export_private_key()
    dest = tmp_path / "ssh" / "jump_2"
    dest.parent.mkdir()
    dest.write_bytes(original)
    calls = []
    real_replace = os.replace
    def checked_replace(source, target):
        assert dest.read_bytes() == original
        assert asyncssh.read_private_key(source)
        if os.name != "nt":
            assert os.stat(source).st_mode & 0o777 == 0o600
        calls.append(True)
        return real_replace(source, target)
    monkeypatch.setattr(ssh_archives.os, "replace", checked_replace)
    with tarfile.open(fileobj=io.BytesIO(archive_with_key("jump_2", new))) as archive:
        ssh_archives.restore_file(dest, archive.getmembers()[0], archive, str(tmp_path))
    assert calls == [True] and dest.read_bytes() == new
    assert not list(dest.parent.glob(".restore-key-*"))


async def test_backup_preserves_one_hop_policy_keys_and_retires_preview(client, auth_headers, session_factory):
    settings = config.get_settings()
    ensure_panel_key(settings.data_dir)
    master, _ = key_paths(settings.data_dir)
    async with session_factory() as session:
        jump = Server(name="relay", host="203.0.113.21", ssh_user="acontrol")
        session.add(jump); await session.flush()
        target = Server(name="target", host="203.0.113.22", ssh_user="acontrol", ssh_jump_server_id=jump.id,
                        ssh_source_mode="custom", ssh_source_ips=["203.0.113.21"], ssh_firewall_mode="preserve")
        session.add(target); await session.flush()
        tid = target.id
        await session.commit()
    ensure_jump_key(master, tid)
    host_key = asyncssh.generate_private_key("ssh-ed25519").export_public_key().decode().strip()
    (master.parent / "known_hosts").write_text(f"203.0.113.21 {host_key}\n203.0.113.22 {host_key}\n")
    original = (master.parent / f"jump_{tid}").read_bytes()
    response = await client.post("/api/backup/download", headers=auth_headers, json={"password": "testpass"})
    assert response.status_code == 200, response.text
    with tarfile.open(fileobj=io.BytesIO(response.content)) as archive:
        dump = json.load(archive.extractfile("db.json"))
        assert "ssh_access_changes" not in dump
        assert archive.extractfile(f"data/ssh/jump_{tid}").read() == original
    async with session_factory() as session:
        current = await session.get(Server, tid)
        current.ssh_source_mode = "any"
        current.ssh_jump_server_id = None
        session.add(SshAccessChange(id="a" * 32, server_id=tid, phase="preview", payload={}))
        await session.commit()
    restored = await client.post("/api/backup/restore", headers=auth_headers | {"X-Confirm-Password": "testpass"}, content=response.content)
    assert restored.status_code == 200, restored.text
    async with session_factory() as session:
        current = await session.get(Server, tid)
        assert current.ssh_jump_server_id == jump.id and current.ssh_source_mode == "custom"
        assert current.ssh_source_ips == ["203.0.113.21"] and current.ssh_firewall_mode == "preserve"
        assert await session.scalar(select(SshAccessChange.id)) is None
    assert (master.parent / f"jump_{tid}").read_bytes() == original


@pytest.mark.parametrize("phase", ["applying", "finalizing"])
async def test_backup_refuses_unresolved_ssh_operation(client, auth_headers, session_factory, phase):
    async with session_factory() as session:
        session.add(SshAccessChange(id="b" * 32, server_id=1, phase=phase, payload={}))
        await session.commit()
    response = await client.post("/api/backup/download", headers=auth_headers, json={"password": "testpass"})
    assert response.status_code == 409


@pytest.mark.parametrize("invalid", ["self", "dangling", "bool", "policy", "missing_key"])
async def test_restore_rejects_unsafe_ssh_archive_before_replacement(client, auth_headers, session_factory, invalid):
    settings = config.get_settings()
    ensure_panel_key(settings.data_dir)
    master, _ = key_paths(settings.data_dir)
    key_before = master.read_bytes()
    async with session_factory() as session:
        session.add_all([Server(id=1, name="first", host="203.0.113.31", ssh_user="acontrol"),
                         Server(id=2, name="second", host="203.0.113.32", ssh_user="acontrol")])
        await session.commit()
    response = await client.post("/api/backup/download", headers=auth_headers, json={"password": "testpass"})
    assert response.status_code == 200
    output = io.BytesIO()
    with tarfile.open(fileobj=io.BytesIO(response.content)) as source, tarfile.open(fileobj=output, mode="w:gz") as changed:
        for member in source:
            if not member.isfile():
                continue
            data = source.extractfile(member).read()
            if member.name == "db.json":
                dump = json.loads(data)
                first = next(row for row in dump["servers"] if row["id"] == 1)
                if invalid == "policy":
                    first["ssh_source_mode"] = "invalid"
                else:
                    first["ssh_jump_server_id"] = {"self": 1, "dangling": 99, "bool": True, "missing_key": 2}[invalid]
                data = json.dumps(dump).encode()
            member.size = len(data)
            changed.addfile(member, io.BytesIO(data))
    result = await client.post("/api/backup/restore", headers=auth_headers | {"X-Confirm-Password": "testpass"}, content=output.getvalue())
    assert result.status_code == 400, result.text
    async with session_factory() as session:
        first = await session.get(Server, 1)
        assert first.name == "first" and first.ssh_jump_server_id is None and first.ssh_source_mode == "panel"
    assert master.read_bytes() == key_before


def test_restore_refuses_managed_key_symlink_even_inside_data(tmp_path):
    ssh = tmp_path / "ssh"
    ssh.mkdir()
    public_copy = tmp_path / "public-copy"
    public_copy.write_text("unchanged")
    try:
        (ssh / "jump_2").symlink_to(public_copy)
    except OSError:
        pytest.skip("This host cannot create symlinks; run the regression on the Linux lab")
    with pytest.raises(ValueError, match="символическую"):
        ssh_archives.validate_path(tmp_path.resolve(), "data/ssh/jump_2")
    assert public_copy.read_text() == "unchanged"


@pytest.mark.parametrize("name", ["data/ssh/./id_ed25519", "data/./ssh/jump_2", "data/ssh//id_ed25519", "data/ssh\\jump_2"])
def test_key_archive_aliases_are_rejected_before_writing(tmp_path, name):
    target = tmp_path / "ssh" / "id_ed25519"
    target.parent.mkdir()
    target.write_bytes(b"original")
    with pytest.raises(ValueError):
        ssh_archives.validate_path(tmp_path.resolve(), name)
    assert target.read_bytes() == b"original"
