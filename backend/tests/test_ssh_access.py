import os
import shutil
import subprocess
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace

import asyncssh
import pytest
from pydantic import ValidationError
from sqlalchemy import select

from app import config, ssh_access, ssh_policy, sshops
from app.models import Server, SshAccessChange
from app.schemas import ServerCreate, ServerUpdate
from app.sshkeys import ensure_jump_key, ensure_panel_key, jump_username, key_paths


def test_policy_validation_requires_explicit_unrestricted():
    for body in ({"ssh_jump_server_id": True}, {"ssh_jump_server_id": "1"}, {"ssh_source_ips": None}, {"ssh_source_mode": None}, {"ssh_firewall_mode": None}):
        with pytest.raises(ValidationError):
            ServerUpdate.model_validate(body)
    for addresses in (["0.0.0.0/0"], ["::/0"], ["example.com"], ["192.0.2.1; id"]):
        with pytest.raises(ValidationError):
            ServerCreate.model_validate({"name": "test", "host": "192.0.2.1", "ssh_source_mode": "custom", "ssh_source_ips": addresses})
    value = ServerCreate.model_validate({"name": "test", "host": "192.0.2.1", "ssh_source_mode": "custom", "ssh_source_ips": ["2001:db8::1/64", "2001:db8::/64", "192.0.2.1/32"]})
    assert value.ssh_source_ips == ["2001:db8::/64", "192.0.2.1"]
    with pytest.raises(ValueError):
        ssh_policy.sources(Server(ssh_source_mode="panel"), "")


def test_sources_are_per_hop_and_keep_direct_source():
    jump = Server(id=1, host="192.0.2.8", ssh_port=22, ssh_source_mode="custom", ssh_source_ips=["198.51.100.0/24"])
    target = Server(id=2, host="192.0.2.9", ssh_jump_server_id=1, ssh_source_mode="panel")
    target.ssh_jump_server = jump
    assert ssh_policy.sources(target, "203.0.113.8") == ["203.0.113.8", "192.0.2.8"]
    assert ssh_policy.sources(jump, "203.0.113.8") == ["198.51.100.0/24"]


def shell(script, home):
    bash = "C:/Program Files/Git/usr/bin/bash.exe" if os.name == "nt" else shutil.which("bash")
    env = {**os.environ, "HOME": home.as_posix(), "PATH": str(Path(bash).parent) + os.pathsep + os.environ["PATH"]}
    # Do not start real watchdog processes in unit tests. Replay their exact
    # generated body deterministically through operation=watchdog instead.
    return subprocess.run([bash, "-s"], input="nohup() { :; };\n" + script,
                          text=True, capture_output=True, env=env, cwd="C:/" if os.name == "nt" else "/")


def test_atomic_key_updates_preserve_admin_lines_and_stale_watchdogs(tmp_path):
    public = "ssh-ed25519 AAA panel"
    directory = tmp_path / ".ssh"
    directory.mkdir()
    ak = directory / "authorized_keys"
    original = '# admin comment\nssh-ed25519 BBB administrator\nfrom="192.0.2.20",restrict ' + public + '\n'
    ak.write_text(original)
    first, second = "a" * 32, "b" * 32
    assert shell(ssh_access.write_key(public, 'from="192.0.2.10",restrict', transaction=first), tmp_path).returncode == 0
    assert '192.0.2.20' in ak.read_text()  # Add before testing the new route.
    assert shell(ssh_access.write_key(public, 'from="192.0.2.10",restrict', transaction=first, operation="rollback"), tmp_path).returncode == 0
    assert ak.read_text() == original
    assert shell(ssh_access.write_key(public, 'from="192.0.2.11",restrict', transaction=second), tmp_path).returncode == 0
    assert shell(ssh_access.write_key(public, 'from="192.0.2.11",restrict', transaction=second, operation="commit"), tmp_path).returncode == 0
    final = ak.read_text()
    assert '192.0.2.11' in final and '192.0.2.20' not in final
    assert '# admin comment\nssh-ed25519 BBB administrator\n' in final
    shell(ssh_access.write_key(public, 'restrict', transaction=first, operation="watchdog"), tmp_path)
    assert ak.read_text() == final
    # Even an interrupted old operation cannot overwrite a newer generation.
    (directory / f".acontrol-{first}.rolledback").unlink()
    shell(ssh_access.write_key(public, 'restrict', transaction=first, operation="watchdog"), tmp_path)
    assert ak.read_text() == final


def test_bootstrap_upserts_own_key_instead_of_duplicate(tmp_path):
    directory = tmp_path / ".ssh"
    directory.mkdir()
    ak = directory / "authorized_keys"
    ak.write_text('restrict ssh-ed25519 AAA panel\nssh-ed25519 BBB admin\n')
    script = ssh_access.write_key("ssh-ed25519 AAA panel", 'from="192.0.2.1",restrict')
    assert shell(script, tmp_path).returncode == 0
    assert shell(script, tmp_path).returncode == 0
    assert ak.read_text().count("AAA") == 1
    assert "BBB admin" in ak.read_text()


async def test_jump_transport_pins_both_hosts_and_closes_parent_on_failed_auth(tmp_path, monkeypatch):
    key, _ = key_paths(str(tmp_path))
    ensure_panel_key(str(tmp_path))
    ensure_jump_key(key, 8)
    calls = []
    closed = []

    class Conn:
        def __init__(self, label): self.label = label
        def close(self): closed.append(self.label)
        async def wait_closed(self): pass

    parent, target = Conn("jump"), Conn("target")

    async def fake(host, port, username, path, **kwargs):
        calls.append((host, username, path, kwargs))
        return parent if len(calls) == 1 else target

    monkeypatch.setattr(sshops, "_tofu_connect", fake)
    route = sshops.Jump("192.0.2.8", 2222, 8)
    async with sshops.connect("192.0.2.9", 22, "service", key, jump=route) as result:
        assert result is target
    assert calls[0][1] == jump_username(key, 8)
    assert calls[0][3]["require_known"] is True
    assert calls[1][3]["tunnel"] is parent
    assert closed == ["target", "jump"]
    calls.clear(); closed.clear()

    async def denied(host, port, username, path, **kwargs):
        if host == "192.0.2.8": return parent
        raise asyncssh.PermissionDenied("no")

    monkeypatch.setattr(sshops, "_tofu_connect", denied)
    with pytest.raises(asyncssh.PermissionDenied):
        async with sshops.connect("192.0.2.9", 22, "service", key, jump=route): pass
    assert closed == ["jump"]


async def test_jump_graph_deletion_endpoint_guard_and_key_reuse(client, auth_headers):
    async def add(host, **fields):
        return await client.post('/api/servers', json={"name": host, "host": host, **fields}, headers=auth_headers)
    first = (await add("192.0.2.1")).json()
    second_response = await add("192.0.2.2", ssh_jump_server_id=first["id"])
    assert second_response.status_code == 201
    second = second_response.json()
    for endpoint, method, payload in [
        (f'/api/servers/{first["id"]}', 'delete', None),
        (f'/api/servers/{first["id"]}/ssh-access/preview', 'post', {"ssh_jump_server_id": second["id"]}),
        (f'/api/servers/{second["id"]}/ssh-access/preview', 'post', {"ssh_jump_server_id": second["id"]}),
    ]:
        response = await client.request(method, endpoint, **({"json": payload} if payload is not None else {}), headers=auth_headers)
        assert response.status_code == 409, response.text
    repaired = await client.patch(f'/api/servers/{first["id"]}', json={"ssh_port": 2222}, headers=auth_headers)
    assert repaired.status_code == 200 and repaired.json()['last_check_ok'] is None
    assert repaired.json()['id'] == first['id']
    key, _ = key_paths(config.get_settings().data_dir)
    public = ensure_jump_key(key, second["id"])
    assert (await client.delete(f'/api/servers/{second["id"]}', headers=auth_headers)).status_code == 200
    third = (await add("192.0.2.3")).json()
    assert third["id"] == second["id"]
    assert ensure_jump_key(key, third["id"]) != public


async def test_preview_stale_null_and_unresolved_journal_are_fail_closed(client, auth_headers):
    server = (await client.post('/api/servers', json={"name": "test", "host": "192.0.2.1"}, headers=auth_headers)).json()
    sid = server['id']
    assert (await client.patch(f'/api/servers/{sid}', json={"ssh_source_mode": None}, headers=auth_headers)).status_code == 422
    assert (await client.patch(f'/api/servers/{sid}', json={"ssh_source_mode": "any"}, headers=auth_headers)).status_code == 409
    preview = await client.post(f'/api/servers/{sid}/ssh-access/preview', json={"ssh_source_mode": "custom", "ssh_source_ips": ["192.0.2.7"]}, headers=auth_headers)
    assert preview.status_code == 200 and preview.json()['sources'] == ['192.0.2.7']
    await client.patch(f'/api/servers/{sid}', json={"host": "192.0.2.3"}, headers=auth_headers)
    assert (await client.post(f'/api/servers/{sid}/ssh-access/apply', json={"token": preview.json()['token']}, headers=auth_headers)).status_code == 409
    async with client.session_factory() as session:
        session.add(SshAccessChange(id='f'*32, server_id=sid, phase='applying', payload={}))
        await session.commit()
    assert (await client.post(f'/api/servers/{sid}/ssh-access/preview', json={}, headers=auth_headers)).status_code == 409


async def test_failed_second_session_restores_original_policy_and_retry_does_not_mutate(client, auth_headers, monkeypatch):
    node = (await client.post('/api/servers', json={"name": "test", "host": "192.0.2.1", "ssh_firewall_mode": "preserve"}, headers=auth_headers)).json()
    sid = node['id']
    scripts = []
    class Conn:
        async def run(self, command, **kwargs):
            scripts.append(command)
            return SimpleNamespace(exit_status=0, stdout="ACONTROL_KEY_READY ACONTROL_KEY_ROLLEDBACK ACONTROL_KEY_COMMITTED", stderr="")
    @asynccontextmanager
    async def connect(*args, **kwargs): yield Conn()
    async def failed(*args, **kwargs): raise RuntimeError("second connection failed")
    monkeypatch.setattr(ssh_access, 'connection', connect)
    monkeypatch.setattr(ssh_access, 'verify', failed)
    preview = (await client.post(f'/api/servers/{sid}/ssh-access/preview', json={"ssh_source_mode": "custom", "ssh_source_ips": ["192.0.2.7"], "ssh_firewall_mode": "preserve"}, headers=auth_headers)).json()
    response = await client.post(f'/api/servers/{sid}/ssh-access/apply', json={"token": preview['token']}, headers=auth_headers)
    assert response.status_code == 409 and 'откат ключа подтвержден' in response.text
    assert len(scripts) == 2
    assert (await client.get(f'/api/servers/{sid}', headers=auth_headers)).json()['ssh_source_mode'] == 'panel'
    async with client.session_factory() as session:
        assert (await session.get(SshAccessChange, preview['token'])).phase == 'rolledback'
    await client.post(f'/api/servers/{sid}/ssh-access/apply', json={"token": preview['token']}, headers=auth_headers)
    assert len(scripts) == 2


async def test_bootstrap_success_marker_without_key_login_is_failure(client, auth_headers, monkeypatch):
    from app import server_ops
    async def installed(*args, **kwargs): return sshops.BootstrapResult(ok=True)
    async def failed(*args, **kwargs): return sshops.CheckResult(ok=False, error="key rejected")
    monkeypatch.setattr(sshops, 'bootstrap_server', installed)
    monkeypatch.setattr(sshops, 'check_server', failed)
    node = (await client.post('/api/servers', json={"name": "test", "host": "192.0.2.1"}, headers=auth_headers)).json()
    response = await client.post(f'/api/servers/{node["id"]}/bootstrap', json={"password": "fixture"}, headers=auth_headers)
    assert response.status_code == 400 and 'key rejected' in response.text


def test_firewall_ipv6_adds_runtime_and_permanent_without_reload():
    script = sshops._firewall_snippet('2001:db8::/64', 2222, 'sudo -n', strict=True)
    assert 'family=ipv6' in script
    assert '--permanent --add-rich-rule' in script and 'firewall-cmd --add-rich-rule' in script
    assert '--reload' not in script
    assert 'FAILED' in script
