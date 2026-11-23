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
    # Git Bash has no kernel flock; VM tests cover process-death locking.
    fixture = "nohup() { :; };\n" + ("flock() { :; };\n" if os.name == 'nt' else '')
    return subprocess.run([bash, "-s"], input=fixture + script,
                          text=True, capture_output=True, env=env, cwd="C:/" if os.name == "nt" else "/")


@pytest.mark.skipif(os.name == 'nt', reason='Kernel flock process-death proof requires Linux; also exercised on a test VM')
def test_key_lock_is_released_after_sigkill(tmp_path):
    directory = tmp_path / '.ssh'; directory.mkdir()
    process = subprocess.Popen(['bash', '-c', 'exec 9>"$HOME/.ssh/.acontrol-key.lock"; flock 9; echo READY; exec sleep 60'],
                               env={**os.environ, 'HOME': str(tmp_path)}, stdout=subprocess.PIPE, text=True)
    try:
        assert process.stdout.readline().strip() == 'READY'
        process.kill(); process.wait(timeout=5)
        result = shell(ssh_access.write_key('ssh-ed25519 AAA panel', 'restrict'), tmp_path)
        assert result.returncode == 0, result.stderr
    finally:
        if process.poll() is None: process.kill(); process.wait(timeout=5)


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
    assert shell(ssh_access.write_key(public, 'restrict', transaction=first, operation="watchdog"), tmp_path).returncode != 0
    assert shell(ssh_access.write_key(public, 'restrict', transaction=first, operation="rollback"), tmp_path).returncode != 0
    assert ak.read_text() == final
    # Even an interrupted old operation cannot overwrite a newer generation.
    (directory / f".acontrol-{first}.rolledback").unlink()
    shell(ssh_access.write_key(public, 'restrict', transaction=first, operation="watchdog"), tmp_path)
    assert ak.read_text() == final


def test_rollback_of_a_stage_that_never_ran_closes_without_changes(tmp_path):
    public = "ssh-ed25519 AAA panel"
    directory = tmp_path / ".ssh"
    directory.mkdir()
    ak = directory / "authorized_keys"
    original = 'ssh-ed25519 BBB administrator\nfrom="192.0.2.20",restrict ' + public + '\n'
    ak.write_text(original)
    # Another generation is current; this one stopped before its backup.
    other, lost = "d" * 32, "e" * 32
    assert shell(ssh_access.write_key(public, 'from="192.0.2.10",restrict', transaction=other), tmp_path).returncode == 0
    staged = ak.read_text()
    result = shell(ssh_access.write_key(public, 'from="192.0.2.11",restrict', transaction=lost, operation="rollback"), tmp_path)
    assert result.returncode == 0, result.stderr
    assert "ACONTROL_KEY_ROLLEDBACK" in result.stdout
    assert ak.read_text() == staged
    assert not (directory / f".acontrol-{lost}.rolledback").exists()
    # Without any panel state at all, even an unsafe layout cannot block closing.
    bare = tmp_path / "bare"
    (bare / ".ssh").mkdir(parents=True)
    (bare / ".ssh" / "authorized_keys").write_text(original)
    (bare / ".ssh" / ".acontrol-key.lock").mkdir()
    result = shell(ssh_access.write_key(public, 'restrict', transaction=lost, operation="rollback"), bare)
    assert result.returncode == 0 and "ACONTROL_KEY_ROLLEDBACK" in result.stdout, result.stderr
    assert (bare / ".ssh" / "authorized_keys").read_text() == original


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


def test_retire_key_removes_only_own_identity_and_preserves_foreign_comments(tmp_path):
    directory = tmp_path / '.ssh'; directory.mkdir()
    ak = directory / 'authorized_keys'
    foreign = 'command="echo with spaces" ssh-ed25519 BBB admin mentions AAA'
    ak.write_text('from="192.0.2.1",restrict ssh-ed25519 AAA panel\n' + foreign)
    result = shell(ssh_access.write_key('ssh-ed25519 AAA panel', 'restrict', operation='revoke'), tmp_path)
    assert result.returncode == 0, result.stderr
    assert ak.read_text() == foreign + '\n'


@pytest.mark.parametrize('failure', ['', 'owner-conflict', 'offline'])
async def test_retire_role_is_owned_and_best_effort(tmp_path, monkeypatch, failure):
    key, _ = key_paths(str(tmp_path)); ensure_panel_key(str(tmp_path)); ensure_jump_key(key, 2)
    jump = Server(id=1, host='192.0.2.1', ssh_port=22, ssh_user='service')
    target = Server(id=2, host='192.0.2.2', ssh_jump_server_id=1); target.ssh_jump_server = jump
    settings = SimpleNamespace(data_dir=str(tmp_path), ssh_connect_timeout=1)
    class Conn:
        async def run(self, command, **kwargs):
            assert "$(cat \"$STATE_DIR/owner\")" in command
            assert 'sshd-sha' in command and 'sha256sum' in command
            return SimpleNamespace(exit_status=1 if failure else 0, stdout='' if failure else 'ACONTROL_JUMP_REVOKED', stderr=failure)
    @asynccontextmanager
    async def connect(*args, **kwargs):
        if failure == 'offline': raise OSError('offline')
        yield Conn()
    monkeypatch.setattr(sshops, 'connect', connect)
    warning = await ssh_access.retire_jump(target, settings)
    assert bool(warning) == bool(failure)
    if failure: assert 'не отозван' in warning and failure in warning
    assert (key.parent / 'jump_2').exists()  # Metadata/delete caller decides disposal.


@pytest.mark.parametrize('operation', ['commit', 'rollback'])
def test_staged_key_preserves_unterminated_admin_key_and_key_blob_in_comments(tmp_path, operation):
    directory = tmp_path / '.ssh'; directory.mkdir()
    ak = directory / 'authorized_keys'
    foreign = 'command="printf with spaces",restrict ssh-ed25519 BBB administrator mentions ssh-ed25519 AAA'
    ak.write_text('restrict ssh-ed25519 AAA panel\n' + foreign)
    token = 'c' * 32
    assert shell(ssh_access.write_key('ssh-ed25519 AAA panel', 'from="192.0.2.1",restrict', transaction=token), tmp_path).returncode == 0
    result = shell(ssh_access.write_key('ssh-ed25519 AAA panel', 'from="192.0.2.1",restrict', transaction=token, operation=operation), tmp_path)
    assert result.returncode == 0, result.stderr
    assert foreign in ak.read_text().splitlines()


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


@pytest.mark.parametrize('observed', ['198.51.100.9', '2001:db8::9'])
async def test_forwarding_identity_uses_observed_source_even_when_management_is_unrestricted(tmp_path, monkeypatch, observed):
    ensure_panel_key(str(tmp_path))
    settings = SimpleNamespace(data_dir=str(tmp_path), panel_ip='203.0.113.7', ssh_connect_timeout=10)
    jump = Server(id=1, host='192.0.2.1', ssh_port=22, ssh_user='service', ssh_source_mode='any')
    target = Server(id=2, host='192.0.2.2', ssh_port=2222, ssh_user='service', ssh_jump_server_id=1)
    target.ssh_jump_server = jump
    commands = []
    class Conn:
        async def run(self, command, **kwargs):
            commands.append(command)
            return SimpleNamespace(exit_status=0, stdout=observed if len(commands) == 1 else 'ACONTROL_JUMP_READY', stderr='')
    @asynccontextmanager
    async def connect(*args, **kwargs): yield Conn()
    monkeypatch.setattr(sshops, 'connect', connect)
    await ssh_access.prepare_jump(None, target, settings)
    assert f'from="{observed}"' in commands[1]
    assert 'from="203.0.113.7"' not in commands[1]
    assert 'AllowTcpForwarding local' in commands[1]
    assert 'AllowStreamLocalForwarding no' in commands[1]
    assert 'PermitListen none' in commands[1]


async def test_not_prepared_jump_is_an_offline_check_not_an_api_failure(tmp_path):
    ensure_panel_key(str(tmp_path))
    key, _ = key_paths(str(tmp_path))
    result = await sshops.check_server('192.0.2.2', 22, 'service', key, jump=sshops.Jump('192.0.2.1', 22, 2))
    assert result.ok is False and 'подготовьте' in result.error.lower()


async def test_bootstrap_nonzero_exit_with_success_text_never_succeeds(tmp_path, monkeypatch):
    key, _ = key_paths(str(tmp_path)); public = ensure_panel_key(str(tmp_path))
    class Conn:
        async def run(self, *args, **kwargs): return SimpleNamespace(exit_status=1, stdout='ACONTROL SETUP OK', stderr='failed')
    @asynccontextmanager
    async def connect(*args, **kwargs): yield Conn()
    monkeypatch.setattr(sshops, 'connect', connect)
    result = await sshops.bootstrap_server('192.0.2.1', 22, 'service', 'fixture', public, '192.0.2.7', key_path=key, trust_first_key=True)
    assert result.ok is False


@pytest.mark.parametrize('failure', ['source', 'key'])
async def test_bootstrap_second_session_failure_rolls_back_and_does_not_blame_password(tmp_path, monkeypatch, failure):
    key, _ = key_paths(str(tmp_path)); public = ensure_panel_key(str(tmp_path))
    commands=[]
    class Conn:
        async def run(self, command, **kwargs):
            commands.append(command)
            return SimpleNamespace(exit_status=0, stdout='ACONTROL SETUP OK' if len(commands) == 1 else 'ACONTROL_KEY_ROLLEDBACK', stderr='')
    class Check:
        async def run(self, *args, **kwargs): return SimpleNamespace(stdout='SOURCE=192.0.2.8')
    @asynccontextmanager
    async def connect(*args, **kwargs):
        if 'password' in kwargs: yield Conn()
        elif failure == 'key': raise asyncssh.PermissionDenied('fixture')
        else: yield Check()
    monkeypatch.setattr(sshops, 'connect', connect)
    result = await sshops.bootstrap_server('192.0.2.1', 22, 'service', 'fixture', public, '192.0.2.7', key_path=key, trust_first_key=True)
    assert result.ok is False and 'Неверный пароль' not in result.error
    assert len(commands)==2 and 'ACONTROL_KEY_ROLLEDBACK' in commands[1]


async def test_jump_graph_deletion_endpoint_guard_and_key_reuse(client, auth_headers, monkeypatch):
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
    async def retire(node, settings):
        assert ensure_jump_key(key, node.id) == public  # Before local key deletion.
        return 'Старый промежуточный доступ не отозван: offline'
    monkeypatch.setattr(ssh_access, 'retire_jump', retire)
    deleted = await client.delete(f'/api/servers/{second["id"]}', headers=auth_headers)
    assert deleted.status_code == 200 and 'не отозван' in deleted.json()['message']
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


async def test_failed_stage_is_rolled_back_at_once(client, auth_headers, monkeypatch):
    node = (await client.post('/api/servers', json={"name": "test", "host": "192.0.2.1", "ssh_firewall_mode": "preserve"}, headers=auth_headers)).json()
    sid = node['id']
    scripts = []
    class Conn:
        async def run(self, command, **kwargs):
            scripts.append(command)
            if 'ACONTROL_KEY_READY' in command:
                return SimpleNamespace(exit_status=1, stdout='', stderr='Требуется flock для безопасного изменения SSH')
            return SimpleNamespace(exit_status=0, stdout='ACONTROL_KEY_ROLLEDBACK', stderr='')
    @asynccontextmanager
    async def connect(*args, **kwargs): yield Conn()
    monkeypatch.setattr(ssh_access, 'connection', connect)
    preview = (await client.post(f'/api/servers/{sid}/ssh-access/preview', json={"ssh_source_mode": "custom", "ssh_source_ips": ["192.0.2.7"], "ssh_firewall_mode": "preserve"}, headers=auth_headers)).json()
    response = await client.post(f'/api/servers/{sid}/ssh-access/apply', json={"token": preview['token']}, headers=auth_headers)
    assert response.status_code == 409 and 'откат ключа подтвержден' in response.text
    assert len(scripts) == 2 and 'ACONTROL_KEY_ROLLEDBACK' in scripts[1]
    async with client.session_factory() as session:
        assert (await session.get(SshAccessChange, preview['token'])).phase == 'rolledback'
    assert (await client.get(f'/api/servers/{sid}', headers=auth_headers)).json()['ssh_access_pending'] is False


@pytest.mark.parametrize('phase', ['applying', 'finalizing'])
async def test_unreachable_node_with_unconfirmed_stage_can_be_deleted(client, auth_headers, phase):
    node = (await client.post('/api/servers', json={"name": "gone", "host": "192.0.2.1"}, headers=auth_headers)).json()
    sid = node['id']
    async with client.session_factory() as session:
        session.add(SshAccessChange(id='c' * 32, server_id=sid, phase=phase, payload={}))
        await session.commit()
    assert (await client.post('/api/backup/now', headers=auth_headers)).status_code == 409
    response = await client.delete(f'/api/servers/{sid}', headers=auth_headers)
    if phase == 'finalizing':
        # The saved policy may already be the new one: never guess, keep the journal.
        assert response.status_code == 409
        return
    assert response.status_code == 200, response.text
    async with client.session_factory() as session:
        assert await session.get(SshAccessChange, 'c' * 32) is None


@pytest.mark.parametrize('warning', ['', 'Старый промежуточный доступ не отозван: offline'])
async def test_successful_route_is_preserved_when_old_role_retirement_fails(client, auth_headers, monkeypatch, warning):
    jump = (await client.post('/api/servers', json={'name': 'jump', 'host': '192.0.2.1'}, headers=auth_headers)).json()
    node = (await client.post('/api/servers', json={'name': 'target', 'host': '192.0.2.2', 'ssh_jump_server_id': jump['id'], 'ssh_firewall_mode': 'preserve'}, headers=auth_headers)).json()
    verified = []
    class Conn:
        async def run(self, *args, **kwargs):
            return SimpleNamespace(exit_status=0, stdout='ACONTROL_KEY_READY ACONTROL_KEY_COMMITTED', stderr='')
    @asynccontextmanager
    async def connection(*args, **kwargs): yield Conn()
    async def verify(target, settings):
        assert target.ssh_jump_server_id is None
        verified.append(True)
        return '192.0.2.7'
    async def retire(old, settings):
        assert verified and old.ssh_jump_server_id == jump['id']
        async with client.session_factory() as session:
            change = await session.scalar(select(SshAccessChange).where(SshAccessChange.server_id == old.id))
            assert change.phase == 'finalizing'  # Crash recovery still retries retirement.
        return warning
    monkeypatch.setattr(ssh_access, 'connection', connection)
    monkeypatch.setattr(ssh_access, 'verify', verify)
    monkeypatch.setattr(ssh_access, 'retire_jump', retire)
    plan = (await client.post(f'/api/servers/{node["id"]}/ssh-access/preview', json={'ssh_jump_server_id': None, 'ssh_source_mode': 'custom', 'ssh_source_ips': ['192.0.2.7'], 'ssh_firewall_mode': 'preserve'}, headers=auth_headers)).json()
    response = await client.post(f'/api/servers/{node["id"]}/ssh-access/apply', json={'token': plan['token']}, headers=auth_headers)
    assert response.status_code == 200, response.text
    assert response.json()['ssh_jump_server_id'] is None
    if warning: assert warning in response.json()['last_check_info']
    async with client.session_factory() as session:
        change = await session.get(SshAccessChange, plan['token'])
        assert change.phase == 'done'
        assert change.payload['retired_jump'] == ('warning' if warning else 'revoked')


@pytest.mark.parametrize('remote_after_loss', ['committed', 'firewall-watchdog', 'partial-firewall-watchdog', 'key-watchdog'])
async def test_lost_firewall_commit_reply_reconciles_without_blind_rollback(client, auth_headers, monkeypatch, remote_after_loss):
    node = (await client.post('/api/servers', json={'name': 'target', 'host': '192.0.2.2'}, headers=auth_headers)).json()
    state = {'key': 'STAGED', 'firewall': 'STAGED', 'lost': False, 'firewall_blocked': False}
    operations = []
    class Conn:
        async def run(self, command, **kwargs):
            if 'ACONTROL_KEY_STATE_' in command: marker = 'ACONTROL_KEY_STATE_' + state['key']
            elif 'ACONTROL_FIREWALL_STATE_' in command: marker = 'ACONTROL_FIREWALL_STATE_' + state['firewall']
            elif 'ACONTROL_KEY_READY' in command: marker = 'ACONTROL_KEY_READY'
            elif 'ACONTROL_FIREWALL_READY' in command: marker = 'ACONTROL_FIREWALL_READY'
            elif 'ACONTROL_KEY_COMMITTED' in command:
                assert state['key'] != 'ROLLEDBACK'
                state['key'] = 'COMMITTED'; marker = 'ACONTROL_KEY_COMMITTED'
            elif 'ACONTROL_FIREWALL_COMMITTED' in command:
                assert state['firewall'] not in ('ROLLINGBACK', 'ROLLEDBACK')
                if not state['lost']:
                    state['lost'] = True
                    if remote_after_loss != 'partial-firewall-watchdog':
                        state['firewall'] = 'COMMITTED'
                    raise OSError('firewall commit reply lost')
                state['firewall'] = 'COMMITTED'
                marker = 'ACONTROL_FIREWALL_COMMITTED'
            elif 'ACONTROL_KEY_ROLLEDBACK' in command:
                state['key'] = 'ROLLEDBACK'; marker = 'ACONTROL_KEY_ROLLEDBACK'
            elif 'ACONTROL_FIREWALL_ROLLEDBACK' in command:
                assert state['firewall'] != 'COMMITTED'
                if state['firewall_blocked']:
                    return SimpleNamespace(exit_status=1, stdout='', stderr='temporary firewall rollback failure')
                state['firewall'] = 'ROLLEDBACK'; marker = 'ACONTROL_FIREWALL_ROLLEDBACK'
            else: raise AssertionError(command)
            operations.append(marker)
            return SimpleNamespace(exit_status=0, stdout=marker, stderr='')
    @asynccontextmanager
    async def connection(*args, **kwargs): yield Conn()
    async def verify(*args): return '192.0.2.7'
    monkeypatch.setattr(ssh_access, 'connection', connection)
    monkeypatch.setattr(ssh_access, 'verify', verify)
    plan = (await client.post(f'/api/servers/{node["id"]}/ssh-access/preview', json={'ssh_source_mode': 'custom', 'ssh_source_ips': ['192.0.2.7'], 'ssh_firewall_mode': 'add'}, headers=auth_headers)).json()
    result = await client.post(f'/api/servers/{node["id"]}/ssh-access/apply', json={'token': plan['token']}, headers=auth_headers)
    assert result.status_code == 409 and 'журнал' in result.text
    assert not any('ROLLEDBACK' in item for item in operations)
    async with client.session_factory() as session:
        assert (await session.get(SshAccessChange, plan['token'])).phase == 'finalizing'
    if remote_after_loss == 'firewall-watchdog': state['firewall'] = 'ROLLEDBACK'
    if remote_after_loss == 'partial-firewall-watchdog':
        state.update(firewall='ROLLINGBACK', firewall_blocked=True)
        blocked = await client.post(f'/api/servers/{node["id"]}/ssh-access/recover', headers=auth_headers)
        assert blocked.status_code == 409
        async with client.session_factory() as session:
            assert (await session.get(SshAccessChange, plan['token'])).phase == 'finalizing'
        state['firewall_blocked'] = False
    if remote_after_loss == 'key-watchdog': state.update(key='ROLLEDBACK', firewall='STAGED')
    result = await client.post(f'/api/servers/{node["id"]}/ssh-access/recover', headers=auth_headers)
    assert result.status_code == 200, result.text
    async with client.session_factory() as session:
        change = await session.get(SshAccessChange, plan['token'])
        assert change.phase == ('done' if remote_after_loss == 'committed' else 'rolledback')
    if remote_after_loss == 'partial-firewall-watchdog':
        assert operations.count('ACONTROL_KEY_COMMITTED') == 1
        assert operations[-2:] == ['ACONTROL_KEY_ROLLEDBACK', 'ACONTROL_FIREWALL_ROLLEDBACK']
    assert result.json()['ssh_source_mode'] == ('custom' if remote_after_loss == 'committed' else 'panel')


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
