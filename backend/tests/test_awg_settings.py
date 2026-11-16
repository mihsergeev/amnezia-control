"""Settings validation, stable client identities and SSH/DB compensation."""

import base64
import ipaddress
import json
import shutil
import subprocess
from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy import select

from app import awg, awg_settings as settings, deploy, nodelock, torrent
from app.api import awg as awg_api
from app.api import awg_settings as api
from app.models import AwgConfig, AwgSettingsChange, Cascade, PausedClient
from app.schemas import DeployRequest


@pytest.mark.parametrize("ver,generator", [("2.0", deploy.generate_awg_params), ("3.1", deploy.generate_awg3_params)])
def test_generated_parameters_validate(ver, generator):
    for _ in range(100):
        assert settings.validate_params(generator(), ver)


@pytest.mark.parametrize("values,ver", [
    ({"Jmin": 100, "Jmax": 10}, "2.0"),
    ({"H1": "5-10", "H2": "10-15"}, "2.0"),
    ({"S1": 10}, "3.1"),
    ({"RandomTrailers": "maybe"}, "3.1"),
    ({"HeaderProtectionKey": "invalid"}, "3.1"),
    ({"I1": "<r -1>"}, "2.0"),
    ({"I1": "<r 1281>"}, "2.0"),
    ({"I1": "<b 0x001>"}, "2.0"),
    ({"I1": "< >"}, "2.0"),
    ({"Jc": 1, "Jmin": "01", "Jmax": "1"}, "2.0"),
    ({"Jc": "3\nPostUp = bad"}, "2.0"),
    ({"Jc": "9" * 1000}, "2.0"),
    ({"FutureSetting": "on"}, "3.1"),
])
def test_invalid_parameters_refused(values, ver):
    params = deploy.generate_awg3_params() if ver == "3.1" else deploy.generate_awg_params()
    params.update(values)
    with pytest.raises(HTTPException) as error:
        settings.validate_params(params, ver)
    assert error.value.status_code == 422
    assert "PostUp" not in error.value.detail


def test_only_actual_version_fields_are_supported():
    assert "RandomTrailers" not in settings.keys("3.0")
    assert "RandomTrailers" in settings.keys("3.1")
    assert "HeaderProtectionKey" not in settings.keys("2.0")
    params = deploy.generate_awg_params()
    params["HeaderProtectionKey"] = "A" * 43 + "="
    with pytest.raises(HTTPException):
        settings.validate_params(params, "2.0")


@pytest.mark.parametrize("subnet,address", [
    ("10.73.1.3/24", None), ("203.0.113.0/24", None),
    ("10.73.1.0/30", None), ("10.73.1.0/24", "10.73.2.1"),
    ("10.73.1.0/24", "10.73.1.0"), ("10.73.1.0/24", "10.73.1.255"),
    ("10.73.1.0/24", "10.73.1.1/16"),
])
def test_invalid_network_refused(subnet, address):
    with pytest.raises(HTTPException):
        settings.network(subnet, address)


def test_existing_legacy_network_address_can_be_retained_without_forced_client_changes():
    _net, address = settings.network('10.73.1.0/24', '10.73.1.0/24', existing_address='10.73.1.0/24')
    assert address == '10.73.1.0/24'
    with pytest.raises(HTTPException):
        settings.network('10.74.1.0/24', '10.74.1.0/24', existing_address='10.73.1.0/24')


async def test_auto_network_and_port_skip_conflicts(monkeypatch):
    class Conn:
        async def run(self, command, **kwargs):
            assert command == "bash -s"
            assert "sudo -n ss" in kwargs["input"]
            return SimpleNamespace(exit_status=0, stdout='[{"dst":"10.8.0.0/16"}]\n===ADDR===\n[{"addr_info":[{"family":"inet","local":"10.9.0.1","prefixlen":16}]}]\n')
    async def owner(_conn, port, *args, **kwargs):
        return "busy" if port < 47302 else None
    monkeypatch.setattr(deploy, "port_owner", owner)
    port, subnet, address, params = await settings.choose(Conn(), DeployRequest(), "3.1")
    assert port == 47302
    assert subnet == "10.73.1.0/24" and address == "10.73.1.1/24"
    assert settings.version(params) == "3.1"
    _port, _subnet, _address, params30 = await settings.choose(Conn(), DeployRequest(), "3.0")
    assert settings.version(params30) == "3.0"
    assert 'RandomTrailers' not in params30 and 'DisableCookies' not in params30
    with pytest.raises(HTTPException) as err:
        await settings.choose(Conn(), DeployRequest(subnet="10.8.12.0/24"), "3.1")
    assert err.value.status_code == 409


def test_discovery_excludes_only_own_container():
    output = '[{"dst":"10.60.0.0/16"}]\nCONTAINER=amnezia-awg3\n[{"dst":"10.61.0.0/16"}]\nCONTAINER=amnezia-awg2\n[{"dst":"10.62.0.0/16"}]\nNETWORK=172.20.0.0/16'
    found = {str(n) for n in settings.discovered_networks(output, "amnezia-awg3")}
    assert found == {"10.60.0.0/16", "10.62.0.0/16", "172.20.0.0/16"}
    with pytest.raises(HTTPException):
        settings.discovered_networks("DISCOVERY_ERROR")


def test_managed_guard_accepts_docker29_defaults_but_rejects_custom_options():
    import copy
    config = {'Image': deploy.IMAGE_V3, 'Entrypoint':['/opt/amnezia/start.sh'], 'Env':['PATH=/usr/bin:/bin'], 'User':'', 'Labels':{}}
    image = {'Config':{**config, 'User':None, 'Labels':None}}
    info = {'Config':config, 'HostConfig':{'NetworkMode':'bridge', 'Privileged':True,
        'RestartPolicy':{'Name':'always'}, 'SecurityOpt':['label=disable'],
        'PortBindings':{'47300/udp':[{'HostIp':'', 'HostPort':'47300'}]}},
        'Mounts':[{'Type':'bind','Source':deploy.HOST_DIR_V3,'Destination':awg.AWG_DIR,'RW':True}],
        'NetworkSettings':{'Networks':{'bridge':{}}}}
    assert settings.managed(info, deploy.CONTAINER_V3, 'awg3', image) == deploy.HOST_DIR_V3
    canonical = copy.deepcopy(info['HostConfig'])
    assert settings.managed(info, deploy.CONTAINER_V3, 'awg3', image, canonical) == deploy.HOST_DIR_V3
    for key, value in [('Sysctls', {'net.ipv4.conf.all.src_valid_mark':'0'}),
                       ('CapAdd', ['NET_ADMIN']), ('LogConfig', {'Type':'none'}),
                       ('Ulimits', [{'Name':'nofile','Soft':1024,'Hard':1024}]),
                       ('ShmSize', 128*1024*1024), ('IpcMode','host'),
                       ('FutureDockerOption','custom')]:
        changed = copy.deepcopy(info)
        changed['HostConfig'][key] = value
        with pytest.raises(HTTPException):
            settings.managed(changed, deploy.CONTAINER_V3, 'awg3', image, canonical)
    for location, key, value in [('HostConfig','SecurityOpt',['seccomp=unconfined']),
                                  ('HostConfig','Dns',['192.0.2.53']),
                                  ('Config','Env',['CUSTOM=synthetic']),
                                  ('Config','Entrypoint',['/custom/start.sh'])]:
        changed = copy.deepcopy(info)
        changed[location][key] = value
        with pytest.raises(HTTPException):
            settings.managed(changed, deploy.CONTAINER_V3, 'awg3', image)


@pytest.mark.skipif(shutil.which("bash") is None, reason="requires bash")
def test_nat_uses_actual_interface_network():
    script = '''set -e
ip(){ echo '10.73.5.0/24 proto kernel scope link src 10.73.5.1'; }
iptables(){ case "$*" in *' -D '*) return 1;; *) echo "$*";; esac; }
''' + deploy._client_nat(deploy.SUBNET)
    result = subprocess.run([shutil.which("bash"), "-s"], input=script, text=True, capture_output=True)
    assert result.returncode == 0, result.stderr
    assert '-s 10.73.5.0/24 ! -o awg0 -j MASQUERADE' in result.stdout
    assert '-s 10.8.1.0/24 ! -o awg0' not in result.stdout
    unit = deploy._systemd_unit_v3()
    assert '$$VPN_SUBNET' in unit and '%%%%' in unit


def test_peer_and_profile_change_preserves_keys_and_metadata():
    private, public = awg.generate_keypair()
    server_private, server_public = awg.generate_keypair()
    psk = base64.b64encode(bytes(32)).decode()
    old = deploy.generate_awg3_params()
    client = awg.build_client_config(client_private=private, address="10.73.1.7", server_public=server_public,
        preshared=psk, endpoint="vpn.example.com:47300", params=old, dns="192.0.2.53")
    new = settings.validate_params(deploy.generate_awg3_params(), "3.1")
    result = settings.refresh_profile(client, new, "10.74.1.7/32", 47500, "10.74.1.0/24")
    iface, peers = awg.parse_conf(result)
    assert iface["PrivateKey"] == private and awg.derive_public_key(iface["PrivateKey"]) == public
    assert iface["Address"] == "10.74.1.7/32" and iface["DNS"] == "192.0.2.53"
    assert peers[0]["PresharedKey"] == psk and peers[0]["PublicKey"] == server_public
    assert peers[0]["Endpoint"] == "vpn.example.com:47500"
    assert all(iface[k] == v for k, v in new.items() if v)
    server = f'[Interface]\n# keep this comment\nPrivateKey = {server_private}\nAddress = 10.73.1.1/24\n\n[Peer]\nPublicKey = {public}\nPresharedKey = {psk}\nAllowedIPs = 10.73.1.7/32\n'
    result = settings.replace_interface(server, {"Address": "10.74.1.1/24", **new})
    result = settings.remap_peers(result, ipaddress.ip_network("10.73.1.0/24"), ipaddress.ip_network("10.74.1.0/24"), ipaddress.ip_address("10.74.1.1"))
    assert '# keep this comment' in result and f'PrivateKey = {server_private}' in result
    assert awg.parse_conf(result)[1][0]["AllowedIPs"] == "10.74.1.7/32"
    with pytest.raises(HTTPException):
        settings.remap_peers(server.replace('/32','/24'), ipaddress.ip_network("10.73.1.0/24"), ipaddress.ip_network("10.74.1.0/24"), ipaddress.ip_address("10.74.1.1"))


def test_runtime_is_valid_shell_and_stages_probe_before_live_changes():
    script = settings.runtime("a" * 32, deploy.CONTAINER_V3, deploy.HOST_DIR_V3, "awg3", 47500, "10.73.1.1/24")
    result = subprocess.run([shutil.which("bash"), "-n"], input=script, text=True, capture_output=True)
    assert result.returncode == 0, result.stderr
    assert script.index('awg-quick up /tmp/awg0.conf') < script.index('docker stop "$C"')
    assert script.index('systemd-run --quiet') < script.index('docker stop "$C"')
    assert 'mark rollback_failed' in script
    assert 'docker rename "$OLD" "$C"' in script
    assert 'readback 47500 10.73.1.1/24' in script


def test_settings_journal_migration_preserves_existing_profiles():
    import importlib.util
    from pathlib import Path
    from alembic.migration import MigrationContext
    from alembic.operations import Operations
    from sqlalchemy import create_engine, inspect, text
    path = Path(__file__).parents[1] / 'alembic/versions/0039_awg_settings_changes.py'
    spec = importlib.util.spec_from_file_location('settings_journal_migration', path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    engine = create_engine('sqlite:///:memory:')
    with engine.begin() as conn:
        conn.execute(text('CREATE TABLE awg_configs (id INTEGER PRIMARY KEY, config TEXT)'))
        conn.execute(text("INSERT INTO awg_configs VALUES (1, 'synthetic-profile')"))
        migration.op = Operations(MigrationContext.configure(conn))
        migration.upgrade()
        assert {c['name'] for c in inspect(conn).get_columns('awg_settings_changes')} == {'id','server_id','protocol','phase','payload'}
        assert conn.scalar(text('SELECT config FROM awg_configs')) == 'synthetic-profile'
        conn.execute(text("INSERT INTO awg_settings_changes VALUES ('test', 1, 'awg3', 'prepared', '{}')"))
        with pytest.raises(RuntimeError, match='Resolve pending'):
            migration.downgrade()
        assert 'awg_settings_changes' in inspect(conn).get_table_names()
        conn.execute(text("UPDATE awg_settings_changes SET phase='rolledback'"))
        migration.downgrade()
        assert 'awg_settings_changes' not in inspect(conn).get_table_names()
        assert conn.scalar(text('SELECT config FROM awg_configs')) == 'synthetic-profile'
    engine.dispose()


async def prepare_case(client, headers, monkeypatch):
    response = await client.post('/api/servers', json={"name":"vpn-test", "host":"203.0.113.10", "ssh_port":2221, "ssh_user":"service"}, headers=headers)
    sid = response.json()["id"]
    cfg = deploy.generate_server_config_v3(47300, "10.73.1.1/24")
    private, public = awg.generate_keypair()
    params, _ = awg.parse_conf(cfg['conf'])
    profile = awg.build_client_config(client_private=private, address="10.73.1.7", server_public=cfg['pub'],
        preshared=cfg['psk'], endpoint="vpn.example.com:47300", params=params, dns="192.0.2.53")
    conf = cfg['conf'] + f'\n[Peer]\nPublicKey = {public}\nPresharedKey = {cfg["psk"]}\nAllowedIPs = 10.73.1.7/32\n'
    current = SimpleNamespace(container=deploy.CONTAINER_V3, interface='awg0', address='10.73.1.1/24', params=params,
        listen_port=47300, clients=[SimpleNamespace(address='10.73.1.7/32')])
    remote = {'phase':'missing', 'actions':[], 'fail':None}
    class Conn:
        async def run(self, command, **kwargs):
            value = json.dumps([{'Image':'sha256:synthetic'}]) if 'docker inspect' in command and 'external' not in command else ''
            if 'image inspect' in command: value='[{}]'
            return SimpleNamespace(exit_status=0, stdout=value)
    @asynccontextmanager
    async def connection(_server):
        yield Conn()
    async def return_state(*args): return current
    async def return_conf(*args): return conf
    async def idle(*args, **kwargs): pass
    async def choose(*args, **kwargs): return 47500, '10.74.1.0/24', '10.74.1.1/24', settings.validate_params(deploy.generate_awg3_params(), '3.1')
    async def table(*args): return [{'clientId':public, 'userData':{'clientName':'client-test'}}]
    async def action(_conn, token, verb):
        remote['actions'].append(verb)
        if verb == 'status': return remote['phase']
        if remote['fail'] == verb: raise HTTPException(502, 'synthetic failure')
        remote['phase'] = {'prepare':'prepared', 'apply':'applied', 'rollback':'rolledback', 'finalize':'committed'}[verb]
        return ''
    monkeypatch.setattr(awg_api, '_connect', connection)
    monkeypatch.setattr(api, 'state', return_state)
    monkeypatch.setattr(awg, 'read_awg_conf', return_conf)
    monkeypatch.setattr(awg, '_read_table', table)
    monkeypatch.setattr(deploy, 'ensure_idle', idle)
    monkeypatch.setattr(settings, 'choose', choose)
    monkeypatch.setattr(settings, 'managed', lambda *args: deploy.HOST_DIR_V3)
    async def canonical(*args): return {}
    monkeypatch.setattr(settings, 'canonical_host', canonical)
    monkeypatch.setattr(settings, 'remote_action', action)
    async with client.session_factory() as session:
        session.add(AwgConfig(server_id=sid, protocol='awg3', public_key=public, name='client-test', config=profile))
        session.add(PausedClient(server_id=sid, protocol='awg3', client_id='synthetic-paused', name='paused', data=json.dumps({'ip':'10.73.1.8', 'other':'keep'})))
        await session.commit()
    body = {'port':47500, 'subnet':'10.74.1.0/24', 'server_address':'10.74.1.1/24', 'params':params,
            'revision':settings.revision(conf), 'acknowledge_disconnect':True}
    return sid, body, remote, private, profile


async def test_settings_apply_updates_profiles_and_paused_without_rekey(client, auth_headers, monkeypatch):
    sid, body, remote, private, _ = await prepare_case(client, auth_headers, monkeypatch)
    response = await client.put(f'/api/servers/{sid}/awg3/settings', json=body, headers=auth_headers)
    assert response.status_code == 200, response.text
    assert response.json()['profiles_refreshed'] == 1
    assert remote['phase'] == 'committed'
    async with client.session_factory() as session:
        profile = await session.scalar(select(AwgConfig))
        iface, peers = awg.parse_conf(profile.config)
        assert iface['PrivateKey'] == private and iface['Address'] == '10.74.1.7/32'
        assert peers[0]['Endpoint'] == 'vpn.example.com:47500'
        paused = await session.scalar(select(PausedClient))
        assert json.loads(paused.data) == {'ip':'10.74.1.8','other':'keep'}
        journal = await session.scalar(select(AwgSettingsChange))
        assert journal.phase == 'done' and journal.payload == {}


async def test_failed_apply_compensates_and_retry_works(client, auth_headers, monkeypatch):
    sid, body, remote, _, old_profile = await prepare_case(client, auth_headers, monkeypatch)
    remote['fail'] = 'apply'
    response = await client.put(f'/api/servers/{sid}/awg3/settings', json=body, headers=auth_headers)
    assert response.status_code == 502
    async with client.session_factory() as session:
        assert (await session.scalar(select(AwgConfig))).config == old_profile
        assert (await session.scalar(select(AwgSettingsChange))).phase == 'rolledback'
    remote['fail'] = None
    response = await client.put(f'/api/servers/{sid}/awg3/settings', json=body, headers=auth_headers)
    assert response.status_code == 200, response.text


async def test_cascade_and_missing_ack_stop_before_remote_mutations(client, auth_headers, monkeypatch):
    sid, body, remote, _, _ = await prepare_case(client, auth_headers, monkeypatch)
    body['acknowledge_disconnect'] = False
    response = await client.put(f'/api/servers/{sid}/awg3/settings', json=body, headers=auth_headers)
    assert response.status_code == 422 and remote['actions'] == []
    body['acknowledge_disconnect'] = True
    async with client.session_factory() as session:
        session.add(Cascade(entry_server_id=sid, exit_server_id=sid+1, transport='gre', status='ready'))
        await session.commit()
    response = await client.put(f'/api/servers/{sid}/awg3/settings', json=body, headers=auth_headers)
    assert response.status_code == 409 and remote['actions'] == []


async def test_crash_recovery_restores_database_after_watchdog_rollback(client, auth_headers, monkeypatch):
    sid, body, remote, _, old_profile = await prepare_case(client, auth_headers, monkeypatch)
    async with client.session_factory() as session:
        profile = await session.scalar(select(AwgConfig))
        profile.config = 'synthetic-new-profile'
        session.add(AwgSettingsChange(id='b'*32, server_id=sid, protocol='awg3', phase='applied',
            payload={'profiles':[{'id':profile.id, 'old':old_profile, 'new':'synthetic-new-profile'}], 'paused':[]}))
        await session.commit()
    remote['phase'] = 'rolledback'
    response = await client.get(f'/api/servers/{sid}/awg3/settings', headers=auth_headers)
    assert response.status_code == 200, response.text
    async with client.session_factory() as session:
        assert (await session.scalar(select(AwgConfig))).config == old_profile
        assert (await session.scalar(select(AwgSettingsChange))).phase == 'rolledback'


async def test_unknown_rollback_is_guarded_until_recovery_succeeds(client, auth_headers, monkeypatch):
    sid, body, remote, _, old_profile = await prepare_case(client, auth_headers, monkeypatch)
    original = settings.remote_action
    async def fail(conn, token, action):
        if action in ('apply', 'rollback'):
            raise HTTPException(502, 'synthetic lost connection')
        return await original(conn, token, action)
    monkeypatch.setattr(settings, 'remote_action', fail)
    response = await client.put(f'/api/servers/{sid}/awg3/settings', json=body, headers=auth_headers)
    assert response.status_code == 502 and 'неизвестен' in response.json()['detail']
    response = await client.get(f'/api/servers/{sid}/awg3/settings', headers=auth_headers)
    assert response.status_code == 409
    monkeypatch.setattr(settings, 'remote_action', original)
    response = await client.get(f'/api/servers/{sid}/awg3/settings', headers=auth_headers)
    assert response.status_code == 200
    async with client.session_factory() as session:
        assert (await session.scalar(select(AwgConfig))).config == old_profile
        assert (await session.scalar(select(AwgSettingsChange))).phase == 'rolledback'


async def test_stale_revision_does_not_apply_and_recovery_can_finalize(client, auth_headers, monkeypatch):
    sid, body, remote, _, old_profile = await prepare_case(client, auth_headers, monkeypatch)
    body['revision'] = '0' * 64
    response = await client.put(f'/api/servers/{sid}/awg3/settings', json=body, headers=auth_headers)
    assert response.status_code == 409 and remote['actions'] == []
    async with client.session_factory() as session:
        profile = await session.scalar(select(AwgConfig))
        profile.config = 'synthetic-new-profile'
        session.add(AwgSettingsChange(id='c'*32, server_id=sid, protocol='awg3', phase='applied',
            payload={'profiles':[{'id':profile.id, 'old':old_profile, 'new':'synthetic-new-profile'}], 'paused':[]}))
        await session.commit()
    remote['phase'] = 'applied'
    response = await client.get(f'/api/servers/{sid}/awg3/settings', headers=auth_headers)
    assert response.status_code == 200 and remote['phase'] == 'committed'
    async with client.session_factory() as session:
        assert (await session.scalar(select(AwgConfig))).config == 'synthetic-new-profile'
        assert (await session.scalar(select(AwgSettingsChange))).phase == 'done'


@pytest.mark.parametrize('cancel_during_recovery', [False, True])
async def test_cancellation_never_detaches_compensation_from_request_resources(
    client, auth_headers, monkeypatch, cancel_during_recovery,
):
    import asyncio
    sid, body, remote, _, old_profile = await prepare_case(client, auth_headers, monkeypatch)
    original = settings.remote_action
    applied, recovering = asyncio.Event(), asyncio.Event()
    owners = []
    async def cancel_point(conn, token, verb):
        owners.append(asyncio.current_task())
        if verb == 'apply':
            await original(conn, token, verb)
            applied.set()
            await asyncio.Event().wait()
        if verb == 'status' and cancel_during_recovery:
            recovering.set()
            await asyncio.Event().wait()
        return await original(conn, token, verb)
    monkeypatch.setattr(settings, 'remote_action', cancel_point)
    request_task = asyncio.create_task(client.put(
        f'/api/servers/{sid}/awg3/settings', json=body, headers=auth_headers))
    await asyncio.wait_for(applied.wait(), 5)
    request_task.cancel()
    if cancel_during_recovery:
        await asyncio.wait_for(recovering.wait(), 5)
        request_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await request_task
    assert owners and all(owner is request_task for owner in owners)
    # A second cancellation leaves a durable pending record, not a detached
    # compensation task using the now-closed request session/connection.
    async with client.session_factory() as session:
        journal = await session.scalar(select(AwgSettingsChange))
        assert journal.phase == ('prepared' if cancel_during_recovery else 'rolledback')
    monkeypatch.setattr(settings, 'remote_action', original)
    response = await client.get(f'/api/servers/{sid}/awg3/settings', headers=auth_headers)
    assert response.status_code == 200
    async with client.session_factory() as session:
        assert (await session.scalar(select(AwgConfig))).config == old_profile
        assert (await session.scalar(select(AwgSettingsChange))).phase == 'rolledback'

@pytest.mark.parametrize('protocol,version', [('awg3', '3.0'), ('awg', '3.0'), ('awg', '3.1')])
async def test_installed_defaults_are_version_specific(client, auth_headers, protocol, version):
    r = await client.post('/api/servers', json={'name':'test-node', 'host':'203.0.113.10'}, headers=auth_headers)
    sid = r.json()['id']
    r = await client.get(f'/api/servers/{sid}/{protocol}/settings/defaults?protocol_version={version}', headers=auth_headers)
    assert r.status_code == 200, r.text
    assert r.json()['version'] == version
    assert set(r.json()['params']) == set(settings.keys(version))
    assert settings.validate_params(r.json()['params'], version)


async def test_cascade_creation_gate_prevents_settings_mutations(client, auth_headers, monkeypatch):
    import asyncio
    sid, body, remote, _, _ = await prepare_case(client, auth_headers, monkeypatch)
    async with nodelock.hold('cascade', sid):
        task = asyncio.create_task(client.put(f'/api/servers/{sid}/awg3/settings', json=body, headers=auth_headers))
        await asyncio.sleep(0.05)
        assert not task.done() and remote['actions'] == []
        async with client.session_factory() as session:
            session.add(Cascade(entry_server_id=sid, exit_server_id=sid+1, transport='gre', status='installing'))
            await session.commit()
    response = await asyncio.wait_for(task, 5)
    assert response.status_code == 409 and remote['actions'] == []


@pytest.mark.parametrize('protocol', ['awg', 'awg3'])
async def test_profile_export_waits_for_settings_transaction(client, auth_headers, monkeypatch, protocol):
    import asyncio
    sid, body, remote, private, _ = await prepare_case(client, auth_headers, monkeypatch)
    async with client.session_factory() as session:
        row = await session.scalar(select(AwgConfig))
        row.protocol = protocol
        public = row.public_key
        await session.commit()
    applied, proceed = asyncio.Event(), asyncio.Event()
    original = settings.remote_action
    async def blocked(conn, token, verb):
        result = await original(conn, token, verb)
        if verb == 'apply':
            applied.set()
            await proceed.wait()
        return result
    monkeypatch.setattr(settings, 'remote_action', blocked)
    task = asyncio.create_task(client.put(f'/api/servers/{sid}/{protocol}/settings', json=body, headers=auth_headers))
    await asyncio.wait_for(applied.wait(), 5)
    export = asyncio.create_task(client.post(f'/api/servers/{sid}/{protocol}/config', json={'public_key':public}, headers=auth_headers))
    await asyncio.sleep(0.05)
    assert not export.done()
    proceed.set()
    assert (await asyncio.wait_for(task, 5)).status_code == 200
    response = await asyncio.wait_for(export, 5)
    assert response.status_code == 200, response.text
    iface, peers = awg.parse_conf(response.json()['config'])
    assert iface['PrivateKey'] == private and iface['Address'] == '10.74.1.7/32'
    assert peers[0]['Endpoint'].endswith(':47500')


async def test_torrent_sample_refreshes_policy_after_settings_lock(client, auth_headers, monkeypatch):
    import asyncio
    from app.models import Server
    sid, _, _, _, _ = await prepare_case(client, auth_headers, monkeypatch)
    async with client.session_factory() as session:
        stale = await session.get(Server, sid)
        assert not stale.torrent_block
    seen = []
    async def sync(conn, container, enabled):
        seen.append(enabled)
        return True, {}
    monkeypatch.setattr(torrent, 'sync_container', sync)
    async with nodelock.hold('awg', sid):
        task = asyncio.create_task(torrent.sample(None, stale, [{'container':'test', 'ips':{}, 'protocol':'awg3'}], client.session_factory))
        await asyncio.sleep(0.05)
        assert not task.done() and seen == []
        async with client.session_factory() as session:
            fresh = await session.get(Server, sid)
            fresh.torrent_block = True
            await session.commit()
    assert await asyncio.wait_for(task, 5) == []
    assert seen == [True]

async def test_database_commit_failure_after_remote_apply_compensates(client, auth_headers, monkeypatch):
    from sqlalchemy.ext.asyncio import AsyncSession
    from sqlalchemy.exc import SQLAlchemyError
    sid, body, remote, _, old_profile = await prepare_case(client, auth_headers, monkeypatch)
    original = AsyncSession.commit
    failed = False
    async def fail_once(session):
        nonlocal failed
        if not failed and any(isinstance(row, AwgSettingsChange) and row.phase == 'applied' for row in session.identity_map.values()):
            failed = True
            raise SQLAlchemyError('synthetic commit failure')
        return await original(session)
    monkeypatch.setattr(AsyncSession, 'commit', fail_once)
    r = await client.put(f'/api/servers/{sid}/awg3/settings', json=body, headers=auth_headers)
    assert failed and r.status_code == 502
    assert remote['actions'] == ['prepare', 'apply', 'status', 'rollback']
    async with client.session_factory() as session:
        assert (await session.scalar(select(AwgConfig))).config == old_profile
        assert (await session.scalar(select(AwgSettingsChange))).phase == 'rolledback'

async def test_delete_server_preserves_unresolved_settings_journal(client, auth_headers, monkeypatch):
    from app.models import Server
    sid, _, remote, _, _ = await prepare_case(client, auth_headers, monkeypatch)
    async with client.session_factory() as session:
        session.add(AwgSettingsChange(id='d'*32, server_id=sid, protocol='awg3', phase='prepared', payload={}))
        await session.commit()
    remote['phase'] = 'unrecognized'
    r = await client.delete(f'/api/servers/{sid}', headers=auth_headers)
    assert r.status_code == 409
    async with client.session_factory() as session:
        assert await session.get(Server, sid) is not None
        assert (await session.scalar(select(AwgSettingsChange))).phase == 'prepared'

@pytest.mark.parametrize('protocol', ['wireguard', 'xray', 'openvpn'])
async def test_other_protocols_do_not_reverse_awg_delete_lock_order(client, auth_headers, monkeypatch, protocol):
    import asyncio
    from app import protoremove, sshops
    from app.api import bulk_clients
    sid, _, _, _, _ = await prepare_case(client, auth_headers, monkeypatch)
    async with client.session_factory() as session:
        session.add(AwgSettingsChange(id='e'*32, server_id=sid, protocol='awg3', phase='prepared', payload={}))
        await session.commit()
    @asynccontextmanager
    async def connection(*args, **kwargs):
        yield object()
    async def rename(*args):
        return True, protocol
    monkeypatch.setattr(sshops, 'connect', connection)
    monkeypatch.setattr(protoremove, 'rename_on_node', rename)
    async def bulk_lookup():
        async with nodelock.hold(protocol, sid), client.session_factory() as session:
            assert (await bulk_clients._server(session, sid, protocol)).id == sid
    # Server deletion takes AWG before these protocol locks. Neither generic
    # operation may wait for AWG while holding an unrelated protocol lock,
    # even when an unresolved AWG settings journal exists.
    async with nodelock.hold('awg', sid):
        await asyncio.wait_for(asyncio.create_task(bulk_lookup()), 3)
        request = asyncio.create_task(client.post(f'/api/servers/{sid}/protocols/{protocol}/rename',
            json={'client_id':'synthetic-client','name':'renamed-test'}, headers=auth_headers))
        response = await asyncio.wait_for(request, 3)
        assert response.status_code == 204, response.text
    async with client.session_factory() as session:
        assert (await session.scalar(select(AwgSettingsChange))).phase == 'prepared'

@pytest.mark.skipif(shutil.which('bash') is None, reason='requires bash')
async def test_partial_runtime_upload_is_unpublished_and_retry_is_atomic(tmp_path):
    token = 'f'*32
    script = '#!/bin/bash\nset -eu\nprintf ready\\n\n'
    class Conn:
        truncated = True
        async def run(self, command, input=None, **kwargs):
            command = command.replace('sudo -n ', '').replace('/lib65/scripts', '.')
            # This truncated prefix is valid shell. A syntax-only check would
            # publish it and strand a prepared journal with an empty status.
            payload = '#!/bin/bash\n' if self.truncated else input
            if tmp_path.drive:
                # Git Bash's install.exe cannot open /dev/stdin on Windows.
                # Supply the same uploaded bytes through a regular file; the
                # production checksum and atomic publish command stay intact.
                (tmp_path / 'upload-input').write_bytes(payload.encode())
                command = command.replace('/dev/stdin', './upload-input')
            result = subprocess.run([shutil.which('bash'), '-c', command], input=payload.encode(), capture_output=True, cwd=tmp_path)
            self.stderr = result.stderr.decode()
            return SimpleNamespace(exit_status=result.returncode, stdout=result.stdout.decode(), stderr=result.stderr.decode())
    conn = Conn()
    target = tmp_path / f'acontrol-awg-settings-{token}.sh'
    with pytest.raises(HTTPException):
        await settings.install_runtime(conn, token, script)
    assert not target.exists()
    assert target.with_suffix('.sh.next').exists(), conn.stderr
    conn.truncated = False
    await settings.install_runtime(conn, token, script)
    assert target.read_text(encoding='utf-8') == script
    assert not target.with_suffix('.sh.next').exists()

async def test_ssh_repair_with_unchanged_policy_preserves_unresolved_journal(client, auth_headers, monkeypatch):
    from app.models import Server
    sid, _, _, _, old_profile = await prepare_case(client, auth_headers, monkeypatch)
    async with client.session_factory() as session:
        session.add(AwgSettingsChange(id='c'*32, server_id=sid, protocol='awg3', phase='prepared', payload={}))
        await session.commit()
    attempts = []
    @asynccontextmanager
    async def unavailable(server):
        attempts.append(server.ssh_port)
        raise OSError('synthetic unreachable old SSH endpoint')
        yield
    monkeypatch.setattr(awg_api, '_connect', unavailable)
    response = await client.patch(f'/api/servers/{sid}', headers=auth_headers,
        json={'name':'repaired-test', 'ssh_port':2222, 'torrent_block':False, 'torrent_autopause':False})
    assert response.status_code == 200, response.text
    assert response.json()['ssh_port'] == 2222 and attempts == []
    async with client.session_factory() as session:
        assert (await session.get(Server, sid)).ssh_port == 2222
        assert (await session.scalar(select(AwgConfig))).config == old_profile
        assert (await session.scalar(select(AwgSettingsChange))).phase == 'prepared'
    response = await client.patch(f'/api/servers/{sid}', headers=auth_headers, json={'torrent_block':True})
    assert response.status_code == 409 and attempts == [2222]
    async with client.session_factory() as session:
        assert (await session.get(Server, sid)).torrent_block is False
        assert (await session.scalar(select(AwgSettingsChange))).phase == 'prepared'
