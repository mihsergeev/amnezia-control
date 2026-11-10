import asyncio
import base64
import importlib.util
import json
import os
import pathlib
import re
import shutil
import shlex
import subprocess
import sys
from types import SimpleNamespace
from contextlib import asynccontextmanager

import pytest
import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import select

from app import cascade, cascade_awg, cascade_exit, cascade_lock, cascadejob, deploy, nodelock, server_ops
from app.api import cascades as api
from app.models import Cascade, Server


def params(transport="gre", owner="a", net="10.99.30.0/30"):
    result = {"runtime_layout": 2, "runtime_owner": owner * 32, "inner_net": net,
              "entry_ip": "192.0.2.10", "exit_ip": "198.51.100.20", "gre_key": 123456,
              "port": 8443, "sni": "www.example.com", "uuid": "11111111-2222-3333-4444-555555555555",
              "private_key": "fixture-private", "public_key": "fixture-public", "short_id": "0123456789abcdef"}
    if transport == "awg":
        result |= cascade_awg.new_params() | {"entry_port": 51830, "exit_port": 51831}
    return result


@pytest.mark.parametrize("transport", ["awg", "gre", "vless"])
def test_shared_exit_resources_and_cleanup_are_per_pair(transport):
    first, second = params(transport), params(transport, "b", "10.99.31.0/30")
    a = cascade.build_exit_script(transport, first["entry_ip"], 7, first)
    b = cascade.build_exit_script(transport, second["entry_ip"], 8, second)
    remove = cascade.build_remove_exit(transport, 7, first)
    assert "/acontrol-cascade-exits/7" in a and "/acontrol-cascade-exits/8" in b
    assert "acontrol-cascade-exit-7" in remove
    assert "acontrol-cascade-exit-8" not in remove
    assert "rm -rf /opt/acontrol/cascade" not in remove
    assert "ufw route delete" not in remove
    assert cascade_exit.paths(7)["interface"] != cascade_exit.paths(8)["interface"]
    assert cascade_exit.paths(7)["interface_gre"] != cascade_exit.paths(8)["interface_gre"]
    if transport == "gre":
        entry = cascade.build_entry_script(transport, first["exit_ip"], 7, first)
        assert "KEY=123456" in entry
    # Verify actual shell bodies, including those encoded for remote writes.
    scripts = [a, b, remove, cascade.build_entry_script(transport, first["exit_ip"], 7, first)]
    if shutil.which("bash"):
        encoded = [base64.b64decode(s).decode() for text in scripts
                   for s in re.findall(r"echo ([A-Za-z0-9+/=]+) \| base64 -d", text)]
        scripts += [s for s in encoded if s.startswith("#!/")]
        for script in scripts:
            result = subprocess.run([shutil.which("bash"), "-n"], input=script, text=True, capture_output=True)
            assert result.returncode == 0, result.stderr


def test_legacy_layout_does_not_migrate_or_remove_scoped_siblings():
    assert cascade_exit.network(255, {}) == cascade.inner_net(255)
    legacy = cascade.build_remove_exit("gre", 7)
    assert "rm -rf /opt/acontrol/cascade" in legacy
    assert "acontrol-cascade-exits" not in legacy


def test_subnet_reservations_include_legacy_and_failed_rows():
    legacy = Cascade(id=254, transport="gre", params="{}")
    failed = Cascade(id=255, transport="awg", status="error", params=json.dumps(params("awg",net="10.99.2.0/30")))
    assert api._inner_reservation([legacy, failed]) == "10.99.3.0/30"
    assert api._reserved_ports([failed], "awg") == {51831}


@pytest.mark.parametrize("foreign", [True, False])
def test_subnet_guard_preserves_foreign_routes_but_allows_own_retry(monkeypatch, foreign):
    text=cascade_exit.network_preflight(7,'gre',params(),'exit')
    words=shlex.split(text);index=words.index('-c');code=words[index+1]
    monkeypatch.setattr(sys,'argv',['worker',*words[index+2:words.index('||')]])
    def output(args,**kwargs):
        if 'address' in args:return b'[]'
        return json.dumps([{'dst':'10.99.30.1/32','dev':'other0' if foreign else 'acgx7'}]).encode()
    monkeypatch.setattr(subprocess,'check_output',output)
    if foreign:
        with pytest.raises(SystemExit) as error:exec(code,{})
        assert error.value.code==73
    else:exec(code,{})


def test_exit_nonce_rejects_reused_id_before_any_runtime_mutation(tmp_path,monkeypatch):
    text=cascade_exit.preflight(7,'gre',params())
    words=shlex.split(text);index=words.index('-c');code=words[index+1]
    args=words[index+2:words.index('||')];base=tmp_path/'pair';base.mkdir()
    marker=cascade_exit._owner(7,'gre',params(owner='b'))
    (base/'owner.json').write_text(json.dumps(marker));args[0]=str(base)
    monkeypatch.setattr(sys,'argv',['worker',*args])
    calls=[]
    monkeypatch.setattr(subprocess,'run',lambda *a,**k:calls.append(a))
    with pytest.raises(SystemExit) as error:exec(code,{})
    assert error.value.code==73 and calls==[]


def test_docker_transport_error_is_not_treated_as_missing_container(tmp_path,monkeypatch):
    words=shlex.split(cascade_exit.preflight(7,'gre',params()));index=words.index('-c');code=words[index+1]
    args=words[index+2:words.index('||')];args[0]=str(tmp_path/'missing-pair')
    monkeypatch.setattr(sys,'argv',['worker',*args]);monkeypatch.setattr(shutil,'which',lambda name:'docker')
    monkeypatch.setattr(subprocess,'run',lambda *a,**k:SimpleNamespace(returncode=1,stdout=b'',stderr=b'permission denied connecting to daemon'))
    with pytest.raises(SystemExit) as error:exec(code,{})
    assert error.value.code==73
    assert not (tmp_path/'missing-pair').exists()


def test_cascade_real_client_probe_includes_only_labelled_native_containers():
    command=cascade.build_check_command()
    assert 'acontrol-wireguard' in command and 'acontrol-openvpn-native' in command
    assert 'org.amnezia.control.native' in command
    assert 'wireguard|true' in command and 'openvpn-native|true' in command


async def test_remote_installer_busy_survives_empty_task_registry_and_force_delete(
    client,auth_headers,session_factory,monkeypatch,caplog
):
    a,_,x,_=await setup_nodes(session_factory)
    async with session_factory() as session:
        row=Cascade(entry_server_id=a,exit_server_id=x,transport='gre',status='error',params=json.dumps(params()))
        session.add(row);await session.commit();cid=row.id
    class Conn:
        def __init__(self, sid):
            self.sid = sid

        async def run(self, command, **kwargs):
            assert "CASCADE_OPERATION_FREE" in command
            assert "AC_CASCADE_OPERATION_PAYLOAD" not in command
            if self.sid == x:
                return SimpleNamespace(stdout='CASCADE_OPERATION_BUSY\n',
                                       stderr='private-ssh-output', exit_status=75)
            return SimpleNamespace(stdout='CASCADE_OPERATION_FREE\n', stderr='', exit_status=0)
    @asynccontextmanager
    async def locked(server):yield Conn(server.id)
    monkeypatch.setattr(api,'_locked',locked)
    monkeypatch.setattr(cascadejob,'_tasks',{})
    retry=await client.post(f'/api/cascades/{cid}/install',headers=auth_headers)
    assert retry.status_code==409
    assert "выходном сервере" in retry.json()["detail"]
    deleted=await client.delete(f'/api/cascades/{cid}?force=true',headers=auth_headers)
    assert deleted.status_code==409
    assert "выходном сервере" in deleted.json()["detail"]
    assert f"reason=cascade_remote_install_running cascade_id={cid}" in caplog.text
    assert "side=exit" in caplog.text and "private-ssh-output" not in caplog.text
    async with session_factory() as session:
        assert (await session.get(Cascade,cid)).status=='error'


def test_operation_wrapper_is_valid_shell_and_keeps_config_out_of_python_argv():
    script=cascade_lock.wrap(7,'echo harmless', 'a'*32,generation='b'*32)
    if shutil.which('bash'):
        result=subprocess.run([shutil.which('bash'),'-n'],input=script,capture_output=True,text=True)
        assert result.returncode==0,result.stderr
    assert 'os.set_inheritable(fd,True)' in script
    assert "<<'AC_CASCADE_OPERATION_PAYLOAD'" in script
    assert 'CASCADE_OPERATION_BUSY' in script


@pytest.mark.skipif(shutil.which('bash') is None,reason='Bash is required')
def test_first_gre_exit_start_brings_device_up_before_peer_route(tmp_path,monkeypatch):
    bin_=tmp_path/'bin';bin_.mkdir();created=tmp_path/'created';up=tmp_path/'up'
    (tmp_path/'exit.env').write_text('TRANSPORT=gre\nOWNER='+('a'*32)+'\nIF=acgx7\nLOCAL=192.0.2.10\nPEER=198.51.100.20\nKEY=123456\nINNER=10.99.30.2\nPEER_INNER=10.99.30.1\nEGRESS=eth0\n',encoding='utf-8',newline='\n')
    ip='#!/bin/sh\ncase "$*" in\n"link show acgx7") test -f '+shlex.quote(created.as_posix())+';;\n"link add acgx7 "*) touch '+shlex.quote(created.as_posix())+';;\n"link set acgx7 mtu 1476 up") touch '+shlex.quote(up.as_posix())+';;\n"route replace "*) test -f '+shlex.quote(up.as_posix())+' || { echo "Device for nexthop is not up" >&2; exit 2; };;\n*) exit 0;;\nesac\n'
    for name,text in {'ip':ip,'flock':'#!/bin/sh\nexit 0\n','docker':'#!/bin/sh\nexit 1\n','sysctl':'#!/bin/sh\nexit 0\n','iptables':'#!/bin/sh\nexit 0\n'}.items():
        path=bin_/name;path.write_text(text,encoding='utf-8',newline='\n');path.chmod(0o755)
    monkeypatch.setenv('PATH',str(bin_)+os.pathsep+os.environ['PATH'])
    script=cascade_exit.RUNTIME.replace('@BASE@',tmp_path.as_posix()).replace('@LOCK@',(tmp_path/'lock').as_posix()).replace('@XRAY@','fixture-image')
    prefix=f'export PATH="$(cygpath -u "{bin_.as_posix()}"):$PATH"\n' if os.name=='nt' else ''
    result=subprocess.run([shutil.which('bash'),'-s','--','up'],input=prefix+script,capture_output=True,text=True,timeout=10)
    assert result.returncode==0,result.stderr
    assert up.is_file()


@pytest.mark.skipif(sys.platform=='win32',reason='real fcntl/exec integration requires Linux')
def test_process_lock_and_generation_prevent_restart_delete_orphans(tmp_path):
    owner='a'*32;old='b'*32;new='c'*32;base=str(tmp_path/'persistent-locks')
    def program(mode,generation=''):
        return cascade_lock._program(7,mode=mode,owner=owner,generation=generation,base=base)
    def run(mode,generation='',payload=''):
        return subprocess.run([sys.executable,'-c',program(mode,generation)],input=payload,text=True,capture_output=True,timeout=10)
    assert run('arm',old).returncode==0
    # Removal supersedes an armed but not-yet-started detached child.
    deleted=tmp_path/'deleted';orphan=tmp_path/'orphan'
    assert run('remove',payload='touch '+shlex.quote(str(deleted))+'\n').returncode==0
    late=run('run',old,'touch '+shlex.quote(str(orphan))+'\n')
    assert late.returncode==73 and not orphan.exists()
    assert run('arm',new).returncode==0
    assert run('run',old,'touch '+shlex.quote(str(orphan))+'\n').returncode==73
    assert not orphan.exists()
    # A new Python process has no shared in-memory locks, yet cannot remove a
    # running installer. The locked descriptor survives exec into its Bash.
    release=tmp_path/'release'
    process=subprocess.Popen([sys.executable,'-c',program('run',new)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
    process.stdin.write('echo ready\nwhile [ ! -e '+shlex.quote(str(release))+' ]; do sleep 0.05; done\n');process.stdin.close()
    try:
        assert process.stdout.readline().strip()=='ready'
        busy=run('remove',payload='touch '+shlex.quote(str(orphan))+'\n')
        assert busy.returncode==75 and not orphan.exists()
        assert run('check').returncode==75
    finally:
        release.touch();process.wait(timeout=10)
    assert run('check').returncode==0


@pytest.mark.skipif(sys.platform == 'win32', reason='real fcntl/exec integration requires Linux')
def test_reused_id_can_retry_or_remove_without_touching_foreign_runtime(tmp_path):
    base = tmp_path / 'locks'
    old_owner, new_owner, generation = 'a' * 32, 'b' * 32, 'c' * 32

    def run(mode, owner, payload=''):
        program = cascade_lock._program(1, mode=mode, owner=owner, generation=generation, base=str(base))
        return subprocess.run([sys.executable, '-c', program], input=payload, text=True,
                              capture_output=True, timeout=10)

    assert run('arm', old_owner).returncode == 0
    for mode in ('check', 'arm', 'remove'):
        assert run(mode, new_owner).returncode == 73
    # A failed teardown still leaves a revocation marker to block late workers.
    assert run('remove', old_owner, 'exit 1\n').returncode == 1
    tombstone = (base / '1.json').read_bytes()

    assert run('check', new_owner).stdout.strip() == 'CASCADE_OPERATION_FREE'
    removed = run('remove', new_owner, 'echo UNEXPECTED_PAYLOAD\nexit 1\n')
    assert removed.returncode == 0 and removed.stdout.strip() == 'CASCADE_REMOVED=yes'
    assert (base / '1.json').read_bytes() == tombstone
    assert run('run', old_owner, 'echo UNEXPECTED_PAYLOAD\n').returncode == 73
    assert run('edit', new_owner, 'echo UNEXPECTED_PAYLOAD\n').returncode == 73
    assert run('arm', new_owner).returncode == 0
    assert run('run', old_owner).returncode == 73
    assert run('run', new_owner, 'echo INSTALLED\n').stdout.strip() == 'INSTALLED'


async def setup_nodes(factory, count=4):
    async with factory() as session:
        rows = [Server(name=f"node-{i}", host=f"192.0.2.{10+i}", last_check_ok=True) for i in range(count)]
        session.add_all(rows); await session.commit()
        return [x.id for x in rows]


def remote_mocks(monkeypatch):
    @asynccontextmanager
    async def locked(server):
        async with nodelock.hold("cascade", server.id):
            await asyncio.sleep(0.005)
            yield object()
    async def addresses(conn, entry, exit_):return entry.host, exit_.host
    async def available(*args):return None
    async def no_owner(*args, **kwargs):return None
    monkeypatch.setattr(api, "_locked", locked)
    monkeypatch.setattr(api, "_addresses", addresses)
    monkeypatch.setattr(api, "_entry_creation_available", available)
    monkeypatch.setattr(api, "_awg_preflight", available)
    monkeypatch.setattr(deploy, "port_owner", no_owner)
    monkeypatch.setattr(cascadejob, "spawn", lambda *args: None)


@pytest.mark.parametrize("transport", ["awg", "vless", "gre"])
async def test_two_entries_reserve_distinct_exit_resources_before_any_listener(
    client, auth_headers, session_factory, monkeypatch, transport
):
    a,b,x,_ = await setup_nodes(session_factory)
    remote_mocks(monkeypatch)
    responses = await asyncio.gather(*(client.post('/api/cascades',headers=auth_headers,json={
        "entry_id":e,"exit_id":x,"transport":transport}) for e in (a,b)))
    assert [r.status_code for r in responses] == [202,202]
    async with session_factory() as session:
        rows=list(await session.scalars(select(Cascade)))
    values=[json.loads(c.params) for c in rows]
    assert len({p['runtime_owner'] for p in values})==2
    assert len({p['inner_net'] for p in values})==2
    if transport!='gre':
        key='exit_port' if transport=='awg' else 'port'
        assert len({p[key] for p in values})==2
    assert all(p['runtime_layout']==2 for p in values)
    reused=await client.post('/api/cascades',headers=auth_headers,json={"entry_id":a,"exit_id":b,"transport":"gre"})
    assert reused.status_code==409


async def test_physical_exit_alias_and_reversed_roles_cannot_bypass_locks(
    client, auth_headers, session_factory, monkeypatch
):
    a,b,x,alias=await setup_nodes(session_factory)
    async with session_factory() as session:
        node=await session.get(Server,alias);node.host=(await session.get(Server,x)).host
        session.add(Cascade(entry_server_id=a,exit_server_id=x,transport="gre",status="ready"));await session.commit()
    remote_mocks(monkeypatch)
    for entry,exit_ in ((b,alias),(x,b),(b,a)):
        result=await client.post('/api/cascades',headers=auth_headers,json={"entry_id":entry,"exit_id":exit_,"transport":"gre"})
        assert result.status_code==409


async def test_concurrent_aliases_of_the_same_physical_exit_conflict(
    client, auth_headers, session_factory, monkeypatch,
):
    a, b, exit_id, alias_id = await setup_nodes(session_factory)
    async with session_factory() as session:
        (await session.get(Server, alias_id)).host = (await session.get(Server, exit_id)).host
        await session.commit()
    remote_mocks(monkeypatch)
    barrier = asyncio.Barrier(2)
    spawns = []

    async def addresses(conn, entry, exit_):
        await asyncio.wait_for(barrier.wait(), timeout=5)
        return entry.host, exit_.host

    monkeypatch.setattr(api, "_addresses", addresses)
    monkeypatch.setattr(cascadejob, "spawn", lambda _app, cid: spawns.append(cid))
    results = await asyncio.gather(*(
        client.post("/api/cascades", headers=auth_headers, json={
            "entry_id": entry, "exit_id": exit_, "transport": "gre", "entry_country": "DE",
        })
        for entry, exit_ in ((a, exit_id), (b, alias_id))
    ))
    assert sorted(result.status_code for result in results) == [202, 409]
    async with session_factory() as session:
        assert [row.id for row in await session.scalars(select(Cascade))] == spawns
    assert len(spawns) == 1


async def test_create_request_replay_returns_existing_job(
    client, auth_headers, session_factory, monkeypatch,
):
    entry, exit_, other, _ = await setup_nodes(session_factory)
    remote_mocks(monkeypatch)
    spawns = []
    monkeypatch.setattr(cascadejob, "spawn", lambda _app, cid: spawns.append(cid))
    monkeypatch.setattr(cascadejob, "running", lambda cid: cid in spawns)
    payload = {"entry_id": entry, "exit_id": exit_, "transport": "gre", "entry_country": "DE",
               "request_id": "da93395d-a562-46b5-8f4a-515cf9bdffbe"}
    first, retry = await asyncio.gather(*(
        client.post("/api/cascades", headers=auth_headers, json=payload) for _ in range(2)
    ))
    assert first.status_code == retry.status_code == 202
    cid = first.json()["id"]
    assert retry.json()["id"] == cid and spawns == [cid]
    async with session_factory() as session:
        (await session.get(Cascade, cid)).status = "ready"
        await session.commit()
    replay = await client.post("/api/cascades", headers=auth_headers, json=payload)
    assert replay.status_code == 202 and replay.json()["status"] == "ready"
    conflict = await client.post("/api/cascades", headers=auth_headers, json=payload | {"exit_id": other})
    assert conflict.status_code == 409 and spawns == [cid]


async def test_delete_one_shared_pair_keeps_sibling_metadata_and_exit_script_scoped(
    client, auth_headers, session_factory, monkeypatch
):
    a,b,x,_=await setup_nodes(session_factory);saved=params();sibling=params(owner='b',net='10.99.31.0/30')
    async with session_factory() as session:
        first=Cascade(entry_server_id=a,exit_server_id=x,transport="gre",params=json.dumps(saved),status="ready")
        other=Cascade(entry_server_id=b,exit_server_id=x,transport="gre",params=json.dumps(sibling),status="ready")
        session.add_all([first,other]);await session.commit();cid,oid=first.id,other.id
    scripts=[]
    async def dismantle(server,script,cascade_id,side):scripts.append((server.id,script));return ''
    async def check(*args):return None
    async def remove_check(*args):return ''
    monkeypatch.setattr(api,'_dismantle',dismantle);monkeypatch.setattr(server_ops,'run_check',check)
    monkeypatch.setattr(api,'_check_remove_node',remove_check)
    result=await client.delete(f'/api/cascades/{cid}',headers=auth_headers)
    assert result.status_code==204
    async with session_factory() as session:
        assert await session.get(Cascade,cid) is None
        assert json.loads((await session.get(Cascade,oid)).params)==sibling
    exit_script=next(script for sid,script in scripts if sid==x)
    assert f'acontrol-cascade-exits/{cid}' in exit_script
    assert f'acontrol-cascade-exits/{oid}' not in exit_script
    assert 'ufw route delete' not in exit_script


async def test_jobs_share_exit_lock_for_the_complete_two_phase_workflow(session_factory,monkeypatch):
    a,b,x,_=await setup_nodes(session_factory)
    async with session_factory() as session:
        rows=[Cascade(entry_server_id=e,exit_server_id=x,transport='gre') for e in (a,b)]
        session.add_all(rows);await session.commit();ids=[c.id for c in rows]
    active=0;peak=0
    async def job(*args):
        nonlocal active,peak
        active+=1;peak=max(peak,active);await asyncio.sleep(.03);active-=1
    monkeypatch.setattr(cascadejob,'_run_locked',job)
    await asyncio.gather(*(cascadejob._run(cid,session_factory,None) for cid in ids))
    assert peak==1


def test_shared_exit_migration_keeps_data_and_blocks_unsafe_old_panel(tmp_path,monkeypatch):
    path=pathlib.Path(__file__).parents[1]/'alembic/versions/0032_shared_cascade_exit.py'
    spec=importlib.util.spec_from_file_location('shared_exit_migration',path);migration=importlib.util.module_from_spec(spec);spec.loader.exec_module(migration)
    engine=sa.create_engine('sqlite:///'+str(tmp_path/'migration.db'))
    metadata=sa.MetaData();table=sa.Table('cascades',metadata,sa.Column('id',sa.Integer,primary_key=True),sa.Column('entry_server_id',sa.Integer,unique=True),sa.Column('exit_server_id',sa.Integer,unique=True),sa.Column('params',sa.Text))
    metadata.create_all(engine)
    with engine.begin() as conn:
        conn.execute(table.insert(),{'id':1,'entry_server_id':1,'exit_server_id':9,'params':'{}'})
        monkeypatch.setattr(migration,'op',Operations(MigrationContext.configure(conn)))
        migration.upgrade()
        assert conn.execute(sa.text('SELECT params FROM cascades WHERE id=1')).scalar()=='{}'
        conn.execute(table.insert(),{'id':2,'entry_server_id':2,'exit_server_id':9,'params':'{}'})
        with pytest.raises(RuntimeError):migration.downgrade()
        conn.execute(sa.text('DELETE FROM cascades WHERE id=2'))
        conn.execute(sa.text('UPDATE cascades SET params=:p'),{'p':json.dumps({'runtime_layout':2})})
        with pytest.raises(RuntimeError):migration.downgrade()
        conn.execute(sa.text("UPDATE cascades SET params='{}'"));migration.downgrade()
        assert any(c['column_names']==['exit_server_id'] for c in sa.inspect(conn).get_unique_constraints('cascades'))
    engine.dispose()
