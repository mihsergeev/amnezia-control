"""Native encrypted cascades: isolation, secrets and fail-closed routing."""

import base64
import json
import os
import shutil
import subprocess
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app import cascade, cascade_awg, cascadejob
from app.api import cascades as api
from app.models import Cascade, Server


def params():
    return cascade_awg.new_params() | {
        "entry_ip": "192.0.2.10", "exit_ip": "198.51.100.20",
        "entry_port": 51830, "exit_port": 51831,
        "entry_inner": "10.99.4.1", "exit_inner": "10.99.4.2",
    }


def test_keys_are_independent_and_profile_has_active_cps():
    p, other = params(), params()
    assert len({p[k] for k in ("entry_private", "exit_private", "psk")}) == 3
    assert p["entry_private"] != other["entry_private"]
    for key in ("entry_private", "entry_public", "exit_private", "exit_public", "psk"):
        assert len(base64.b64decode(p[key], validate=True)) == 32
    entry, exit_ = cascade_awg.config("entry", p), cascade_awg.config("exit", p)
    assert "AllowedIPs = 0.0.0.0/0" in entry
    assert "AllowedIPs = 10.99.4.1/32" in exit_
    assert "Endpoint = 198.51.100.20:51831" in entry
    assert "Endpoint = 192.0.2.10:51830" in exit_
    assert "FwMark = 1024" in entry and "I1 = <r 2>" in entry
    assert all(f"H{i} = {i}\n" in entry for i in range(1, 5))


@pytest.mark.skipif(shutil.which("bash") is None, reason="нужен bash")
def test_native_scripts_are_valid_shell_and_never_install_gre():
    p = params()
    scripts = [cascade_awg.runtime_script(), cascade_awg.preflight_command(),
               cascade.build_entry_script("awg", p["exit_ip"], 3, p),
               cascade.build_exit_script("awg", p["entry_ip"], 3, p),
               cascade.build_remove_entry("awg", 3), cascade.build_remove_exit("awg", 3)]
    for script in scripts:
        r = subprocess.run([shutil.which("bash"), "-n"], input=script, capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
    entry = scripts[2]
    assert "ip tunnel add" not in entry
    assert "AWG handshake or routing" in entry
    assert entry.index("AWG handshake or routing") < entry.index("[3/5]")
    assert entry.index(f"sudo {cascade_awg.SCRIPT} guard") < entry.index(
        f"sudo systemctl restart {cascade_awg.UNIT}")
    assert "AWG operation refused" not in entry  # runtime is encoded, not printed
    gateway = json.loads(cascade.entry_gateway_config("awg", p["exit_ip"], p))
    outbound = next(x for x in gateway["outbounds"] if x["tag"] == "exit")
    assert outbound["protocol"] == "freedom"
    assert outbound["streamSettings"]["sockopt"]["mark"] == 512


def test_failclosed_guards_and_cleanup_are_scoped():
    script = cascade_awg.runtime_script()
    assert 'rule filter OUTPUT -m mark --mark 0x200 ! -o "$IF" -j DROP' in script
    assert "pref 1011 fwmark 0x200 unreachable" in script
    assert "pref 1009 fwmark 0x400 table main" in script
    assert 'ip route replace default dev "$IF" src "$INNER" table 242' in script
    assert "ip route replace default table main" not in script
    assert "iptables -F" not in script and "docker restart" not in script
    assert "awg showconf" not in script and '"$IF" dump' not in script
    assert "--cap-drop ALL --cap-add NET_ADMIN" in script
    assert 'setconf "$IF" /etc/acontrol-awg/link.conf >/dev/null 2>&1' in script
    assert "acontrol-awg-link.service" in cascade_awg.preflight_command()
    assert "docker container inspect xray-cascade" in cascade_awg.preflight_command()
    assert "org.amnezia.control.cascade" in cascade_awg.preflight_command(3)
    assert "CID=3" in cascade_awg.remove(3)
    # An external symlink/helper must survive automatic old-script upgrades.
    upgrade = cascade.build_entry_upgrade()
    assert "test -L" in upgrade and "acontrol-awg-link.service" in upgrade
    assert "dev acawg" in upgrade


def _status(tmp_path, monkeypatch, *, age=20, guard=True, allowed="0.0.0.0/0", fail_config=False,
            down_routes: str | None = None):
    bin_ = tmp_path / "bin"
    bin_.mkdir(exist_ok=True)
    (tmp_path / "node.env").write_text(
        "CID=3\nROLE=entry\nPORT=51830\nPUBLIC=own-public\nPEER_PUBLIC=peer-public\n"
        "PEER=198.51.100.20\nINNER=10.99.4.1\nPEER_INNER=10.99.4.2\nEGRESS=eth0\n",
        encoding="utf-8", newline="\n")
    (bin_ / "docker").write_text(
        "#!/bin/sh\n"
        f'echo "docker $*" >> "{(tmp_path / "calls").as_posix()}"\n'
        "case \"$*\" in\n"
        + ("*setconf*) exit 1;;\n" if fail_config else "") +
        "'container ls '*) echo acontrol-cascade-awg;;\n"
        "*'index .Config.Labels'*) echo 3;;\n"
        "*'.State.Running'*) echo true;;\n"
        "*public-key*) echo own-public;;\n"
        "*' peers') echo peer-public;;\n"
        f"*allowed-ips*) printf 'peer-public\\t{allowed}\\n';;\n"
        "*fwmark*) echo 0x400;;\n"
        "*listen-port*) echo 51830;;\n"
        f"*latest-handshakes*) printf 'peer-public\\t{int(time.time())-age}\\n';;\n"
        "esac\n", encoding="utf-8", newline="\n")
    (bin_ / "ip").write_text(
        "#!/bin/sh\n"
        f'echo "ip $*" >> "{(tmp_path / "calls").as_posix()}"\n'
        "case \"$*\" in\n"
        "'rule show') printf '1010: from all fwmark 0x200 lookup 242\\n1011: from all fwmark 0x200 unreachable\\n';;\n"
        "'route show table 242') echo 'default dev acawg scope link';;\n"
        f"'-N -4 route show table all') echo '{down_routes or ''}';;\n"
        f"'route flush table 242') exit {0 if down_routes else 2};;\n"
        "esac\n", encoding="utf-8", newline="\n")
    (bin_ / "iptables").write_text(
        f'#!/bin/sh\necho "iptables $*" >> "{(tmp_path / "calls").as_posix()}"\nexit {0 if guard else 1}\n',
        encoding="utf-8", newline="\n")
    (bin_ / "flock").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8", newline="\n")
    (bin_ / "nft").write_text(
        f'#!/bin/sh\necho "nft $*" >> "{(tmp_path / "calls").as_posix()}"\n'
        'echo \'meta mark 0x00000200 oifname != "acawg" counter packets 0 bytes 0 drop\'\n',
        encoding="utf-8", newline="\n")
    for f in bin_.iterdir():
        f.chmod(0o755)
    script = cascade_awg.runtime_script().replace(cascade_awg.BASE, tmp_path.as_posix())
    script = script.replace("/run/acontrol-cascade-awg.lock", (tmp_path / "lock").as_posix())
    prefix = ""
    if os.name == "nt":
        prefix = f'export PATH="$(cygpath -u "{bin_.as_posix()}"):$PATH"\n'
    monkeypatch.setenv("PATH", str(bin_) + os.pathsep + os.environ["PATH"])
    action = "down" if down_routes is not None else "up" if fail_config else "status"
    r = subprocess.run([shutil.which("bash"), "-s", "--", action],
                       input=prefix + script, capture_output=True, text=True, timeout=10)
    if fail_config:
        assert r.returncode != 0
        return (tmp_path / "calls").read_text()
    assert r.returncode == 0, r.stderr
    if down_routes is not None:
        return (tmp_path / "calls").read_text()
    return cascade.parse_kv(r.stdout)


@pytest.mark.skipif(shutil.which("bash") is None, reason="нужен bash")
@pytest.mark.parametrize("routes", ["", "default dev acawg table 242 scope link"])
def test_runtime_down_accepts_already_missing_routing_table(tmp_path, monkeypatch, routes):
    calls = _status(tmp_path, monkeypatch, guard=False, down_routes=routes)
    assert ("ip route flush table 242" in calls) == bool(routes)


@pytest.mark.skipif(shutil.which("bash") is None, reason="нужен bash")
def test_runtime_proof_distinguishes_encryption_from_health(tmp_path, monkeypatch):
    good = _status(tmp_path, monkeypatch)
    assert good["encrypted"] == "yes" and good["awg"] == "yes"
    stale = _status(tmp_path, monkeypatch, age=400)
    assert stale["encrypted"] == "yes" and stale["awg"] == "no"
    unguarded = _status(tmp_path, monkeypatch, guard=False)
    assert unguarded["encrypted"] == "yes" and unguarded["awg"] == "no"
    wrong_peer_routes = _status(tmp_path, monkeypatch, allowed="10.99.4.2/32")
    assert wrong_peer_routes["encrypted"] == "unknown" and wrong_peer_routes["awg"] == "no"


@pytest.mark.skipif(shutil.which("bash") is None, reason="нужен bash")
def test_failed_device_configuration_leaves_kill_switch_installed(tmp_path, monkeypatch):
    calls = _status(tmp_path, monkeypatch, fail_config=True)
    assert calls.index("iptables -w -t filter -C OUTPUT") < calls.index("awg setconf")
    assert "docker start" not in calls and "docker rm" not in calls
    assert calls.index("nft -f -") < calls.index("awg setconf")
    assert "docker exec acontrol-cascade-awg awg setconf" in calls
    assert "delete table" not in calls and "-D OUTPUT" not in calls


def test_health_rejects_missing_awg_proof_and_stale_encrypted_gre():
    kv = {"gw": "yes", "tproxy": "active", "rule": "yes", "awg": "yes"}
    result = {"egress": "198.51.100.20", "client": "198.51.100.20", "direct": "203.0.113.10"}
    assert cascade.health("awg", kv, result) == (True, "")
    assert cascade.health("awg", kv | {"awg": "no"}, result)[0] is False
    assert cascade.health("gre", kv | {"tun": "UNKNOWN", "linkhealth": "no"}, result)[0] is False


@pytest.mark.skipif(shutil.which("bash") is None, reason="нужен bash")
@pytest.mark.parametrize("collision", ["", "xray-cascade", cascade_awg.CONTAINER])
def test_preflight_rejects_manual_or_unlabelled_carrier(tmp_path, monkeypatch, collision):
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    scripts = {
        "sudo": '#!/bin/sh\nexec "$@"\n',
        "docker": ('#!/bin/sh\n' +
                   (f'[ "$*" = "container inspect {collision}" ] && exit 0\n' if collision else '') +
                   'exit 1\n'),
        "ip": '#!/bin/sh\nexit 1\n',
        "nft": '#!/bin/sh\nexit 1\n',
    }
    for name, data in scripts.items():
        p = bin_ / name
        p.write_text(data, encoding="utf-8", newline="\n")
        p.chmod(0o755)
    command = cascade_awg.preflight_command().replace(cascade_awg.BASE, (tmp_path / "state").as_posix())
    prefix = f'export PATH="$(cygpath -u "{bin_.as_posix()}"):$PATH"\n' if os.name == "nt" else ""
    monkeypatch.setenv("PATH", str(bin_) + os.pathsep + os.environ["PATH"])
    p = subprocess.run([shutil.which("bash"), "-c", prefix + command], capture_output=True, text=True, timeout=10)
    assert (p.returncode == 0) is (not collision), p.stderr
    assert ("CASCADE_AVAILABLE" in p.stdout) is (not collision)


async def test_create_awg_preserves_secrets_in_storage_only(client, auth_headers, session_factory, monkeypatch):
    async with session_factory() as session:
        nodes = [Server(name=f"node-{n}", host=f"192.0.2.{n}", last_check_ok=True) for n in (10, 20)]
        session.add_all(nodes)
        await session.commit()
        entry, exit_ = [n.id for n in nodes]

    @asynccontextmanager
    async def locked(server):
        yield object()

    async def addresses(*args):
        return "192.0.2.10", "198.51.100.20"

    async def available(*args):
        return None

    async def port(conn, requested, reserved=None):
        return requested or 51830

    monkeypatch.setattr(api, "_locked", locked)
    monkeypatch.setattr(api, "_addresses", addresses)
    monkeypatch.setattr(api, "_entry_creation_available", available)
    monkeypatch.setattr(api, "_awg_preflight", available)
    monkeypatch.setattr(api, "_operation_available", available)
    monkeypatch.setattr(api, "_awg_port", port)
    monkeypatch.setattr(cascadejob, "spawn", lambda *args: None)
    r = await client.post("/api/cascades", headers=auth_headers, json={
        "entry_id": entry, "exit_id": exit_, "transport": "awg", "exit_port": 51831})
    assert r.status_code == 202, r.text
    assert r.json()["entry_port"] == 51830 and r.json()["exit_port"] == 51831
    assert r.json()["encrypted"] is None
    async with session_factory() as session:
        row = await session.scalar(select(Cascade))
        stored = json.loads(row.params)
    for key in ("entry_private", "exit_private", "psk"):
        assert stored[key] not in r.text
    assert "params" not in r.json()
    cid = r.json()["id"]
    installed = await client.post(f"/api/cascades/{cid}/install", headers=auth_headers)
    assert installed.status_code == 202, installed.text
    async with session_factory() as session:
        assert json.loads((await session.get(Cascade, cid)).params) == stored


async def test_external_underlay_cannot_be_deleted_with_force(client, auth_headers, session_factory, monkeypatch):
    async with session_factory() as session:
        nodes = [Server(name=f"node-{n}", host=f"192.0.2.{n}") for n in (10, 20)]
        session.add_all(nodes)
        await session.flush()
        c = Cascade(entry_server_id=nodes[0].id, exit_server_id=nodes[1].id,
                    transport="gre", status="ready")
        session.add(c)
        await session.commit()
        cid = c.id

    class Conn:
        async def run(self, *args, **kwargs):
            return type("R", (), {"stdout": "CASCADE_EXTERNAL_UNDERLAY\n", "stderr": ""})()

    @asynccontextmanager
    async def locked(server):
        yield Conn()

    monkeypatch.setattr(api, "_locked", locked)
    r = await client.delete(f"/api/cascades/{cid}?force=true", headers=auth_headers)
    assert r.status_code == 409
    async with session_factory() as session:
        assert await session.get(Cascade, cid) is not None


async def test_missing_runtime_proof_clears_stored_crypto(client, auth_headers, session_factory, monkeypatch):
    async with session_factory() as session:
        nodes = [Server(name=f"node-{n}", host=f"192.0.2.{n}") for n in (10, 20)]
        session.add_all(nodes)
        await session.flush()
        c = Cascade(entry_server_id=nodes[0].id, exit_server_id=nodes[1].id,
                    transport="awg", status="ready", result=json.dumps({
                        "encryption": "awg", "encrypted": True, "handshake_age": 10}))
        session.add(c)
        await session.commit()
        cid = c.id

    class Conn:
        async def run(self, *args, **kwargs):
            return type("R", (), {"stdout": "CASCADE_GW=yes\nCASCADE_TPROXY=active\nCASCADE_RULE=yes\n"})()

    @asynccontextmanager
    async def locked(server):
        yield Conn()

    monkeypatch.setattr(api, "_locked", locked)
    checked = await client.post(f"/api/cascades/{cid}/check", headers=auth_headers)
    assert checked.status_code == 200
    assert checked.json()["encrypted"] is None and checked.json()["encryption"] == "unknown"
    shown = await client.get(f"/api/cascades/{cid}", headers=auth_headers)
    assert shown.json()["encrypted"] is None and shown.json()["encryption"] == "unknown"
    assert shown.json()["result"]["handshake_age"] is None


@pytest.mark.parametrize("body", [
    {"transport": "awg", "entry_port": 0}, {"transport": "awg", "exit_port": 65536},
    {"transport": "gre", "entry_port": 51830}, {"transport": "vless", "exit_port": 51830},
])
async def test_invalid_port_contract_fails_before_ssh(client, auth_headers, body):
    r = await client.post("/api/cascades", headers=auth_headers,
                          json={"entry_id": 1, "exit_id": 2, **body})
    assert r.status_code == 422


async def test_port_conflict_is_rejected_without_persisting_keys(monkeypatch):
    async def busy(*args, **kwargs):
        return "test listener"
    monkeypatch.setattr(api.deploy, "port_owner", busy)
    with pytest.raises(api.HTTPException) as exc:
        await api._awg_port(object(), 51830)
    assert exc.value.status_code == 409


def test_stored_result_does_not_infer_encryption_from_transport():
    c = Cascade(id=3, entry_server_id=1, exit_server_id=2, transport="awg", status="ready",
                error="", params=json.dumps(params()), result="{}", probe="{}",
                created_at=datetime.now(timezone.utc))
    assert api._out(c).encrypted is None
    c.result = json.dumps({"encryption": "awg", "encrypted": True})
    assert api._out(c).encrypted is True


@pytest.mark.parametrize("info", ["[]", "null", '{"cascade_link":[]}', '{"cascade_link":null}'])
def test_malformed_server_runtime_metadata_is_unknown(info):
    c = Cascade(id=3, entry_server_id=1, exit_server_id=2, transport="gre", status="ready",
                error="", params="{}", result="{}", probe="{}", created_at=datetime.now(timezone.utc))
    entry = Server(last_check_at=datetime.now(timezone.utc), last_check_info=info)
    assert api._out(c, entry).encrypted is None


def test_future_or_old_server_check_cannot_override_encryption():
    c = Cascade(id=3, entry_server_id=1, exit_server_id=2, transport="gre", status="ready",
                error="", params="{}", result="{}", probe="{}", created_at=datetime.now(timezone.utc))
    now = datetime.now(timezone.utc)
    entry = Server(last_check_at=now, last_check_info=json.dumps({
        "cascade_link": {"transport": "awg", "encrypted": True}}))
    assert api._out(c, entry).encrypted is True
    for delta in (timedelta(minutes=1), timedelta(minutes=-6)):
        entry.last_check_at = now + delta
        assert api._out(c, entry).encrypted is None
