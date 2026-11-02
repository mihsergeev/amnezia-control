"""Удаление протокола с ноды и массовый отзыв из карточки протокола."""

import json
import asyncio
from contextlib import asynccontextmanager
import os
import shlex
import shutil
import subprocess
import sys

import pytest
from sqlalchemy import select

from app import awg, cascade_alias, deploy, expiry, nodelock, pausestore, protoremove, sshops
from app.models import AwgConfig, AwgNote, ClientLimit, ClientName, PausedClient, Server


class _Conn:
    """Нода: запоминает команды, на удаление отвечает заданным выводом."""

    def __init__(self, out: str):
        self.out = out
        self.cmds: list[str] = []

    async def run(self, cmd, input=None, check=False):  # noqa: A002
        self.cmds.append(cmd)
        return type("R", (), {"exit_status": 0, "stdout": self.out, "stderr": ""})()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False


def _legacy_only(monkeypatch, found):
    async def detect(conn):
        return found

    monkeypatch.setattr(awg, "detect_awg_containers", detect)


async def test_remove_snapshots_then_moves_config_dirs(monkeypatch):
    _legacy_only(monkeypatch, {"new": "amnezia-awg2", "legacy": "amnezia-awg"})
    snaps = []

    async def snap(conn, tag, keep=10, container=None):
        snaps.append((tag, container))
        return "20261027-120000"

    monkeypatch.setattr(deploy, "snapshot_config", snap)
    conn = _Conn("REMOVED\nMOVED /opt/amnezia/awg.removed-20261027-120001\nIMAGE amnezia-awg\n")
    res = await protoremove.remove(conn, "awglegacy")
    # удаляется именно legacy, снимок снят до удаления и с того же контейнера
    assert snaps == [("awg", "amnezia-awg")]
    assert res.container == "amnezia-awg" and res.kind == "awglegacy"
    assert res.moved == ["/opt/amnezia/awg.removed-20261027-120001"]
    assert res.image == "amnezia-awg"
    assert "C=amnezia-awg;" in conn.cmds[0]
    # переименовываются только каталоги Amnezia и панели
    assert "/opt/amnezia/*|/opt/acontrol/*)" in conn.cmds[0]


async def test_remove_aborts_without_snapshot(monkeypatch):
    _legacy_only(monkeypatch, {"new": "amnezia-awg2", "legacy": None})

    async def no_snap(*a, **k):
        return None

    monkeypatch.setattr(deploy, "snapshot_config", no_snap)
    conn = _Conn("REMOVED\n")
    with pytest.raises(protoremove.RemoveError, match="снимок"):
        await protoremove.remove(conn, "awg")
    assert conn.cmds == []  # до docker rm дело не дошло


async def test_lone_legacy_is_found_under_awg_tab(monkeypatch):
    _legacy_only(monkeypatch, {"new": None, "legacy": "amnezia-awg"})
    assert await protoremove.find_container(_Conn(""), "awg") == ("amnezia-awg", "awglegacy")
    assert await protoremove.find_container(_Conn(""), "awglegacy") == (
        "amnezia-awg", "awglegacy")
    _legacy_only(monkeypatch, {"new": "amnezia-awg2", "legacy": None})
    assert await protoremove.find_container(_Conn(""), "awglegacy") is None


async def _server(client, headers) -> int:
    r = await client.post(
        "/api/servers",
        json={"name": "vpn-a", "host": "203.0.113.10", "ssh_port": 22, "ssh_user": "acontrol"},
        headers=headers,
    )
    return r.json()["id"]


async def test_api_remove_requires_password(client, auth_headers, monkeypatch):
    sid = await _server(client, auth_headers)
    called = []

    async def remove(conn, protocol):
        called.append(protocol)

    monkeypatch.setattr(protoremove, "remove", remove)
    r = await client.post(
        f"/api/servers/{sid}/protocols/awglegacy/remove",
        json={"password": "wrong"}, headers=auth_headers,
    )
    assert r.status_code == 403 and called == []
    r = await client.post(
        f"/api/servers/{sid}/protocols/bogus/remove",
        json={"password": "testpass"}, headers=auth_headers,
    )
    assert r.status_code == 400


async def test_api_remove_cleans_only_that_protocol(
    client, auth_headers, session_factory, monkeypatch
):
    sid = await _server(client, auth_headers)
    route = {"transport": "vless", "security": "reality", "network": "tcp",
             "exit_host": "203.0.113.20", "exit_port": 443}
    async with session_factory() as s:
        server = await s.get(Server, sid)
        server.last_check_info = json.dumps({"manual_cascade": route | {"exit_country": "KZ"}})
        await cascade_alias.set_name(s, server, "vpn-exit (transit)")
        for proto in ("awglegacy", "awg"):
            s.add(AwgConfig(server_id=sid, public_key=f"K-{proto}", name="x",
                            config="[Interface]", protocol=proto))
            s.add(AwgNote(server_id=sid, protocol=proto, public_key=f"K-{proto}", note="n"))
            s.add(ClientName(server_id=sid, protocol=proto, client_id=f"K-{proto}", name="x"))
            s.add(ClientLimit(server_id=sid, protocol=proto, client_id=f"K-{proto}", name="x"))
            s.add(PausedClient(server_id=sid, protocol=proto, client_id=f"K-{proto}",
                               name="x", data="{}"))
        await s.commit()

    monkeypatch.setattr(sshops, "connect", lambda *a, **k: _Conn(""))

    async def remove(conn, protocol):
        return protoremove.RemoveResult(
            container="amnezia-awg", kind="awglegacy", snapshot="20261027-120000")

    async def probe(conn):
        return sshops.CheckResult(ok=True, docker=True, containers=["amnezia-awg2"],
                                  amnezia_containers=["amnezia-awg2"],
                                  protocols={"amnezia-awg2": "awg2"},
                                  manual_cascade=dict(route))

    monkeypatch.setattr(protoremove, "remove", remove)
    monkeypatch.setattr(sshops, "probe_containers", probe)
    r = await client.post(
        f"/api/servers/{sid}/protocols/awglegacy/remove",
        json={"password": "testpass"}, headers=auth_headers,
    )
    assert r.status_code == 200, r.text
    assert r.json()["snapshot"] == "20261027-120000"
    async with session_factory() as s:
        for model in (AwgConfig, AwgNote, ClientName, ClientLimit, PausedClient):
            rows = list(await s.scalars(select(model).where(model.server_id == sid)))
            assert [r.protocol for r in rows] == ["awg"], model.__name__
        srv = await s.get(Server, sid)
        info = json.loads(srv.last_check_info)
        assert info["amnezia_containers"] == ["amnezia-awg2"]
        assert info["manual_cascade"]["exit_name"] == "vpn-exit (transit)"
        assert info["manual_cascade"]["exit_country"] == "KZ"


async def test_bulk_revoke_groups_by_node_and_protocol(
    client, auth_headers, monkeypatch
):
    """Клиенты одного протокола на одной ноде отзываются за одно подключение,
    ошибка одного клиента не мешает остальным."""
    sid = await _server(client, auth_headers)
    calls = []

    async def many(server, protocol, client_ids, *a, **kw):
        calls.append((protocol, list(client_ids)))
        return {"B=": RuntimeError("peer busy")} if "B=" in client_ids else {}

    monkeypatch.setattr(expiry, "revoke_many_on_node", many)
    r = await client.post(
        "/api/clients/revoke-bulk",
        json={"items": [
            {"server_id": sid, "protocol": "awglegacy", "client_id": "A="},
            {"server_id": sid, "protocol": "awglegacy", "client_id": "B="},
            {"server_id": sid, "protocol": "awglegacy", "client_id": "C="},
            {"server_id": sid, "protocol": "xray", "client_id": "X="},
        ]},
        headers=auth_headers,
    )
    body = r.json()
    assert sorted(calls) == [("awglegacy", ["A=", "B=", "C="]), ("xray", ["X="])]
    assert body["revoked"] == 3 and body["failed"] == 1
    bad = [i for i in body["items"] if not i["ok"]]
    assert bad[0]["client_id"] == "B=" and "peer busy" in bad[0]["error"]


async def test_bulk_cleanup_has_group_session_and_node_lock(
    client, auth_headers, session_factory, monkeypatch
):
    ids = [await _server(client, auth_headers) for _ in range(2)]
    async with session_factory() as s:
        for sid in ids:
            await pausestore.add(s, sid, "awg", "paused-key", "phone", {"ip": "10.8.1.2"})
    sessions = []
    real_cleanup = expiry.cleanup_client_db

    async def revoke(*args, **kwargs):
        await asyncio.sleep(0.02)
        return {}

    async def cleanup(session, sid, protocol, cid):
        lk = nodelock._locks[(nodelock.family(protocol), sid)]
        assert lk.owner is asyncio.current_task() and lk.lock.locked()
        sessions.append(session)
        await real_cleanup(session, sid, protocol, cid)

    monkeypatch.setattr(expiry, "revoke_many_on_node", revoke)
    monkeypatch.setattr(expiry, "cleanup_client_db", cleanup)
    r = await client.post("/api/clients/revoke-bulk", headers=auth_headers,
                          json={"items": [{"server_id": sid, "protocol": "awg", "client_id": "paused-key"} for sid in ids]})
    assert r.status_code == 200 and r.json()["revoked"] == 2
    assert len(sessions) == 2 and sessions[0] is not sessions[1]
    async with session_factory() as s:
        for sid in ids:
            assert await pausestore.list_paused(s, sid, "awg") == {}


async def test_bulk_lock_timeout_is_reported_per_group(client, auth_headers, monkeypatch):
    from fastapi import HTTPException
    busy, free = [await _server(client, auth_headers) for _ in range(2)]
    real_hold = nodelock.hold

    @asynccontextmanager
    async def hold(protocol, sid, **kwargs):
        if sid == busy:
            raise HTTPException(409, "node busy")
        async with real_hold(protocol, sid, **kwargs):
            yield

    async def revoke(*args, **kwargs):
        return {}

    monkeypatch.setattr(nodelock, "hold", hold)
    monkeypatch.setattr(expiry, "revoke_many_on_node", revoke)
    r = await client.post("/api/clients/revoke-bulk", headers=auth_headers,
                          json={"items": [{"server_id": sid, "protocol": "awg", "client_id": "key"} for sid in (busy, free)]})
    assert r.status_code == 200
    data = r.json()
    assert data["revoked"] == 1 and data["failed"] == 1
    assert next(x for x in data["items"] if x["server_id"] == busy)["ok"] is False


async def test_revoke_many_uses_one_connection(monkeypatch):
    opened = []

    def connect(*a, **k):
        opened.append(1)
        return _Conn("")

    async def detect(conn):
        return {"new": None, "legacy": "amnezia-awg"}

    async def state(conn, host, container=None):
        return type("S", (), {"container": container, "interface": "wg0"})()

    revoked = []

    async def revoke(conn, container, iface, key):
        if key == "B=":
            raise RuntimeError("нет такого")
        revoked.append(key)

    monkeypatch.setattr(sshops, "connect", connect)
    monkeypatch.setattr(awg, "detect_awg_containers", detect)
    monkeypatch.setattr(awg, "read_state", state)
    monkeypatch.setattr(awg, "revoke_client", revoke)
    srv = Server(id=1, name="vpn-a", host="203.0.113.10", ssh_port=22, ssh_user="acontrol")
    errors = await expiry.revoke_many_on_node(srv, "awglegacy", ["A=", "B=", "C="], None, 5)
    assert opened == [1]
    assert revoked == ["A=", "C="] and list(errors) == ["B="]
    with pytest.raises(RuntimeError):
        await expiry.revoke_on_node(srv, "awglegacy", "B=", None, 5)


async def test_rename_on_node_keeps_other_clients(monkeypatch):
    _legacy_only(monkeypatch, {"new": "amnezia-awg2", "legacy": None})
    table = [
        {"clientId": "A=", "userData": {"clientName": "old", "creationDate": "d"}},
        {"clientId": "B=", "userData": {"clientName": "other"}},
    ]
    written = []

    async def read(conn, container):
        return json.loads(json.dumps(table))

    async def write(conn, container, data):
        written.append((container, data))

    monkeypatch.setattr(awg, "_read_table", read)
    monkeypatch.setattr(awg, "_write_table", write)
    assert await protoremove.rename_on_node(_Conn(""), "awg", "A=", "new name") == (True, "awg")
    container, data = written[0]
    assert container == "amnezia-awg2"
    assert data[0]["userData"] == {"clientName": "new name", "creationDate": "d"}
    assert data[1] == table[1]
    # клиента нет в таблице (или таблица не прочиталась) - ничего не пишем
    written.clear()
    assert await protoremove.rename_on_node(_Conn(""), "awg", "Z=", "x") == (False, "awg")
    assert written == []


async def test_api_rename_updates_panel_tables(
    client, auth_headers, session_factory, monkeypatch
):
    sid = await _server(client, auth_headers)
    async with session_factory() as s:
        s.add(AwgConfig(server_id=sid, public_key="A=", name="old", config="[Interface]"))
        s.add(ClientName(server_id=sid, protocol="awg", client_id="A=", name="old"))
        s.add(ClientLimit(server_id=sid, protocol="awg", client_id="A=", name="old"))
        s.add(ClientName(server_id=sid, protocol="xray", client_id="A=", name="keep"))
        await s.commit()
    monkeypatch.setattr(sshops, "connect", lambda *a, **k: _Conn(""))
    seen = []

    async def on_node(conn, protocol, cid, name):
        seen.append((protocol, cid, name))
        return True, "awg"

    monkeypatch.setattr(protoremove, "rename_on_node", on_node)
    r = await client.post(
        f"/api/servers/{sid}/protocols/awg/rename",
        json={"client_id": "A=", "name": "  phone   max "}, headers=auth_headers,
    )
    assert r.status_code == 204, r.text
    assert seen == [("awg", "A=", "phone max")]
    async with session_factory() as s:
        names = {(type(x).__name__, getattr(x, "protocol", "")): x.name
                 for m in (AwgConfig, ClientName, ClientLimit)
                 for x in await s.scalars(select(m).where(m.server_id == sid))}
    assert names[("AwgConfig", "awg")] == "phone max"
    assert names[("ClientName", "awg")] == "phone max"
    assert names[("ClientLimit", "awg")] == "phone max"
    assert names[("ClientName", "xray")] == "keep"


async def test_api_rename_unknown_client_is_404(client, auth_headers, monkeypatch):
    sid = await _server(client, auth_headers)
    monkeypatch.setattr(sshops, "connect", lambda *a, **k: _Conn(""))

    async def on_node(conn, protocol, cid, name):
        return False, protocol

    monkeypatch.setattr(protoremove, "rename_on_node", on_node)
    r = await client.post(
        f"/api/servers/{sid}/protocols/xray/rename",
        json={"client_id": "nope", "name": "x"}, headers=auth_headers,
    )
    assert r.status_code == 404


@pytest.mark.skipif(
    not os.environ.get("TEST_BASH") and (shutil.which("bash") is None or sys.platform == "win32"),
    reason="нужен bash (на Windows это bash из WSL со своим sudo)",
)
def test_remove_script_moves_openvpn_dirs_from_whole_amnezia_mount(tmp_path):
    """OpenVPN монтирует /opt/amnezia целиком: переименоваться должны каталоги
    протокола, а не остаться на месте (иначе переустановка вернет клиентов)."""
    root = tmp_path.as_posix()
    for d in ("openvpn", "cloak", "shadowsocks", "awg"):
        (tmp_path / "amnezia" / d).mkdir(parents=True)
    sub = deploy._SNAP_SPECS["openvpn"]["paths"].replace("/opt/", f"{root}/")
    script = protoremove._REMOVE_SCRIPT.format(
        cont="amnezia-openvpn-cloak", sub=shlex.quote(sub)
    ).replace("/opt/", f"{root}/")
    fake = (
        "sudo() { \"$@\"; }; systemctl() { :; }\n"
        "docker() { case \"$1 $2\" in\n"
        "  'inspect -f') case \"$3\" in *Mounts*) echo " + root + "/amnezia;; *) echo img;; esac;;\n"
        "  *) :;; esac; }\n"
    )
    out = subprocess.run([os.environ.get("TEST_BASH", "bash"), "-c", fake + script], capture_output=True, text=True)
    assert "REMOVED" in out.stdout, out.stderr
    moved = sorted(p.name.split(".removed-")[0] for p in (tmp_path / "amnezia").iterdir()
                   if ".removed-" in p.name)
    assert moved == ["cloak", "openvpn", "shadowsocks"]
    assert (tmp_path / "amnezia" / "awg").is_dir()  # чужой протокол не тронут


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
def test_remove_refuses_before_destroying_container_when_config_move_fails(tmp_path):
    root = tmp_path.as_posix()
    (tmp_path / "amnezia" / "awg").mkdir(parents=True)
    script = protoremove._REMOVE_SCRIPT.format(cont="amnezia-awg2", sub="''").replace("/opt/", f"{root}/")
    fake = (
        'sudo() { "$@"; }; systemctl() { :; }; mv() { return 1; }\n'
        'docker() { case "$1 $2" in\n'
        ' "inspect -f") case "$3" in *Mounts*) echo ' + root + '/amnezia/awg;; *) echo img;; esac;;\n'
        ' "rm -f") echo DESTROYED;; *) :;; esac; }\n'
    )
    result = subprocess.run([shutil.which("bash"), "-c", fake + script], capture_output=True, text=True)
    assert "DESTROYED" not in result.stdout
    assert "REMOVED" not in result.stdout
    assert result.returncode != 0


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
@pytest.mark.parametrize("failure", ["second_move", "docker_remove"])
def test_remove_restores_staged_directories_on_failure(tmp_path, failure):
    root = tmp_path.as_posix()
    for name in ("openvpn", "cloak", "shadowsocks"):
        path = tmp_path / "amnezia" / name
        path.mkdir(parents=True)
        (path / "keep").write_text(name)
    sub = deploy._SNAP_SPECS["openvpn"]["paths"].replace("/opt/", f"{root}/")
    script = protoremove._REMOVE_SCRIPT.format(cont="amnezia-openvpn-cloak", sub=shlex.quote(sub)).replace("/opt/", f"{root}/")
    fake = (
        'sudo() { "$@"; }; systemctl() { :; }\n'
        'docker() { case "$1 $2" in\n'
        ' "inspect -f") case "$3" in *Mounts*) echo ' + root + '/amnezia;; *) echo img;; esac;;\n'
        ' "rm -f") ' + ('return 1' if failure == "docker_remove" else ':') + ';; *) :;; esac; }\n'
    )
    if failure == "second_move":
        fake += 'mv() { case "$1" in */cloak) return 1;; *) command mv "$@";; esac; }\n'
    result = subprocess.run([shutil.which("bash"), "-c", fake + script], capture_output=True, text=True)
    assert result.returncode != 0
    assert "REMOVED" not in result.stdout
    assert sorted(p.name for p in (tmp_path / "amnezia").iterdir()) == ["cloak", "openvpn", "shadowsocks"]
    for name in ("openvpn", "cloak", "shadowsocks"):
        assert (tmp_path / "amnezia" / name / "keep").read_text() == name
