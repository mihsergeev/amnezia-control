"""Удаление протокола с ноды и массовый отзыв из карточки протокола."""

import json

import pytest
from sqlalchemy import select

from app import awg, deploy, expiry, protoremove, sshops
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
    async with session_factory() as s:
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
                                  protocols={"amnezia-awg2": "awg2"})

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
        assert json.loads(srv.last_check_info)["amnezia_containers"] == ["amnezia-awg2"]


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
