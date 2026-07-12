import httpx
import pytest

from app import awg
from app.api import awg as awg_api

SERVER = {"name": "n", "host": "1.2.3.4", "ssh_port": 22, "ssh_user": "root"}


@pytest.fixture(autouse=True)
def _mock_detect(monkeypatch):
    """get_awg теперь делит контейнеры на new/legacy; по умолчанию — только new."""
    monkeypatch.setattr(
        awg, "detect_awg_containers",
        lambda conn: _wrap({"new": "amnezia-awg2", "legacy": None}),
    )


class _DummyConn:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False


def _state(clients):
    return awg.AwgState(
        container="amnezia-awg2",
        interface="awg0",
        listen_port=47180,
        server_public_key="SRVPUB",
        endpoint="1.2.3.4:47180",
        address="10.8.1.0/24",
        clients=clients,
    )


async def _make_server(client, auth_headers) -> int:
    r = await client.post("/api/servers", json=SERVER, headers=auth_headers)
    return r.json()["id"]


async def test_create_stores_config_and_has_config_flag(
    client: httpx.AsyncClient, auth_headers, monkeypatch
) -> None:
    sid = await _make_server(client, auth_headers)
    monkeypatch.setattr(awg_api, "_connect", lambda server: _DummyConn())

    existing = awg.AwgClient(name="old", public_key="OLDPUB", address="10.8.1.1/32")
    monkeypatch.setattr(awg, "read_state", lambda conn, host, container=None: _wrap(_state([existing])))

    new_client = awg.AwgClient(name="phone", public_key="NEWPUB", address="10.8.1.2/32")
    monkeypatch.setattr(
        awg, "create_client",
        lambda conn, state, name, dns, fixed_ip=None: _wrap((new_client, "CONFIG-TEXT")),
    )

    r = await client.post(
        f"/api/servers/{sid}/awg/clients",
        json={"name": "phone"}, headers=auth_headers,
    )
    assert r.status_code == 201
    assert r.json()["config"] == "CONFIG-TEXT"
    assert r.json()["client"]["has_config"] is True

    # get_awg помечает has_config
    monkeypatch.setattr(
        awg, "read_state", lambda conn, host, container=None: _wrap(_state([existing, new_client]))
    )
    r = await client.get(f"/api/servers/{sid}/awg", headers=auth_headers)
    by_pub = {c["public_key"]: c for c in r.json()["clients"]}
    assert by_pub["NEWPUB"]["has_config"] is True
    assert by_pub["OLDPUB"]["has_config"] is False


async def test_get_stored_config(
    client: httpx.AsyncClient, auth_headers, monkeypatch
) -> None:
    sid = await _make_server(client, auth_headers)
    monkeypatch.setattr(awg_api, "_connect", lambda server: _DummyConn())
    monkeypatch.setattr(awg, "read_state", lambda conn, host, container=None: _wrap(_state([])))
    nc = awg.AwgClient(name="pc", public_key="PCPUB", address="10.8.1.5/32")
    monkeypatch.setattr(
        awg, "create_client",
        lambda conn, state, name, dns, fixed_ip=None: _wrap((nc, "PC-CONFIG")),
    )
    await client.post(
        f"/api/servers/{sid}/awg/clients", json={"name": "pc"}, headers=auth_headers
    )

    r = await client.post(
        f"/api/servers/{sid}/awg/config",
        json={"public_key": "PCPUB"}, headers=auth_headers,
    )
    assert r.status_code == 200
    assert r.json()["config"] == "PC-CONFIG"

    r = await client.post(
        f"/api/servers/{sid}/awg/config",
        json={"public_key": "UNKNOWN"}, headers=auth_headers,
    )
    assert r.status_code == 404


async def test_revoke_removes_stored_config(
    client: httpx.AsyncClient, auth_headers, monkeypatch
) -> None:
    sid = await _make_server(client, auth_headers)
    monkeypatch.setattr(awg_api, "_connect", lambda server: _DummyConn())
    monkeypatch.setattr(awg, "read_state", lambda conn, host, container=None: _wrap(_state([])))
    nc = awg.AwgClient(name="x", public_key="XPUB", address="10.8.1.9/32")
    monkeypatch.setattr(
        awg, "create_client",
        lambda conn, state, name, dns, fixed_ip=None: _wrap((nc, "XCONF")),
    )
    monkeypatch.setattr(
        awg, "revoke_client", lambda conn, c, i, pub: _wrap(None)
    )
    await client.post(
        f"/api/servers/{sid}/awg/clients", json={"name": "x"}, headers=auth_headers
    )

    r = await client.post(
        f"/api/servers/{sid}/awg/revoke",
        json={"public_key": "XPUB"}, headers=auth_headers,
    )
    assert r.status_code == 204

    r = await client.post(
        f"/api/servers/{sid}/awg/config",
        json={"public_key": "XPUB"}, headers=auth_headers,
    )
    assert r.status_code == 404


async def test_note_set_and_shown(
    client: httpx.AsyncClient, auth_headers, monkeypatch
) -> None:
    sid = await _make_server(client, auth_headers)
    monkeypatch.setattr(awg_api, "_connect", lambda server: _DummyConn())
    peer = awg.AwgClient(name="pc", public_key="PCPUB", address="10.8.1.5/32")
    monkeypatch.setattr(awg, "read_state", lambda conn, host, container=None: _wrap(_state([peer])))

    # ставим заметку на существующего клиента (созданного вне панели)
    r = await client.post(
        f"/api/servers/{sid}/awg/note",
        json={"public_key": "PCPUB", "note": "ноут жены"},
        headers=auth_headers,
    )
    assert r.status_code == 204

    r = await client.get(f"/api/servers/{sid}/awg", headers=auth_headers)
    by_pub = {c["public_key"]: c for c in r.json()["clients"]}
    assert by_pub["PCPUB"]["note"] == "ноут жены"

    # очистка заметки пустой строкой
    await client.post(
        f"/api/servers/{sid}/awg/note",
        json={"public_key": "PCPUB", "note": ""},
        headers=auth_headers,
    )
    r = await client.get(f"/api/servers/{sid}/awg", headers=auth_headers)
    by_pub = {c["public_key"]: c for c in r.json()["clients"]}
    assert by_pub["PCPUB"]["note"] == ""


async def test_create_with_note(
    client: httpx.AsyncClient, auth_headers, monkeypatch
) -> None:
    sid = await _make_server(client, auth_headers)
    monkeypatch.setattr(awg_api, "_connect", lambda server: _DummyConn())
    monkeypatch.setattr(awg, "read_state", lambda conn, host, container=None: _wrap(_state([])))
    nc = awg.AwgClient(name="tab", public_key="TABPUB", address="10.8.1.7/32")
    monkeypatch.setattr(
        awg, "create_client",
        lambda conn, state, name, dns, fixed_ip=None: _wrap((nc, "TABCONF")),
    )
    r = await client.post(
        f"/api/servers/{sid}/awg/clients",
        json={"name": "tab", "note": "планшет"},
        headers=auth_headers,
    )
    assert r.status_code == 201
    assert r.json()["client"]["note"] == "планшет"

    monkeypatch.setattr(awg, "read_state", lambda conn, host, container=None: _wrap(_state([nc])))
    r = await client.get(f"/api/servers/{sid}/awg", headers=auth_headers)
    assert r.json()["clients"][0]["note"] == "планшет"


async def _wrap(value):
    return value
