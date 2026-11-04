from datetime import datetime, timezone

import httpx
import pytest

from app import awg, limits, notes, pausestore
from app.api import awg as awg_api
from app.api import awg3, awg_legacy
from app.models import AwgConfig

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
        lambda conn, state, name, dns, fixed_ip=None, reserved=None: _wrap((new_client, "CONFIG-TEXT")),
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
        lambda conn, state, name, dns, fixed_ip=None, reserved=None: _wrap((nc, "PC-CONFIG")),
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
        lambda conn, state, name, dns, fixed_ip=None, reserved=None: _wrap((nc, "XCONF")),
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
        lambda conn, state, name, dns, fixed_ip=None, reserved=None: _wrap((nc, "TABCONF")),
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

@pytest.mark.parametrize(("path", "protocol", "module", "read"), [
    ("awg", "awg", awg_api, None),
    ("awg3", "awg3", awg3, "_state"),
    ("awg-legacy", "awglegacy", awg_legacy, "_legacy_state"),
])
async def test_reissue_paused_client_with_occupied_address(
    client, auth_headers, session_factory, monkeypatch, path, protocol, module, read,
):
    sid = await _make_server(client, auth_headers)
    base = f"/api/servers/{sid}/{path}"
    active = awg.AwgClient(name="laptop", public_key="ACTIVE", address="10.8.1.2/32")
    state = _state([active])
    monkeypatch.setattr(module, "_connect", lambda server: _DummyConn())
    if read:
        monkeypatch.setattr(module, read, lambda *_: _wrap(state))
    else:
        monkeypatch.setattr(awg, "read_state", lambda *_: _wrap(state))

    async def issue(conn, st, name, dns, fixed_ip=None, reserved=None):
        assert fixed_ip is None
        ip = awg.allocate_ip(st.address, reserved | {active.address.split("/")[0]})
        new = awg.AwgClient(name=name, public_key="REPLACEMENT", address=f"{ip}/32")
        st.clients.append(new)
        return new, f"Address = {new.address}"

    async def revoke(conn, container, interface, key):
        assert key == "REPLACEMENT"
        state.clients[:] = [peer for peer in state.clients if peer.public_key != key]

    monkeypatch.setattr(awg, "create_client", issue)
    monkeypatch.setattr(awg, "revoke_client", revoke)
    expires = datetime(2030, 1, 1, tzinfo=timezone.utc)
    async with session_factory() as session:
        await pausestore.add(session, sid, protocol, "PAUSED", "phone", {"ip": "10.8.1.2"})
        await pausestore.add(session, sid, protocol, "OTHER", "tablet", {"ip": "10.8.1.1"})
        await pausestore.add(session, sid, protocol, "THIRD", "desktop", {"ip": "10.8.1.3"})
        await notes.set_note(session, sid, protocol, "PAUSED", "keep this")
        await limits.set_limit(session, sid, protocol, "PAUSED", "phone", expires)
        session.add(AwgConfig(server_id=sid, protocol=protocol, public_key="PAUSED",
                              name="phone", config="Address = 10.8.1.2/32"))
        await session.commit()

    payload = {"public_key": "PAUSED"}
    failed = await client.post(f"{base}/resume", json=payload, headers=auth_headers)
    assert failed.status_code == 502
    assert state.clients == [active]

    async def fail_to_drop(*args):
        raise RuntimeError("pause metadata write failed")

    with monkeypatch.context() as injected:
        injected.setattr(pausestore, "drop", fail_to_drop)
        failed = await client.post(f"{base}/reissue", json=payload, headers=auth_headers)
    assert failed.status_code == 500
    assert state.clients == [active]
    async with session_factory() as session:
        assert "PAUSED" in await pausestore.list_paused(session, sid, protocol)

    repaired = await client.post(f"{base}/reissue", json=payload, headers=auth_headers)
    assert repaired.status_code == 201, repaired.text
    replacement = repaired.json()["client"]
    assert replacement["name"] == "phone"
    assert replacement["address"] == "10.8.1.4/32"
    assert replacement["note"] == "keep this"
    assert replacement["expires_at"].startswith("2030-01-01")
    assert state.clients[0] is active

    async with session_factory() as session:
        assert set(await pausestore.list_paused(session, sid, protocol)) == {"OTHER", "THIRD"}
        assert await notes.notes_map(session, sid, protocol) == {"REPLACEMENT": "keep this"}
        assert set(await limits.limits_map(session, sid, protocol)) == {"REPLACEMENT"}
    assert (await client.post(f"{base}/config", json=payload, headers=auth_headers)).status_code == 404
    saved = await client.post(
        f"{base}/config", json={"public_key": "REPLACEMENT"}, headers=auth_headers,
    )
    assert saved.json()["config"] == repaired.json()["config"]
