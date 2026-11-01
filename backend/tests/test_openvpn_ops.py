"""OpenVPN: порядок перевыпуска, правила торрентов после рестарта, ответы API
без протокола и на повторную паузу."""

import httpx
import pytest
from fastapi import HTTPException

from app import openvpn, pausestore, torrent, xray
from app.api import openvpn as ovpn_api
from app.api import xray as xray_api
from app.models import Server


class _Result:
    def __init__(self, stdout: str = "", exit_status: int = 0):
        self.stdout = stdout
        self.stderr = ""
        self.exit_status = exit_status


class _EmptyConn:
    """docker ps без нужного контейнера."""

    async def run(self, cmd, input=None, check=False):  # noqa: A002
        # без `|| true` grep отдал бы 1 и наружу ушло бы "код 1"
        return _Result("", 0 if "|| true" in cmd else 1)


class _DummyConn:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False


async def _wrap(v=None):
    return v


async def test_reissue_issues_before_revoking(monkeypatch) -> None:
    calls: list[str] = []

    async def issue(*a, **kw):
        calls.append("issue")
        return openvpn.OvpnClient(client_id="NEW", name="n", creation_date=""), "vpn://x"

    async def revoke(conn, container, cid):
        calls.append(f"revoke {cid}")
        return False

    monkeypatch.setattr(openvpn, "issue_client", issue)
    monkeypatch.setattr(openvpn, "revoke_client", revoke)
    await openvpn.reissue_client(None, "c", "OLD", "n", "203.0.113.5", "d", "1.1.1.1", "1.0.0.1")
    assert calls == ["issue", "revoke OLD"]


async def test_reissue_keeps_old_client_when_issue_fails(monkeypatch) -> None:
    revoked: list[str] = []

    async def issue(*a, **kw):
        raise openvpn.OpenVpnError("CA не подписал")

    async def revoke(conn, container, cid):
        revoked.append(cid)

    monkeypatch.setattr(openvpn, "issue_client", issue)
    monkeypatch.setattr(openvpn, "revoke_client", revoke)
    with pytest.raises(openvpn.OpenVpnError):
        await openvpn.reissue_client(None, "c", "OLD", "n", "203.0.113.5", "d", "1", "2")
    assert revoked == []


async def test_not_deployed_is_clear_error() -> None:
    with pytest.raises(openvpn.OpenVpnNotDeployed):
        await openvpn.detect_container(_EmptyConn())
    with pytest.raises(xray.XrayNotDeployed):
        await xray.detect_container(_EmptyConn())


def test_busy_node_http_error_is_preserved() -> None:
    exc = HTTPException(409, "Нода занята")
    assert ovpn_api._ovpn_error(exc) is exc
    assert xray_api._xray_error(exc) is exc


async def test_revoke_paused_xray_removes_uuid_restored_from_snapshot(
    client, auth_headers, session_factory, monkeypatch
) -> None:
    sid = await _server(client, auth_headers, session_factory)
    async with session_factory() as s:
        await pausestore.add(s, sid, "xray", "restored-client", "phone", {"entry": {"id": "restored-client"}})
    # A snapshot taken before pause has restored this UUID on the node.
    runtime = {"restored-client"}
    monkeypatch.setattr(xray_api, "_connect", lambda server: _DummyConn())
    monkeypatch.setattr(xray, "detect_container", lambda conn: _wrap("amnezia-xray"))

    async def revoke(conn, container, cid):
        runtime.discard(cid)

    monkeypatch.setattr(xray, "revoke_client", revoke)
    r = await client.post(f"/api/servers/{sid}/xray/revoke", headers=auth_headers,
                          json={"client_id": "restored-client"})
    assert r.status_code == 204
    assert runtime == set()


async def _server(client, auth_headers, session_factory, torrent_block=False) -> int:
    r = await client.post("/api/servers", json={"name": "n", "host": "203.0.113.5",
                                                "ssh_port": 22, "ssh_user": "root"},
                          headers=auth_headers)
    sid = r.json()["id"]
    if torrent_block:
        async with session_factory() as s:
            (await s.get(Server, sid)).torrent_block = True
            await s.commit()
    return sid


async def test_list_without_protocol_is_409(
    client: httpx.AsyncClient, auth_headers, session_factory, monkeypatch
) -> None:
    sid = await _server(client, auth_headers, session_factory)

    class Conn(_DummyConn, _EmptyConn):
        pass

    monkeypatch.setattr(ovpn_api, "_connect", lambda server: Conn())
    monkeypatch.setattr(xray_api, "_connect", lambda server: Conn())
    for proto in ("openvpn", "xray"):
        r = await client.get(f"/api/servers/{sid}/{proto}", headers=auth_headers)
        assert r.status_code == 409, proto
        assert "не развернут" in r.json()["detail"]


async def test_pause_restores_torrent_rules_and_repeat_is_404(
    client: httpx.AsyncClient, auth_headers, session_factory, monkeypatch
) -> None:
    sid = await _server(client, auth_headers, session_factory, torrent_block=True)
    monkeypatch.setattr(ovpn_api, "_connect", lambda server: _DummyConn())
    monkeypatch.setattr(openvpn, "detect_container", lambda conn: _wrap("amnezia-openvpn-cloak"))
    monkeypatch.setattr(openvpn, "read_clients", lambda conn: _wrap(
        [openvpn.OvpnClient(client_id="CID", name="phone", creation_date="")]
    ))
    monkeypatch.setattr(openvpn, "pause_client", lambda conn, c, cid: _wrap())
    monkeypatch.setattr(openvpn, "resume_client", lambda conn, c, cid: _wrap())
    synced: list[tuple[str, bool]] = []

    async def sync(conn, container, enabled):
        synced.append((container, enabled))
        return True, {}

    monkeypatch.setattr(torrent, "sync_container", sync)

    r = await client.post(f"/api/servers/{sid}/openvpn/pause", json={"client_id": "CID"},
                          headers=auth_headers)
    assert r.status_code == 204
    assert synced == [("amnezia-openvpn-cloak", True)]
    # повторная пауза - как у AWG/XRay
    r = await client.post(f"/api/servers/{sid}/openvpn/pause", json={"client_id": "CID"},
                          headers=auth_headers)
    assert r.status_code == 404
    r = await client.post(f"/api/servers/{sid}/openvpn/resume", json={"client_id": "CID"},
                          headers=auth_headers)
    assert r.status_code == 204
    assert len(synced) == 2
