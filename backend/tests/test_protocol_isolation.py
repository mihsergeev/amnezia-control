import pytest
from sqlalchemy import select

from app import awg
from app.api import awg as awg_api, awg3 as awg3_api, awg_legacy as legacy_api
from app.models import AwgConfig
from app import pausestore, xray
from app.api import xray as xray_api

class Conn:
    async def __aenter__(self):
        return self
    async def __aexit__(self, *args):
        return False

async def done(*args, **kwargs):
    return None

@pytest.mark.parametrize("path,protocol,module", [
    ("awg", "awg", awg_api), ("awg3", "awg3", awg3_api),
    ("awg-legacy", "awglegacy", legacy_api),
])
async def test_awg_config_and_revoke_do_not_cross_protocols(
    client, auth_headers, session_factory, monkeypatch, path, protocol, module
):
    r = await client.post("/api/servers", headers=auth_headers,
                          json={"name": "vpn-a", "host": "203.0.113.10"})
    sid = r.json()["id"]
    foreign = "awg3" if protocol != "awg3" else "awglegacy"
    async with session_factory() as s:
        s.add(AwgConfig(server_id=sid, protocol=foreign, public_key="foreign-key",
                        name="other protocol", config="synthetic config"))
        await s.commit()
    monkeypatch.setattr(module, "_amnezia_link", lambda *a, **kw: "vpn://synthetic")
    r = await client.post(f"/api/servers/{sid}/{path}/config", headers=auth_headers,
                          json={"public_key": "foreign-key"})
    assert r.status_code == 404

    monkeypatch.setattr(module, "_connect", lambda server: Conn())
    async def state(*args, **kwargs):
        return awg.AwgState(container="amnezia-awg2", interface="awg0", address="10.8.1.0/24",
                            listen_port=47180, server_public_key="", endpoint="", clients=[])
    monkeypatch.setattr(awg, "read_state", state)
    if path == "awg3": monkeypatch.setattr(module, "_state", state)
    if path == "awg-legacy": monkeypatch.setattr(module, "_legacy_state", state)
    monkeypatch.setattr(awg, "revoke_client", done)
    r = await client.post(f"/api/servers/{sid}/{path}/revoke", headers=auth_headers,
                          json={"public_key": "foreign-key"})
    assert r.status_code == 204
    async with session_factory() as s:
        row = await s.scalar(select(AwgConfig).where(AwgConfig.public_key == "foreign-key"))
        assert row is not None and row.protocol == foreign


@pytest.mark.parametrize("path,protocol,module", [
    ("awg", "awg", awg_api), ("awg3", "awg3", awg3_api),
    ("awg-legacy", "awglegacy", legacy_api), ("xray", "xray", xray_api),
])
@pytest.mark.parametrize("failure", ["transport", "write"])
async def test_paused_revoke_keeps_metadata_when_node_revoke_fails(
    client, auth_headers, session_factory, monkeypatch, path, protocol, module, failure
):
    r = await client.post("/api/servers", headers=auth_headers,
                          json={"name": "vpn-a", "host": "203.0.113.10"})
    sid = r.json()["id"]
    async with session_factory() as s:
        await pausestore.add(s, sid, protocol, "paused-id", "phone", {"ip": "10.8.1.2"})
    error = OSError("connection reset") if failure == "transport" else (
        xray.XrayError("write failed: no space") if path == "xray" else awg.AwgError("write failed: no space")
    )
    class Failed(Conn):
        async def __aenter__(self):
            raise error
    monkeypatch.setattr(module, "_connect", lambda server: Failed())
    body = {"client_id" if path == "xray" else "public_key": "paused-id"}
    r = await client.post(f"/api/servers/{sid}/{path}/revoke", headers=auth_headers, json=body)
    assert r.status_code == 502
    async with session_factory() as s:
        assert "paused-id" in await pausestore.list_paused(s, sid, protocol)
