import asyncio
import base64
import json
import socket
import zlib

import pytest

from app import awg, client_endpoint, deploy
from app.models import AwgConfig, NativeVpnConfig


def decode_link(value):
    encoded = value.removeprefix("vpn://")
    top = json.loads(zlib.decompress(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))[4:]))
    return top, json.loads(top["containers"][0]["awg"]["last_config"])


@pytest.mark.parametrize("invalid", [
    "https://vpn.example.com", "vpn.example.com:443", "192.0.2.5:443",
    "[2001:db8::5]:443", "fe80::1%eth0", "vpn", "192.0.2.500", "x.example.com/path",
])
def test_endpoint_rejects_non_host_values(invalid):
    with pytest.raises(ValueError, match=client_endpoint.INVALID):
        client_endpoint.normalize(invalid)


def test_endpoint_normalizes_idn_and_edits_only_peer_address():
    assert client_endpoint.normalize(" пример.example. ") == "xn--e1afmkfd.example."
    assert client_endpoint.normalize("[2001:0db8::9]") == "2001:db8::9"
    config = "[Interface]\r\nEndpoint = keep:1\r\n[Peer]\r\n Endpoint = old.example:1234 # note\r\n"
    assert client_endpoint.peer_config(config, "2001:db8::9") == config.replace(
        "old.example:1234", "[2001:db8::9]:1234"
    )


async def test_saved_profiles_use_endpoint_without_changing_credentials(client, auth_headers, session_factory, monkeypatch):
    lookups = []

    async def getaddrinfo(host, port, **kwargs):
        lookups.append(host)
        if host == "missing.example.com":
            raise socket.gaierror(socket.EAI_NONAME, "no address")
        assert host == "vpn.example.com"
        return [(socket.AF_INET, socket.SOCK_DGRAM, 17, "", ("192.0.2.9", 0))]

    monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", getaddrinfo)
    response = await client.post(
        "/api/servers", headers=auth_headers,
        json={"name": "VPN test", "host": "192.0.2.5", "ssh_port": 2222},
    )
    assert response.status_code == 201
    sid = response.json()["id"]
    path = f"/api/servers/{sid}"
    assert response.json()["client_endpoint"] == ""
    response = await client.patch(path, headers=auth_headers, json={"client_endpoint": " VPN.Example.COM "})
    assert response.status_code == 200
    assert response.json()["host"] == "192.0.2.5"
    assert response.json()["ssh_port"] == 2222
    assert response.json()["client_endpoint"] == "vpn.example.com"
    assert lookups == ["vpn.example.com"]

    server = deploy.generate_server_config_v3(51820)
    private, public = awg.generate_keypair()
    sample = awg.build_client_config(
        client_private=private, address="10.8.3.2", server_public=server["pub"],
        preshared=server["psk"], endpoint="192.0.2.5:51820",
        params=awg.parse_conf(server["conf"])[0], dns="192.0.2.53",
    )
    profiles = {"awg3": sample}
    for protocol in ("awg", "awglegacy", "wireguard"):
        profiles[protocol] = "\n".join(
            line for line in sample.split("\n")
            if line.split(" = ", 1)[0] not in awg.AWG_PARAM_KEYS
        )
    async with session_factory() as session:
        for protocol, text in profiles.items():
            _, key = awg.generate_keypair()
            if protocol == "wireguard":
                session.add(NativeVpnConfig(server_id=sid, protocol=protocol, client_id=key, name="Test", config=text))
            else:
                session.add(AwgConfig(server_id=sid, protocol=protocol, public_key=key, name="Test", config=text))
            profiles[protocol] = (key, text)
        await session.commit()

    for protocol, (key, stored) in profiles.items():
        route = "awg-legacy" if protocol == "awglegacy" else protocol
        response = await client.post(path + f"/{route}/config", headers=auth_headers, json={"public_key": key})
        assert response.status_code == 200, (protocol, response.status_code)
        body = response.json()
        expected = stored.replace("192.0.2.5:51820", "vpn.example.com:51820")
        assert body["config"] == expected
        if protocol != "wireguard":
            top, inner = decode_link(body["config_amnezia"])
            assert top["hostName"] == inner["hostName"] == "vpn.example.com"
            assert inner["client_pub_key"] == public
            assert inner["psk_key"] == server["psk"]
            assert "Endpoint = vpn.example.com:51820" in inner["config"]
            if protocol == "awg3":
                assert top["containers"][0]["awg"]["protocol_version"] == "3.1"

    created_key = await client.post(
        "/api/apikeys", headers=auth_headers, json={"name": "Integration", "password": "testpass"},
    )
    key, stored = profiles["awg"]
    response = await client.get(
        f"/api/v1/servers/{sid}/clients/config", params={"public_key": key},
        headers={"X-API-Key": created_key.json()["key"]},
    )
    assert response.status_code == 200
    assert response.json()["config"] == stored.replace("192.0.2.5:51820", "vpn.example.com:51820")
    assert len(lookups) == 6

    response = await client.patch(path, headers=auth_headers, json={"note": "Keep the DNS override"})
    assert response.status_code == 200 and len(lookups) == 6
    response = await client.patch(path, headers=auth_headers, json={"client_endpoint": "missing.example.com"})
    assert response.status_code == 422 and response.json()["detail"] == client_endpoint.UNRESOLVED
    response = await client.get(path, headers=auth_headers)
    assert response.json()["client_endpoint"] == "vpn.example.com"

    response = await client.patch(path, headers=auth_headers, json={"client_endpoint": ""})
    assert response.status_code == 200 and response.json()["client_endpoint"] == ""
    key, original = profiles["awg3"]
    response = await client.post(path + "/awg3/config", headers=auth_headers, json={"public_key": key})
    assert response.status_code == 200 and response.json()["config"] == original
    assert decode_link(response.json()["config_amnezia"])[0]["hostName"] == "192.0.2.5"


async def test_dns_failure_stops_download_and_issuance_before_ssh(client, auth_headers, session_factory, monkeypatch):
    from app.api import awg3
    from app.models import Server

    async def getaddrinfo(*args, **kwargs):
        raise socket.gaierror(socket.EAI_NONAME, "no address")

    def unexpected_ssh(*args, **kwargs):
        pytest.fail("An unresolved endpoint must fail before making changes to a peer")

    monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", getaddrinfo)
    monkeypatch.setattr(awg3, "_connect", unexpected_ssh)
    async with session_factory() as session:
        server = Server(name="VPN test", host="192.0.2.5", client_endpoint="vpn.example.com", ssh_user="vpn")
        session.add(server)
        await session.flush()
        sid = server.id
        session.add(AwgConfig(server_id=sid, protocol="awg3", public_key="saved-key", name="Test", config="saved"))
        await session.commit()
    for route, payload in (("clients", {"name": "New test"}), ("config", {"public_key": "saved-key"})):
        response = await client.post(f"/api/servers/{sid}/awg3/{route}", headers=auth_headers, json=payload)
        assert response.status_code == 422
        assert response.json()["detail"] == client_endpoint.UNRESOLVED
