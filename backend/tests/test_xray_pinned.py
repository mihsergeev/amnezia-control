"""Панель ставит закрепленную версию xray-core, а не последний релиз GitHub.

26.10.31 выключает MPTCP по умолчанию. Проверенный профиль FirefoxAuto148
сохраняется; старые ClientHello без X25519MLKEM768 upstream не поддерживает.
Кнопки "Обновить ядро" и "Переустановить" должны ставить проверенный pin.
"""

import base64
import json
import re
import subprocess

import pytest

from app import deploy, deploywatch, xray
from app.api import xray as xray_api

PINNED = xray.XRAY_RELEASE.lstrip("v")


class _DummyConn:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False


async def _server(client, auth_headers) -> int:
    r = await client.post("/api/servers", json={
        "name": "vpn-a", "host": "203.0.113.10", "ssh_port": 22, "ssh_user": "amn",
    }, headers=auth_headers)
    return r.json()["id"]


@pytest.fixture
def node(monkeypatch):
    """Нода без SSH: запоминает запущенный сценарий."""
    launched: list[str] = []

    async def fake_launch(conn, script, tag):
        launched.append(script)

    async def nothing(*a, **kw):
        return None

    async def container(conn):
        return xray.CONTAINER_NAME

    async def bits(conn, container):
        return {"port": 443, "site": "www.example.com"}

    monkeypatch.setattr(xray_api, "_connect", lambda server: _DummyConn())
    monkeypatch.setattr(deploy, "port_owner", nothing)
    monkeypatch.setattr(xray, "deployment_bind_ip", nothing)
    monkeypatch.setattr(deploy, "snapshot_all", nothing)
    monkeypatch.setattr(deploy, "snapshot_config", nothing)
    monkeypatch.setattr(deploy, "launch", fake_launch)
    monkeypatch.setattr(deploy, "ensure_idle", lambda conn, *, tag: nothing())
    monkeypatch.setattr(deploywatch, "spawn", lambda *a, **kw: None)
    monkeypatch.setattr(xray, "detect_container", container)
    monkeypatch.setattr(xray, "read_server_bits", bits)
    monkeypatch.setattr(xray, "stage_update_stats", nothing)
    return launched


def test_no_github_lookup_left() -> None:
    # последний релиз панель больше не спрашивает вовсе
    assert not hasattr(xray, "latest_release")


def test_mptcp_security_release_preserves_issued_fingerprint() -> None:
    assert xray.XRAY_RELEASE == "v26.10.31"
    assert xray.FINGERPRINT == "firefox"
    script = xray.build_deploy_script(8443, "www.example.com")
    dockerfile = re.search(r"echo ([A-Za-z0-9+/=]+) \| base64 -d.*Dockerfile", script)
    assert dockerfile is not None
    dockerfile_text = base64.b64decode(dockerfile[1]).decode()
    assert f'ARG XRAY_RELEASE="{xray.XRAY_RELEASE}"' in dockerfile_text
    assert 'sha256sum -c -' in dockerfile_text
    assert "ENV GODEBUG=multipathtcp=0" in dockerfile_text
    run = re.search(r'sudo docker run -d.*?\n.*?\n.*?\n.*?\n.*?\n', script)
    assert run is not None
    assert "-e GODEBUG=multipathtcp=0" in run[0]
    # Свой netns выключает и явно запрошенный tcpMptcp:true; на ядре без
    # CONFIG_MPTCP sysctl пропускаем, иначе Docker отказался бы запускаться.
    assert 'if [ -e /proc/sys/net/mptcp/enabled ]; then MPTCP_OPT="--sysctl net.mptcp.enabled=0"; fi' in script
    assert "$MPTCP_OPT" in run[0]


def test_version_tuple() -> None:
    assert xray.version_tuple("v26.3.27") == (26, 3, 27)
    assert xray.version_tuple("26.10.21") > xray.version_tuple("v26.3.27")
    assert xray.version_tuple("") == ()


def test_explicit_xray_version_is_accepted_with_or_without_prefix() -> None:
    assert "XRAY_RELEASE=v26.10.21" in xray.build_deploy_script(443, "www.example.com", "26.10.21")
    assert "XRAY_RELEASE=v26.10.21" in xray.build_deploy_script(443, "www.example.com", "v26.10.21")


async def test_deploy_installs_pinned(client, auth_headers, node) -> None:
    sid = await _server(client, auth_headers)
    r = await client.post(
        f"/api/servers/{sid}/xray/deploy", json={"port": 8443}, headers=auth_headers
    )
    assert r.status_code == 202
    assert f"XRAY_RELEASE={xray.XRAY_RELEASE}" in node[0]


@pytest.mark.parametrize("settings,sni,target", [
    ({"site": "  ", "dest": ""}, xray.DEFAULT_REALITY_SITE, f"{xray.DEFAULT_REALITY_SITE}:443"),
    ({"site": "WWW.Example.COM."}, "www.example.com", "www.example.com:443"),
    ({"dest": "BÜCHER.example:8443"}, "xn--bcher-kva.example", "xn--bcher-kva.example:8443"),
    ({"site": "www.example.com", "dest": "192.0.2.1:8443"}, "www.example.com", "192.0.2.1:8443"),
    ({"site": "www.example.com", "dest": "[2001:db8::1]"}, "www.example.com", "[2001:db8::1]:443"),
    ({"port": xray.STATS_API_PORT}, xray.DEFAULT_REALITY_SITE, f"{xray.DEFAULT_REALITY_SITE}:443"),
])
async def test_deploy_renders_reality_settings(client, auth_headers, node, settings, sni, target) -> None:
    sid = await _server(client, auth_headers)
    r = await client.post(
        f"/api/servers/{sid}/xray/deploy", json={"port": 9443, **settings}, headers=auth_headers
    )
    assert r.status_code == 202
    script, = node
    assignments = re.findall(r"^(?:XRAY_(?:SITE_NAME|DEST|SERVER_PORT)|INBOUND_PORT)=.*$", script, re.M)
    remap = re.search(r'^ +if \[ "\$INBOUND_PORT" = .*INBOUND_PORT=443; fi$', script, re.M)
    assert remap is not None
    block = re.search(r'server\.json" >/dev/null <<EOF[^\n]*\n(.*?)\nEOF', script, re.S)
    assert block is not None
    rendered = subprocess.run(
        ["bash", "-s"], input="\n".join([*assignments, remap[0], "cat <<EOF", block[1], "EOF", ""]).encode(),
        capture_output=True, check=True,
    ).stdout
    inbound, stats = json.loads(rendered)["inbounds"]
    assert inbound["port"] == (443 if settings.get("port") == xray.STATS_API_PORT else 9443)
    assert stats["port"] == xray.STATS_API_PORT
    reality = inbound["streamSettings"]["realitySettings"]
    assert reality["serverNames"] == [sni]
    assert reality["dest"] == target
    custom = bool(settings.get("site", "").strip() or settings.get("dest", "").strip())
    assert ("Xray already has a configuration or container" in script) == custom


@pytest.mark.parametrize("settings", [
    {"site": "*.example.com"},
    {"site": "192.0.2.1"},
    {"site": "www.example.com:443"},
    {"dest": "https://www.example.com/"},
    {"dest": "www.example.com;id"},
    {"dest": "www.example.com:65536"},
    {"dest": "[2001:db8::1]:443"},
    {"site": "www.example.com", "dest": f"127.0.0.1:{xray.STATS_API_PORT}"},
    {"dest": f"loopback.example.com:{xray.STATS_API_PORT}"},
])
async def test_deploy_rejects_invalid_reality_settings(client, auth_headers, node, settings) -> None:
    sid = await _server(client, auth_headers)
    r = await client.post(f"/api/servers/{sid}/xray/deploy", json=settings, headers=auth_headers)
    assert r.status_code == 422
    assert not node


async def test_read_server_bits_uses_published_port(monkeypatch) -> None:
    async def run(conn, command):
        assert "HostConfig.PortBindings" in command
        return '===BINDINGS===\n{"19443/tcp":[{"HostIp":"192.0.2.2","HostPort":"18443"}]}'

    async def config(conn, container):
        return {"inbounds": [{"port": 19443}]}

    monkeypatch.setattr(xray, "_run", run)
    monkeypatch.setattr(xray, "_read_server", config)
    bits = await xray.read_server_bits(_DummyConn(), xray.CONTAINER_NAME)
    assert bits["port"] == 18443


async def test_update_installs_pinned(client, auth_headers, node) -> None:
    sid = await _server(client, auth_headers)
    r = await client.post(f"/api/servers/{sid}/xray/update", headers=auth_headers)
    assert r.status_code == 202
    assert f"XRAY_RELEASE={xray.XRAY_RELEASE}" in node[0]


@pytest.mark.parametrize("current,offer", [
    ("25.8.3", True),     # старее закрепленной - предлагаем обновить
    (PINNED, False),      # уже на ней
    ("26.10.21", True),   # предыдущее ядро - предлагаем security release
    ("26.11.1", False),   # новее pin - не зовем "обновлять"
])
async def test_update_offered_only_up_to_pinned(
    client, auth_headers, node, monkeypatch, current, offer
) -> None:
    async def version(conn, container):
        return current

    monkeypatch.setattr(xray, "node_version", version)
    sid = await _server(client, auth_headers)
    r = await client.get(f"/api/servers/{sid}/xray/version", headers=auth_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["latest_version"] == PINNED
    assert body["update_available"] is offer
