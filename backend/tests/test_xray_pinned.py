"""Панель ставит закрепленную версию xray-core, а не последний релиз GitHub.

22.10.2026 latest на GitHub стал 26.10.21, а с 26.9.8 REALITY-сервер отвергает
ClientHello без ключа X25519MLKEM768: клиенты на sing-box (Hiddify, Karing,
NekoBox) и старые сборки Xray с отпечатком firefox молча перестают подключаться.
Кнопки "Обновить ядро" и "Переустановить" брали latest и отрезали бы их.
"""

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

    async def stats(conn, container):
        return True

    monkeypatch.setattr(xray_api, "_connect", lambda server: _DummyConn())
    monkeypatch.setattr(deploy, "port_owner", nothing)
    monkeypatch.setattr(deploy, "snapshot_all", nothing)
    monkeypatch.setattr(deploy, "snapshot_config", nothing)
    monkeypatch.setattr(deploy, "launch", fake_launch)
    monkeypatch.setattr(deploywatch, "spawn", lambda *a, **kw: None)
    monkeypatch.setattr(xray, "detect_container", container)
    monkeypatch.setattr(xray, "read_server_bits", bits)
    monkeypatch.setattr(xray, "enable_stats", stats)
    return launched


def test_no_github_lookup_left() -> None:
    # последний релиз панель больше не спрашивает вовсе
    assert not hasattr(xray, "latest_release")


def test_version_tuple() -> None:
    assert xray.version_tuple("v26.3.27") == (26, 3, 27)
    assert xray.version_tuple("26.10.21") > xray.version_tuple("v26.3.27")
    assert xray.version_tuple("") == ()


async def test_deploy_installs_pinned(client, auth_headers, node) -> None:
    sid = await _server(client, auth_headers)
    r = await client.post(
        f"/api/servers/{sid}/xray/deploy", json={"port": 8443}, headers=auth_headers
    )
    assert r.status_code == 202
    assert f"XRAY_RELEASE={xray.XRAY_RELEASE}" in node[0]


async def test_update_installs_pinned(client, auth_headers, node) -> None:
    sid = await _server(client, auth_headers)
    r = await client.post(f"/api/servers/{sid}/xray/update", headers=auth_headers)
    assert r.status_code == 202
    assert f"XRAY_RELEASE={xray.XRAY_RELEASE}" in node[0]


@pytest.mark.parametrize("current,offer", [
    ("25.8.3", True),     # старее закрепленной - предлагаем обновить
    (PINNED, False),      # уже на ней
    ("26.10.21", False),  # новее (поставили руками) - не зовем "обновлять"
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
