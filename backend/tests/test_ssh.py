import json

import httpx

from app import sshops

NEW_SERVER = {
    "name": "de-hz-vpn",
    "host": "198.51.100.37",
    "ssh_port": 2221,
    "ssh_user": "ms-dev",
}


async def _create_server(client: httpx.AsyncClient, auth_headers) -> int:
    response = await client.post("/api/servers", json=NEW_SERVER, headers=auth_headers)
    assert response.status_code == 201
    return response.json()["id"]


async def test_setup_script(client: httpx.AsyncClient, auth_headers) -> None:
    server_id = await _create_server(client, auth_headers)
    response = await client.get(
        f"/api/servers/{server_id}/setup-script", headers=auth_headers
    )
    assert response.status_code == 200
    body = response.json()
    assert body["panel_public_key"].startswith("ssh-ed25519 ")
    script = body["script"]
    assert body["panel_public_key"] in script
    assert "ms-dev" in script
    assert "ufw allow from 203.0.113.7 to any port 2221" in script
    assert "sshd: 203.0.113.7" in script
    assert "ACONTROL SETUP OK" in script


async def test_setup_script_requires_auth(client: httpx.AsyncClient, auth_headers) -> None:
    server_id = await _create_server(client, auth_headers)
    response = await client.get(f"/api/servers/{server_id}/setup-script")
    assert response.status_code == 401


async def test_check_stores_result(
    client: httpx.AsyncClient, auth_headers, monkeypatch
) -> None:
    async def fake_check(host, port, username, key_path, timeout=10):
        assert host == "198.51.100.37"
        assert port == 2221
        assert username == "ms-dev"
        return sshops.CheckResult(
            ok=True,
            hostname="de-hz-vpn",
            docker=True,
            containers=["amnezia-awg2", "caddy"],
            amnezia_containers=["amnezia-awg2"],
        )

    monkeypatch.setattr(sshops, "check_server", fake_check)

    server_id = await _create_server(client, auth_headers)
    response = await client.post(
        f"/api/servers/{server_id}/check", headers=auth_headers
    )
    assert response.status_code == 200
    body = response.json()
    assert body["last_check_ok"] is True
    assert body["last_check_at"] is not None
    info = json.loads(body["last_check_info"])
    assert info["hostname"] == "de-hz-vpn"
    assert info["amnezia_containers"] == ["amnezia-awg2"]


async def test_check_failure_stored(
    client: httpx.AsyncClient, auth_headers, monkeypatch
) -> None:
    async def fake_check(host, port, username, key_path, timeout=10):
        return sshops.CheckResult(ok=False, error="Таймаут подключения")

    monkeypatch.setattr(sshops, "check_server", fake_check)

    server_id = await _create_server(client, auth_headers)
    response = await client.post(
        f"/api/servers/{server_id}/check", headers=auth_headers
    )
    assert response.status_code == 200
    body = response.json()
    assert body["last_check_ok"] is False
    assert "Таймаут" in json.loads(body["last_check_info"])["error"]


async def test_bootstrap_success(
    client: httpx.AsyncClient, auth_headers, monkeypatch
) -> None:
    captured = {}

    async def fake_bootstrap(
        host, port, username, password, public_key, panel_ip,
        become_password=None, timeout=10,
    ):
        captured["password"] = password
        captured["panel_ip"] = panel_ip
        return sshops.BootstrapResult(ok=True, output="ACONTROL SETUP OK: de-hz-vpn")

    async def fake_check(host, port, username, key_path, timeout=10):
        return sshops.CheckResult(
            ok=True, hostname="de-hz-vpn", docker=True,
            containers=["amnezia-awg2"], amnezia_containers=["amnezia-awg2"],
        )

    monkeypatch.setattr(sshops, "bootstrap_server", fake_bootstrap)
    monkeypatch.setattr(sshops, "check_server", fake_check)

    server_id = await _create_server(client, auth_headers)
    response = await client.post(
        f"/api/servers/{server_id}/bootstrap",
        json={"password": "s3cret"},
        headers=auth_headers,
    )
    assert response.status_code == 200
    assert response.json()["last_check_ok"] is True
    assert captured["password"] == "s3cret"
    assert captured["panel_ip"] == "203.0.113.7"


async def test_bootstrap_wrong_password(
    client: httpx.AsyncClient, auth_headers, monkeypatch
) -> None:
    async def fake_bootstrap(*args, **kwargs):
        return sshops.BootstrapResult(ok=False, error="Неверный пароль")

    monkeypatch.setattr(sshops, "bootstrap_server", fake_bootstrap)

    server_id = await _create_server(client, auth_headers)
    response = await client.post(
        f"/api/servers/{server_id}/bootstrap",
        json={"password": "nope"},
        headers=auth_headers,
    )
    assert response.status_code == 400
    assert "Неверный пароль" in response.json()["detail"]


async def test_config_endpoint(client: httpx.AsyncClient, auth_headers) -> None:
    response = await client.get("/api/config", headers=auth_headers)
    assert response.status_code == 200
    body = response.json()
    assert body["default_ssh_user"] == "acontrol"
    assert body["panel_ip"] == "203.0.113.7"


async def test_config_requires_auth(client: httpx.AsyncClient) -> None:
    response = await client.get("/api/config")
    assert response.status_code == 401


def test_bootstrap_script_best_effort_firewall() -> None:
    script = sshops._build_bootstrap_script("ssh-ed25519 AAA key", 2221, "203.0.113.7")
    # критичная часть под set -e, фаервол — после set +e
    assert "set -e" in script
    assert "set +e" in script
    assert script.index("authorized_keys") < script.index("set +e")
    assert "command -v ufw" in script
    assert "command -v firewall-cmd" in script
    assert "[ -f /etc/hosts.allow ]" in script  # трогаем только если есть


def test_setup_script_firewall_guarded() -> None:
    script = sshops.build_setup_script("ssh-ed25519 AAA key", "acontrol", 22, "1.2.3.4")
    assert "command -v ufw" in script
    assert "[ -f /etc/hosts.allow ]" in script
    assert "set +e" in script


def test_parse_check_output() -> None:
    output = "HOST=my-node\namnezia-awg2\namnezia-openvpn-cloak\ncaddy\n"
    result = sshops._parse_check_output(output)
    assert result.hostname == "my-node"
    assert result.docker is True
    assert result.amnezia_containers == ["amnezia-awg2", "amnezia-openvpn-cloak"]


def test_parse_no_docker() -> None:
    result = sshops._parse_check_output("HOST=x\nDOCKER_UNAVAILABLE\n")
    assert result.docker is False
    assert result.containers == []
