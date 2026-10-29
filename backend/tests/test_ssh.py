import json

import httpx

from app import sshops

NEW_SERVER = {
    "name": "de-hz-vpn",
    "host": "198.51.100.37",
    "ssh_port": 2221,
    "ssh_user": "ms-dev",
}


def _refuse_connect(*args, **kwargs):
    raise OSError("no network in tests")


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
    monkeypatch.setattr(sshops, "connect", _refuse_connect)

    server_id = await _create_server(client, auth_headers)
    response = await client.post(
        f"/api/servers/{server_id}/check", headers=auth_headers
    )
    assert response.status_code == 200
    body = response.json()
    assert body["last_check_ok"] is True
    # адрес выхода не узнали - схемы нет
    assert body["egress_ip"] == ""
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
        become_password=None, timeout=10, key_path=None,
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


class _Conn:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False


async def test_check_stores_cascade_egress(
    client: httpx.AsyncClient, auth_headers, monkeypatch
) -> None:
    from app import geo

    async def fake_check(host, port, username, key_path, timeout=10):
        return sshops.CheckResult(
            ok=True, docker=True,
            containers=["amnezia-awg3"], amnezia_containers=["amnezia-awg3"],
        )

    async def fake_probe(conn):
        return "203.0.113.9"

    async def fake_info(ip):
        assert ip == "203.0.113.9"
        return "FI", "Example Hosting"

    monkeypatch.setattr(sshops, "check_server", fake_check)
    monkeypatch.setattr(sshops, "connect", lambda *a, **k: _Conn())
    monkeypatch.setattr(sshops, "probe_egress", fake_probe)
    monkeypatch.setattr(geo, "ip_info", fake_info)

    server_id = await _create_server(client, auth_headers)
    response = await client.post(
        f"/api/servers/{server_id}/check", headers=auth_headers
    )
    body = response.json()
    assert body["egress_ip"] == "203.0.113.9"
    assert body["egress_country"] == "FI"
    assert body["egress_org"] == "Example Hosting"
    assert body["egress_at"] is not None


async def test_check_egress_same_as_host_is_direct(
    client: httpx.AsyncClient, auth_headers, monkeypatch
) -> None:
    async def fake_check(host, port, username, key_path, timeout=10):
        return sshops.CheckResult(
            ok=True, docker=True,
            containers=["amnezia-xray"], amnezia_containers=["amnezia-xray"],
        )

    async def fake_probe(conn):
        return NEW_SERVER["host"]

    monkeypatch.setattr(sshops, "check_server", fake_check)
    monkeypatch.setattr(sshops, "connect", lambda *a, **k: _Conn())
    monkeypatch.setattr(sshops, "probe_egress", fake_probe)

    server_id = await _create_server(client, auth_headers)
    body = (
        await client.post(f"/api/servers/{server_id}/check", headers=auth_headers)
    ).json()
    assert body["egress_ip"] == ""
    assert body["egress_at"] is not None


def test_parse_egress_output() -> None:
    assert sshops._parse_egress_output("EGRESS=203.0.113.9\n") == "203.0.113.9"
    assert sshops._parse_egress_output("") == ""
    assert sshops._parse_egress_output("EGRESS=<html>1.2.3</html>\n") == ""
    assert sshops._parse_egress_output("EGRESS=127.0.0.1\n") == ""


def test_egress_command_probes_inside_amnezia_container() -> None:
    # клиентский трафик идет из контейнера, у каскадов он выходит не с адреса ноды
    assert "grep -i '^amnezia'" in sshops.EGRESS_COMMAND
    assert '$D exec "$c"' in sshops.EGRESS_COMMAND


# так `ip -o -d link show type gre` печатает поднятый туннель и служебный gre0
_GRE_UP = (
    "6: gre-a@NONE: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1476 qdisc noqueue state UNKNOWN"
    " \\    link/gre 198.51.100.5 peer 203.0.113.9 \\    gre remote 203.0.113.9"
    " local 198.51.100.5 ttl 64"
)
_GRE_IDLE = (
    "3: gre0@NONE: <NOARP> mtu 1476 qdisc noop state DOWN \\    link/gre 0.0.0.0"
    " \\    gre remote any local any ttl inherit"
)


def test_parse_check_output_gre_tunnels() -> None:
    out = f"HOST=x\nGRELINK={_GRE_UP}\nGRELINK={_GRE_IDLE}\namnezia-xray\n"
    result = sshops._parse_check_output(out)
    # служебный gre0 без адреса - не туннель; строки GRELINK не попадают в контейнеры
    assert result.tunnels == [{"kind": "gre", "name": "gre-a", "remote": "203.0.113.9"}]
    assert result.containers == ["amnezia-xray"]
    assert result.as_dict()["tunnels"] == result.tunnels


def test_egress_probe_leaves_no_ssl_client_zombies():
    # busybox wget по https оставлял сироту ssl_client у PID 1 контейнера:
    # https только через curl, wget только по http
    cmd = sshops.EGRESS_COMMAND
    assert "curl -fsS -m 6 https://$u" in cmd
    assert "wget -qO- -T 6 http://$u" in cmd
    assert "wget -qO- -T 6 https" not in cmd
    # доступ к docker по правам на сокет, без docker info и docker ps на каждом шаге
    assert "docker info" not in cmd and "docker ps >/dev/null" not in cmd


def test_docker_prefix_without_docker_info():
    from app import awg, deploy, fullaccess, openvpn, xray
    import inspect

    for mod in (awg, deploy, fullaccess, openvpn, sshops, xray):
        assert "docker info >" not in inspect.getsource(mod), mod.__name__
    assert "[ -w /var/run/docker.sock ]" in awg._DOCKER
