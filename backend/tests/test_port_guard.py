"""Проверка порта перед установкой протокола.

Случай 08.10.2026: XRay на vpn-x-admin ставился на 443, а его держит
caddy, через который открывается сама панель. Установка собрала образ,
сгенерировала ключи, открыла фаервол и только на docker run упала с
"port is already allocated", оставив мертвый контейнер, на который алертил
мониторинг.

Рядом нашлась беда опаснее: сценарий AWG 2.0 сносил все, что публикует целевой
порт, фильтром без протокола, а он видит только TCP. AWG на популярном 443/udp
удалил бы caddy вместе со входом в панель.
"""

import pytest

from app import deploy, openvpn, xray
from app.api import xray as xray_api


class _Result:
    def __init__(self, stdout: str = ""):
        self.stdout = stdout
        self.stderr = ""
        self.exit_status = 0


class _Conn:
    """Подставляет вывод по подстроке команды и запоминает команды."""

    def __init__(self, by_substring: dict | None = None):
        self.by_substring = by_substring or {}
        self.commands: list[str] = []

    async def run(self, cmd, **kw):
        self.commands.append(cmd)
        for sub, out in self.by_substring.items():
            if sub in cmd:
                return _Result(out)
        return _Result()


async def test_busy_port_names_the_container() -> None:
    conn = _Conn({"publish=443/tcp": "caddy-proxy-caddy-1\n"})
    owner = await deploy.port_owner(conn, 443, "tcp", own="amnezia-xray")
    assert owner == "контейнер «caddy-proxy-caddy-1»"
    # проверяется только нужный протокол
    assert "publish=443/tcp" in conn.commands[0]
    assert "publish=443/udp" not in conn.commands[0]


async def test_own_container_is_not_a_conflict() -> None:
    # переустановка поверх себя: порт держит наш же контейнер
    conn = _Conn({"publish=443/tcp": "amnezia-xray\n"})
    assert await deploy.port_owner(conn, 443, "tcp", own="amnezia-xray") is None
    # и до ss дело не доходит: его docker-proxy - тоже наш
    assert not any("ss " in c for c in conn.commands)


async def test_host_process_counts_too() -> None:
    # nginx не в Docker держит порт так же, как контейнер
    ss = 'LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=812,fd=6))'
    conn = _Conn({"-lntpH": ss})
    assert await deploy.port_owner(conn, 443, "tcp") == "процесс «nginx»"


async def test_free_port() -> None:
    assert await deploy.port_owner(_Conn(), 8443, "tcp", own="amnezia-xray") is None


async def test_udp_vpn_next_to_tcp_web_server_is_fine() -> None:
    # AmneziaWG на 443/udp рядом с caddy на 443/tcp - законная схема, а не конфликт
    conn = _Conn({"publish=443/tcp": "caddy-proxy-caddy-1\n", "-lntpH": "LISTEN ..."})
    assert await deploy.port_owner(conn, 443, "udp", own=deploy.CONTAINER) is None
    assert all("publish=443/tcp" not in c for c in conn.commands)
    assert any("-lnupH" in c for c in conn.commands)


def test_busy_detail_mentions_web_server_on_443() -> None:
    text = deploy.port_busy_detail(443, "tcp", "контейнер «caddy-proxy-caddy-1»", "XRay")
    assert "443/tcp" in text and "caddy-proxy-caddy-1" in text and "веб-сервер" in text
    assert "веб-сервер" not in deploy.port_busy_detail(47180, "udp", "x", "AmneziaWG")


@pytest.mark.parametrize("build", [
    lambda: deploy.build_script("deploy", 47180, deploy.generate_server_config(47180)),
    lambda: deploy.build_script_v3("deploy", 47300, deploy.generate_server_config_v3(47300)),
])
def test_awg_scripts_remove_only_udp_holders(build) -> None:
    # TCP-контейнер на том же номере порта (веб-сервер) сценарий AWG не трогает
    s = build()
    assert '--filter "publish=$PORT/udp"' in s
    assert '--filter "publish=$PORT"' not in s


@pytest.mark.parametrize("script", [
    lambda: deploy.build_script("deploy", 47180, deploy.generate_server_config(47180)),
    lambda: deploy.build_script_v3("deploy", 47300, deploy.generate_server_config_v3(47300)),
    lambda: xray.build_deploy_script(8443, "www.example.com"),
    lambda: openvpn.build_deploy_script(8443, "www.example.com", "203.0.113.5"),
])
def test_failed_run_removes_the_container(script) -> None:
    # контейнер, не сумевший стартовать, не должен оставаться в "created":
    # на него алертит мониторинг, а повтор упирается в занятое имя
    s = script()
    run_at = s.index("docker run -d --name")
    tail = s[run_at:run_at + 600]
    assert "docker rm -f" in tail
    assert tail.index("docker rm -f") > tail.index("docker run -d")


def test_xray_script_checks_port_before_building() -> None:
    # страховка для вызовов в обход окна: проверка до сборки и генерации ключей
    s = xray.build_deploy_script(443, "www.example.com")
    assert s.index('publish=$XRAY_SERVER_PORT/tcp') < s.index("docker build")


class _DummyConn:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False


async def test_xray_deploy_on_busy_port_is_refused_before_anything(
    client, auth_headers, monkeypatch
) -> None:
    r = await client.post("/api/servers", json={
        "name": "kz-admin", "host": "203.0.113.10", "ssh_port": 2221, "ssh_user": "amn",
    }, headers=auth_headers)
    sid = r.json()["id"]

    async def fake_release():
        return {"tag": "v26.3.27"}

    async def fake_owner(conn, port, proto, own=""):
        return "контейнер «caddy-proxy-caddy-1»"

    async def must_not_run(*a, **kw):
        raise AssertionError("при занятом порте установка не должна стартовать")

    monkeypatch.setattr(xray_api, "_connect", lambda server: _DummyConn())
    monkeypatch.setattr(xray, "latest_release", fake_release)
    monkeypatch.setattr(deploy, "port_owner", fake_owner)
    monkeypatch.setattr(deploy, "snapshot_all", must_not_run)
    monkeypatch.setattr(deploy, "launch", must_not_run)

    r = await client.post(
        f"/api/servers/{sid}/xray/deploy", json={"port": 443}, headers=auth_headers
    )
    # 409 - окно установки покажет поле выбора порта и подставит 8443
    assert r.status_code == 409
    assert "443/tcp" in r.json()["detail"]
    assert "caddy-proxy-caddy-1" in r.json()["detail"]
