import base64
import shutil
import subprocess
from contextlib import asynccontextmanager

import httpx
import pytest

from app import cascadejob, egresscheck, geo
from app.models import Server

OUT = """EC_CONTAINER=amnezia-awg3
EC_EGRESS=198.51.100.20
EC_LOCAL=203.0.113.10
EC_SITE=Google 204 0.153
EC_SITE=Telegram 000 0
EC_SITE=Instagram 200 1.2
"""


def _script(cmd: str) -> str:
    return base64.b64decode(cmd.split()[1]).decode()


@pytest.mark.skipif(shutil.which("bash") is None, reason="нужен bash")
def test_command_is_valid_shell() -> None:
    for country in ("RU", "FI", ""):
        r = subprocess.run([shutil.which("bash"), "-n"], input=_script(egresscheck.build_command(country)),
                           capture_output=True, text=True)
        assert r.returncode == 0, r.stderr


def test_command_runs_in_container_network() -> None:
    script = _script(egresscheck.build_command("RU"))
    # путь клиентов: сеть контейнера, curl хоста; сервис DNS контейнера там не нужен
    assert 'nsenter -t "$P" -n curl' in script and "--resolve" in script
    assert "https://ip.nic.ru" in script
    assert "Telegram=https://telegram.org/" in script
    # для страны без своего сервиса адреса местный адрес не спрашиваем
    assert "ip.nic.ru" not in _script(egresscheck.build_command("FI"))


def test_parse() -> None:
    res = egresscheck.parse(OUT + "EC_EGRESS=junk\n")
    assert res["container"] == "amnezia-awg3" and res["local"] == "203.0.113.10"
    # мусор вместо адреса - пусто
    assert res["egress"] == ""
    res = egresscheck.parse(OUT)
    assert res["egress"] == "198.51.100.20"
    assert res["sites"] == [
        {"name": "Google", "ok": True, "code": 204, "ms": 153},
        {"name": "Telegram", "ok": False, "code": 0, "ms": 0},
        {"name": "Instagram", "ok": True, "code": 200, "ms": 1200},
    ]
    assert egresscheck.parse("EC_ERROR=нет VPN-контейнеров\n")["error"] == "нет VPN-контейнеров"


async def test_endpoint(client: httpx.AsyncClient, auth_headers, session_factory, monkeypatch) -> None:
    async with session_factory() as s:
        s.add(Server(id=7, name="vpn-a", host="203.0.113.10", ssh_port=22, ssh_user="acontrol",
                     country="RU"))
        await s.commit()

    class Conn:
        async def run(self, cmd, check=False, timeout=None):
            return type("R", (), {"stdout": OUT})()

    @asynccontextmanager
    async def fake_connect(server, settings=None):
        yield Conn()

    async def fake_info(ip):
        return "FI", "Example Hosting"

    monkeypatch.setattr(cascadejob, "connect", fake_connect)
    monkeypatch.setattr(geo, "ip_info", fake_info)
    r = await client.post("/api/servers/7/egress-check", headers=auth_headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["egress"] == "198.51.100.20" and body["egress_country"] == "FI"
    assert [x["name"] for x in body["sites"] if not x["ok"]] == ["Telegram"]
