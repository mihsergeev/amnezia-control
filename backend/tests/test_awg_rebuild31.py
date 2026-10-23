"""Пересборка amnezia-awg2, обновленного до 3.1 на месте, и откат движка.

Кнопка "Обновить/Переустановить" на вкладке 2.0 пересобирала контейнер из
образа 2.x, а конфиг сохраняла. После обновления на месте конфиг уже 3.1, и
движок 2.x его не поднимает: отвалились бы все клиенты ноды. Такой контейнер
пересобираем движком 3.1 с тем же конфигом.

Пересборка 3.x к тому же оставляла прежний образ безымянным, и откатить движок,
если новый не понравится клиентам, было не на что.
"""

import base64
import shutil
import subprocess
from types import SimpleNamespace

import pytest

from app import awg, deploy, deploywatch
from app.api import awg as awg_api

CONF_31 = deploy.generate_server_config_v3(47180)["conf"]


def test_rebuild_keeps_the_config_as_is() -> None:
    s = deploy.build_script_upgrade31(CONF_31, rebuild=True)
    # конфиг уходит на ноду дословно: те же ключи, порт, S1-S4 и пиры
    assert base64.b64encode(CONF_31.encode()).decode() in s
    assert "перевыпуск" not in s
    # обычное обновление до 3.1 по-прежнему предупреждает про перевыпуск
    assert "перевыпуск" in deploy.build_script_upgrade31(CONF_31)


def _prev_lines(script: str) -> str:
    lines = script.splitlines()
    i = next(n for n, x in enumerate(lines) if x.startswith("PREV="))
    return "\n".join(lines[i:i + 2])


@pytest.mark.skipif(shutil.which("bash") is None, reason="нужен bash")
@pytest.mark.parametrize("script", [
    deploy.build_script_v3("update", 47300, deploy.generate_server_config_v3(47300)),
    deploy.build_script_upgrade31(CONF_31, rebuild=True),
])
@pytest.mark.parametrize("running,tagged", [("sha256:abc", True), ("", False)])
def test_previous_image_is_kept_for_rollback(script, running, tagged) -> None:
    # до сборки образ живого контейнера получает тег :prev; без контейнера
    # (первая установка) шаг молча пропускается и не роняет set -e
    assert script.index("PREV=") < script.index("OLDSC=0")
    prog = (
        "set -e; IMG=acontrol-awg3; CONT=amnezia-awg3; log(){ :; }\n"
        f'sudo() {{ "$@"; }}; docker() {{ case "$1" in inspect) '
        f'[ -n "{running}" ] && echo {running} || return 1;; '
        'tag) echo "TAG $2 $3";; esac; }\n'
        f"{_prev_lines(script)}\necho END\n"
    )
    out = subprocess.run(
        [shutil.which("bash"), "-c", prog], capture_output=True, text=True
    )
    assert out.stdout.strip().endswith("END"), out.stderr
    assert ("TAG sha256:abc acontrol-awg3:prev" in out.stdout) is tagged


class _DummyConn:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False


@pytest.mark.parametrize("conf,rebuild31", [
    (CONF_31, True),
    ("[Interface]\nListenPort = 47180\nJc = 4\nS1 = 116\n", False),
])
async def test_update_on_inplace_31_uses_31_engine(
    client, auth_headers, monkeypatch, conf, rebuild31
) -> None:
    r = await client.post("/api/servers", json={
        "name": "vpn-a", "host": "203.0.113.10", "ssh_port": 2221, "ssh_user": "amn",
    }, headers=auth_headers)
    sid = r.json()["id"]
    params, _ = awg.parse_conf(conf)
    launched: list[str] = []

    async def fake_none(*a, **kw):
        return None

    async def fake_hub():
        return {}

    async def fake_containers(conn):
        return {"new": deploy.CONTAINER, "legacy": None}

    async def fake_state(conn, host, container=None):
        return SimpleNamespace(container=deploy.CONTAINER, interface="awg0", params=params)

    async def fake_conf(conn, container, interface="awg0"):
        return conf

    async def fake_launch(conn, script, tag="awg"):
        launched.append(script)

    monkeypatch.setattr(awg_api, "_connect", lambda server: _DummyConn())
    monkeypatch.setattr(deploy, "foreign_awg_container", fake_none)
    monkeypatch.setattr(deploy, "hub_info", fake_hub)
    monkeypatch.setattr(deploy, "snapshot_all", fake_none)
    monkeypatch.setattr(deploy, "launch", fake_launch)
    monkeypatch.setattr(awg, "detect_awg_containers", fake_containers)
    monkeypatch.setattr(awg, "read_state", fake_state)
    monkeypatch.setattr(awg, "read_awg_conf", fake_conf)
    monkeypatch.setattr(deploywatch, "spawn", lambda *a, **kw: None)

    r = await client.post(f"/api/servers/{sid}/awg/update", headers=auth_headers)
    assert r.status_code == 202
    (script,) = launched
    assert (f"IMG={deploy.IMAGE_INPLACE_31}" in script) is rebuild31
    if rebuild31:
        assert base64.b64encode(conf.encode()).decode() in script
