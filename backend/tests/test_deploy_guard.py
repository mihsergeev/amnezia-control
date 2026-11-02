"""Установка протокола поверх идущей и поверх готового конфига на другом порту.

bash читает run.sh по ходу выполнения: второй деплой, пока первый идет, писал
`cat > run.sh` в тот же файл, и прежний bash дочитывал новый текст со старого
смещения. Теперь ручки отвечают 409, а сам скрипт подменяется через mv.
"""

import httpx
import pytest

from app import deploy
from app.api import awg as awg_api
from app.api import awg3 as awg3_api

SERVER = {"name": "n", "host": "203.0.113.5", "ssh_port": 22, "ssh_user": "root"}


class _Result:
    def __init__(self, stdout: str = ""):
        self.stdout = stdout
        self.stderr = ""
        self.exit_status = 0


class _Conn:
    def __init__(self, by_substring: dict | None = None):
        self.by_substring = by_substring or {}
        self.commands: list[str] = []

    async def run(self, cmd, **kw):
        self.commands.append(cmd)
        for sub, out in self.by_substring.items():
            if sub in cmd:
                return _Result(out)
        return _Result()


class _DummyConn:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False


async def _wrap(v):
    return v


async def test_ensure_idle_running_and_alive_is_busy() -> None:
    conn = _Conn({"deploy.log": "[1/6] docker\n", "pgrep": "BUSY\n"})
    with pytest.raises(deploy.DeployBusy):
        await deploy.ensure_idle(conn, tag="awg3")
    # шаблон со скобками: pgrep не находит собственную командную строку
    assert "[.]acontrol/awg3/run[.]sh" in conn.commands[-1]


async def test_ensure_idle_empty_log_and_alive_is_busy() -> None:
    conn = _Conn({"pgrep": "BUSY\n"})
    with pytest.raises(deploy.DeployBusy):
        await deploy.ensure_idle(conn, tag="awg")


async def test_ensure_idle_dead_script_does_not_block() -> None:
    # лог без маркера конца, а процесса нет (ребут ноды посреди установки)
    conn = _Conn({"deploy.log": "[1/6] docker\n"})
    await deploy.ensure_idle(conn, tag="awg")


async def test_ensure_idle_finished_skips_pgrep() -> None:
    conn = _Conn({"deploy.log": "...\nDEPLOY_DONE\n"})
    await deploy.ensure_idle(conn, tag="awg")
    assert not any("pgrep" in c for c in conn.commands)


async def test_launch_replaces_script_via_mv() -> None:
    conn = _Conn()
    await deploy.launch(conn, "echo hi\n", tag="awg")
    write = next(c for c in conn.commands if "cat >" in c)
    assert 'cat > "$HOME/.acontrol/awg/run.sh.tmp"' in write
    assert 'chmod 600 "$HOME/.acontrol/awg/run.sh.tmp"' in write
    assert write.index('chmod 600') < write.index('mv -f')


async def test_launch_does_not_run_previous_script_after_write_failure() -> None:
    class Full(_Conn):
        async def run(self, cmd, **kw):
            self.commands.append(cmd)
            if "cat >" in cmd:
                assert kw["check"] is True
                raise OSError("write failed")
            return _Result()

    conn = Full()
    with pytest.raises(OSError):
        await deploy.launch(conn, "echo hi\n", tag="awg")
    assert not any("nohup" in cmd for cmd in conn.commands)


async def _server(client, auth_headers) -> int:
    r = await client.post("/api/servers", json=SERVER, headers=auth_headers)
    return r.json()["id"]


@pytest.mark.parametrize("path", ["deploy", "update", "adopt", "upgrade31"])
async def test_awg_handlers_refuse_while_deploy_runs(
    client: httpx.AsyncClient, auth_headers, monkeypatch, path
) -> None:
    sid = await _server(client, auth_headers)
    monkeypatch.setattr(awg_api, "_connect", lambda server: _DummyConn())

    async def busy(conn, *, tag):
        assert tag == "awg"
        raise deploy.DeployBusy("Установка уже идет - дождитесь ее окончания и повторите.")

    async def must_not_run(*a, **kw):
        raise AssertionError("launch поверх идущей установки")

    monkeypatch.setattr(deploy, "ensure_idle", busy)
    monkeypatch.setattr(deploy, "launch", must_not_run)
    body = {"port": 47180} if path == "deploy" else None
    r = await client.post(f"/api/servers/{sid}/awg/{path}", json=body, headers=auth_headers)
    assert r.status_code == 409
    assert "уже идет" in r.json()["detail"]


async def test_awg3_deploy_refuses_while_deploy_runs(
    client: httpx.AsyncClient, auth_headers, monkeypatch
) -> None:
    sid = await _server(client, auth_headers)
    monkeypatch.setattr(awg3_api, "_connect", lambda server: _DummyConn())

    async def busy(conn, *, tag):
        assert tag == "awg3"
        raise deploy.DeployBusy("Установка уже идет")

    monkeypatch.setattr(deploy, "ensure_idle", busy)
    r = await client.post(f"/api/servers/{sid}/awg3/deploy", json={"port": 47300},
                          headers=auth_headers)
    assert r.status_code == 409


# --- повторный deploy на другой порт ------------------------------------------


async def test_existing_port_reads_listen_port() -> None:
    conn = _Conn({"ListenPort": "47180"})
    assert await deploy.existing_port(conn) == 47180
    assert "amnezia-awg2" in conn.commands[0]
    conn = _Conn({"ListenPort": "47300"})
    assert await deploy.existing_port(conn, v3=True) == 47300
    assert "/opt/amnezia/awg3/awg0.conf" in conn.commands[0]
    assert await deploy.existing_port(_Conn()) is None


async def test_awg_deploy_other_port_over_existing_config_is_409(
    client: httpx.AsyncClient, auth_headers, monkeypatch
) -> None:
    sid = await _server(client, auth_headers)
    monkeypatch.setattr(awg_api, "_connect", lambda server: _DummyConn())
    monkeypatch.setattr(deploy, "ensure_idle", lambda conn, *, tag: _wrap(None))
    monkeypatch.setattr(awg_api, "_guard_foreign_awg", lambda conn: _wrap(None))
    monkeypatch.setattr(deploy, "existing_port", lambda conn, v3=False: _wrap(47180))

    async def must_not_run(*a, **kw):
        raise AssertionError("launch при чужом порту в конфиге")

    monkeypatch.setattr(deploy, "launch", must_not_run)
    r = await client.post(f"/api/servers/{sid}/awg/deploy", json={"port": 51820},
                          headers=auth_headers)
    assert r.status_code == 409
    assert "47180" in r.json()["detail"]


def test_script_refuses_other_port_only_on_deploy() -> None:
    cfg = deploy.generate_server_config(47180)
    assert "протокол уже стоит на порту $DPORT" in deploy.build_script("deploy", 47180, cfg)
    # update/adopt сохраняют порт конфига намеренно
    assert "уже стоит" not in deploy.build_script("update", 47180, cfg)
    assert "уже стоит" not in deploy.build_script("adopt", 47180, cfg)
    cfg3 = deploy.generate_server_config_v3(47300)
    assert "уже стоит" in deploy.build_script_v3("deploy", 47300, cfg3)
    assert "уже стоит" not in deploy.build_script_v3("update", 47300, cfg3)
