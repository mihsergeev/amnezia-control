import base64
import re

from app import deploy


def test_awg_params_constraints() -> None:
    for _ in range(200):
        p = deploy.generate_awg_params()
        assert 3 <= p["Jc"] <= 10
        assert p["Jmin"] < p["Jmax"] <= 1280 or p["Jmax"] <= p["Jmin"] + 900
        assert p["S1"] != p["S2"]
        assert p["S1"] + 56 != p["S2"]
        assert p["S2"] + 56 != p["S1"]
        hs = [p["H1"], p["H2"], p["H3"], p["H4"]]
        assert len(set(hs)) == 4
        assert all(h > 4 for h in hs)


def test_server_config_shape() -> None:
    cfg = deploy.generate_server_config(51820)
    assert "[Interface]" in cfg["conf"]
    assert "ListenPort = 51820" in cfg["conf"]
    assert f"PrivateKey = {cfg['priv']}" in cfg["conf"]
    assert len(base64.b64decode(cfg["priv"])) == 32
    assert len(base64.b64decode(cfg["pub"])) == 32
    assert len(base64.b64decode(cfg["psk"])) == 32


def test_build_script_deploy() -> None:
    cfg = deploy.generate_server_config(47180)
    script = deploy.build_script("deploy", 47180, cfg)
    assert "docker build -t $IMG" in script
    assert "docker pull amneziavpn/amneziawg-go:latest" in script  # для digest-версии
    assert 'if [ ! -f "$D/awg0.conf" ]; then' in script  # сохранение конфига
    assert "DEPLOY_DONE" in script
    assert "trap 'echo DEPLOY_ERROR' ERR" in script


def test_build_script_update_pulls() -> None:
    cfg = deploy.generate_server_config(47180)
    script = deploy.build_script("update", 47180, cfg)
    assert "docker pull amneziavpn/amneziawg-go:latest" in script


def test_embedded_dockerfile_decodes() -> None:
    cfg = deploy.generate_server_config(47180)
    script = deploy.build_script("deploy", 47180, cfg)
    # находим base64-блоб Dockerfile и проверяем, что он декодируется в наш Dockerfile
    b64s = re.findall(r"echo ([A-Za-z0-9+/=]{40,}) \| base64 -d", script)
    decoded = [base64.b64decode(b).decode() for b in b64s]
    assert any("FROM amneziavpn/amneziawg-go:latest" in d for d in decoded)
    assert any("[Interface]" in d for d in decoded)  # конфиг тоже вшит


def test_start_sh_and_systemd_present() -> None:
    assert "exec tail -f /dev/null" in deploy.START_SH
    unit = deploy._systemd_unit()
    assert "After=docker.service" in unit
    assert "amnezia-awg2" in unit


class _FakeConn:
    """Мини-заглушка asyncssh-соединения: помнит команды, отдаёт содержимое
    файлов по `cat "<path>"`."""

    def __init__(self, files: dict[str, str]):
        self.files = files
        self.cmds: list[str] = []

    async def run(self, cmd, input=None, check=False):  # noqa: A002
        self.cmds.append(cmd)
        m = re.search(r'cat "([^"]+)" 2>/dev/null', cmd)
        stdout = self.files.get(m.group(1), "") if m else ""
        return type("R", (), {"stdout": stdout})()


async def test_deploy_status_isolated_per_protocol():
    """Регресс: обновление одного протокола не должно показывать лог другого
    (раньше был общий /tmp/acontrol/deploy.log — AWG показывал лог XRay)."""
    xray_log = deploy._paths("xray")[2]
    conn = _FakeConn({xray_log: "docker build (xray)\nDEPLOY_DONE"})
    awg = await deploy.read_status(conn, tag="awg")
    xray = await deploy.read_status(conn, tag="xray")
    assert awg["state"] == "unknown"  # AWG НЕ видит лог XRay
    assert "DEPLOY_DONE" not in awg["log"]
    assert xray["state"] == "done"  # XRay видит свой лог


async def test_launch_uses_tagged_home_path():
    conn = _FakeConn({})
    await deploy.launch(conn, "echo hi\n", tag="openvpn")
    joined = " ".join(conn.cmds)
    assert '$HOME/.acontrol/openvpn/run.sh' in joined
    assert '/tmp/acontrol' not in joined  # больше не общий /tmp
    assert '.acontrol/awg' not in joined  # и не чужой протокол


async def test_foreign_awg_container_detection():
    class C:
        def __init__(self, out):
            self.out = out

        async def run(self, cmd, input=None, check=False):  # noqa: A002
            return type("R", (), {"stdout": self.out})()

    # исходный (не панельный) контейнер обнаружен → deploy/update заблокируются
    assert await deploy.foreign_awg_container(C("amnezia-awg\namnezia-awg2\n")) == "amnezia-awg"  # noqa: E501
    # только панельный amnezia-awg2 → безопасно
    assert await deploy.foreign_awg_container(C("amnezia-awg2\n")) is None
    assert await deploy.foreign_awg_container(C("")) is None


async def test_awg_adoptable_requires_awg0conf():
    """Adopt разрешён только настоящему AmneziaWG (awg0.conf). Клиентский
    plain-WireGuard (wg0.conf → команда test -f вернёт NO) — не переносим."""
    class C:
        def __init__(self, out):
            self.out = out

        async def run(self, cmd, input=None, check=False):  # noqa: A002
            return type("R", (), {"stdout": self.out})()

    assert await deploy.awg_adoptable(C("YES\n"), "amnezia-awg") is True
    assert await deploy.awg_adoptable(C("NO\n"), "amnezia-awg") is False
    # инъекция/мусор в имени контейнера отсекается без запуска команды
    assert await deploy.awg_adoptable(C("YES\n"), "amnezia-awg; rm -rf /") is False
    assert await deploy.awg_adoptable(C("YES\n"), "") is False


def test_build_script_preserves_live_config_before_guard():
    """Регресс de-hz 10.07: пересборка должна вытаскивать конфиг из ЖИВОГО
    контейнера на хост ДО guard, иначе guard сгенерит пустой и затрёт клиентов.
    Источник — клиентский amnezia-awg (adopt) в приоритете, иначе amnezia-awg2."""
    s = deploy.build_script("update", 47180, deploy.generate_server_config(47180))
    assert 'grep -ix "amnezia-awg"' in s  # приоритет клиентскому контейнеру
    assert 'docker exec "$SRC" cat "/opt/amnezia/awg/$f"' in s
    assert 'base64 -d | sudo tee "$D/$f"' in s
    # preserve идёт ДО guard [ ! -f awg0.conf ]
    assert s.index('docker exec "$SRC" cat') < s.index('if [ ! -f "$D/awg0.conf" ]')


def test_build_script_adopt_detects_port_and_removes_parallel():
    """Adopt: порт берётся из самого конфига (у клиента он может отличаться),
    а перед созданием сносится ЛЮБОЙ amnezia-awg* — чтобы не остался
    параллельный контейнер (инцидент uz)."""
    s = deploy.build_script("adopt", 47180, deploy.generate_server_config(47180))
    assert 'DPORT=$(sudo grep -iE "^ *ListenPort" "$D/awg0.conf"' in s
    assert "[ -n \"$DPORT\" ] && PORT=$DPORT" in s
    assert 'docker ps -aq --filter "name=amnezia-awg"' in s
    # снос параллельного идёт ДО docker run нового контейнера
    assert s.index('--filter "name=amnezia-awg"') < s.index("docker run -d --name $CONT")


async def test_snapshot_helpers_all_protocols():
    import pytest

    class C:
        def __init__(self, out=""):
            self.out = out

        async def run(self, cmd, check=False):  # noqa: A002
            return type("R", (), {"stdout": self.out})()

    for tag in ("awg", "xray", "openvpn"):
        assert await deploy.snapshot_config(C("SNAP 20260710-023528\n"), tag) == "20260710-023528"
        assert await deploy.snapshot_config(C("NO_CONT\n"), tag) is None
        assert await deploy.restore_snapshot(C("RESTORE_OK\n"), tag, "20260710-023528") is True
        assert await deploy.restore_snapshot(C("NO_SNAP\n"), tag, "20260710-023528") is False
        with pytest.raises(ValueError):
            await deploy.restore_snapshot(C(), tag, "x; rm -rf /")
    snaps = await deploy.list_snapshots(
        C("20260710-023528|3\n20260709-010101|0\n"), "xray"
    )
    assert snaps == [
        {"id": "20260710-023528", "clients": 3},
        {"id": "20260709-010101", "clients": 0},
    ]
