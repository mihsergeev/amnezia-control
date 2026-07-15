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
        # H1-H4 (2.0) — восходящие непересекающиеся диапазоны «low-high»
        prev = 4
        for h in ("H1", "H2", "H3", "H4"):
            lo_s, dash, hi_s = str(p[h]).partition("-")
            lo, hi = int(lo_s), int(hi_s)
            assert dash and 4 < lo <= hi and lo >= prev
            prev = hi


def test_server_config_shape() -> None:
    cfg = deploy.generate_server_config(51820)
    assert "[Interface]" in cfg["conf"]
    assert "ListenPort = 51820" in cfg["conf"]
    assert f"PrivateKey = {cfg['priv']}" in cfg["conf"]
    assert len(base64.b64decode(cfg["priv"])) == 32
    assert len(base64.b64decode(cfg["pub"])) == 32
    assert len(base64.b64decode(cfg["psk"])) == 32


def test_server_config_is_awg2() -> None:
    # AmneziaWG 2.0 (точно как приложение): H1-H4 — ДИАПАЗОНЫ «low-high» (признак
    # 2.0; одиночные значения приложение считает Legacy), S3/S4 активны, I1
    # закомментирован (# I1 = …), I2-I5 пустые.
    cfg = deploy.generate_server_config(47180)
    conf = cfg["conf"]
    assert "\n# I1 = " in conf and "\nI1 = " not in conf
    for marker in ("\nS3 = ", "\nS4 = "):
        assert marker in conf, marker
    # H1-H4 — диапазоны
    p = deploy.generate_awg_params()
    for h in ("H1", "H2", "H3", "H4"):
        lo, dash, hi = str(p[h]).partition("-")
        assert dash and int(lo) <= int(hi), f"{h} не диапазон: {p[h]}"


def test_server_cps_roundtrips_to_client() -> None:
    # закомментированный I1 в серверном конфиге панель должна вычитывать (I2-I5
    # пустые), иначе клиент выйдет без CPS и не сойдётся хендшейк с 2.0
    from app import awg

    conf = deploy.generate_server_config(47180)["conf"]
    interface, _ = awg.parse_conf(conf)
    assert interface.get("I1"), "I1 не прочитан из # I1"
    # клиентский конфиг: H — ТЕ ЖЕ диапазоны, что у сервера (в 2.0 заголовки
    # варьируются в пределах диапазона; одиночное значение → клиент отверг бы
    # ответ сервера и хендшейк завис бы). Приложение строит клиента так же.
    client = awg.build_client_config(
        client_private="k", address="10.8.1.2", server_public="s",
        preshared="p", endpoint="1.2.3.4:47180", params=interface, dns="1.1.1.1",
    )
    import re as _re
    for h in ("H1", "H2", "H3", "H4"):
        m = _re.search(rf"^{h} = (\d+-\d+)$", client, _re.M)
        assert m, f"{h} в клиенте не диапазон"
        assert m.group(1) == interface[h], f"{h} клиента != сервера"
    assert "\nI1 = " in client and "\nI2 = " not in client  # I1 активен, I2 пуст


def test_build_script_upgrades_legacy_without_clients() -> None:
    # передеплой: legacy-конфиг (без I1) и без пиров → пересоздать как 2.0
    cfg = deploy.generate_server_config(47180)
    script = deploy.build_script("deploy", 47180, cfg)
    # I1 активный ИЛИ закомментированный (# I1) считаем 2.0
    assert 'grep -qE "^#? *I1"' in script
    assert 'grep -c "^\\[Peer\\]"' in script  # проверка отсутствия клиентов
    assert "пересоздаю как AmneziaWG 2.0" in script


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

    # свой определяем по ОБРАЗУ (acontrol-awg), не по имени: формат "name\timage".
    # чужой legacy рядом с панельным awg2 → чужой обнаружен, awg2 (acontrol-awg) нет
    assert await deploy.foreign_awg_container(
        C("amnezia-awg\tamneziavpn/amnezia-wg\namnezia-awg2\tacontrol-awg:latest\n")
    ) == "amnezia-awg"
    # КРИТИЧНО: чужой amnezia-awg2 (образ Amnezia) — тоже чужой, хоть имя как у панели
    assert await deploy.foreign_awg_container(
        C("amnezia-awg2\tamneziavpn/amneziawg-go:latest\n")
    ) == "amnezia-awg2"
    # два протокола сразу → оба чужие
    assert await deploy.foreign_awg_containers(
        C("amnezia-awg\tamneziavpn/amnezia-wg\namnezia-awg2\tamneziavpn/amneziawg-go\n")
    ) == ["amnezia-awg", "amnezia-awg2"]
    # только панельный (образ acontrol-awg) → безопасно, чужих нет
    assert await deploy.foreign_awg_container(C("amnezia-awg2\tacontrol-awg\n")) is None
    assert await deploy.foreign_awg_container(C("")) is None


async def test_detect_awg_containers_splits_new_and_legacy():
    """Детектор делит awg-контейнеры на new (awg0) и legacy (wg0) по рантайм-конфигу."""
    from app import awg

    class C:
        def __init__(self, out):
            self.out = out

        async def run(self, cmd, input=None, check=False):  # noqa: A002
            return type("R", (), {"stdout": self.out, "stderr": "", "exit_status": 0})()

    res = await awg.detect_awg_containers(C("amnezia-awg2 new\namnezia-awg legacy\n"))
    assert res == {"new": "amnezia-awg2", "legacy": "amnezia-awg"}
    # только новый
    res2 = await awg.detect_awg_containers(C("amnezia-awg2 new\n"))
    assert res2 == {"new": "amnezia-awg2", "legacy": None}
    # только legacy
    res3 = await awg.detect_awg_containers(C("amnezia-awg legacy\n"))
    assert res3 == {"new": None, "legacy": "amnezia-awg"}


async def test_snapshot_all_awg_backs_up_every_container():
    """Пре-оп бэкап: snapshot_all снимает КАЖДЫЙ awg-контейнер (и legacy, и awg2),
    чтобы любую операцию можно было откатить (регресс ru-be 12.07 — awg2 снесли
    без снимка)."""
    calls = []

    class C:
        async def run(self, cmd, input=None, check=False):  # noqa: A002
            calls.append(cmd)
            if 'ps --format' in cmd and 'grep -iE "amnezia-awg' in cmd:
                return type("R", (), {
                    "stdout": "amnezia-awg\tamneziavpn/amnezia-wg\n"
                              "amnezia-awg2\tamneziavpn/amneziawg-go\n"
                })()
            return type("R", (), {"stdout": "SNAP 20260712-130000\n"})()

    made = await deploy.snapshot_all(C(), "awg")
    assert made == 2  # сняты оба контейнера
    snaps = [c for c in calls if "tar -czf" in c]
    assert any("C=amnezia-awg;" in c for c in snaps)   # legacy
    assert any("C=amnezia-awg2;" in c for c in snaps)  # awg2


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


def test_build_script_adopt_detects_port_and_removes_only_target():
    """Adopt: порт берётся из самого конфига (у клиента он может отличаться),
    а перед созданием сносится ТОЛЬКО контейнер на целевом порту и свой прежний
    ($CONT) — НЕ любой amnezia-awg*, иначе убьётся сосед-протокол на другом порту
    (инцидент ru-be 12.07). Порт-совпадение сохраняет и фикс инцидента uz."""
    s = deploy.build_script("adopt", 47180, deploy.generate_server_config(47180))
    assert 'DPORT=$(sudo grep -iE "^ *ListenPort" "$D/awg0.conf"' in s
    assert "[ -n \"$DPORT\" ] && PORT=$DPORT" in s
    # снос по порту + своему имени, а НЕ по подстроке name=amnezia-awg
    assert '--filter "publish=$PORT"' in s
    assert '--filter "name=^${CONT}$"' in s
    assert 'docker ps -aq --filter "name=amnezia-awg"' not in s  # больше не сносим всё
    # снос идёт ДО docker run нового контейнера
    assert s.index('--filter "publish=$PORT"') < s.index("docker run -d --name $CONT")
    # legacy-раскладка: если awg0.conf нет, нормализуем wg0.conf в awg0.conf
    assert 'cat "/opt/amnezia/awg/wg0.conf"' in s
    assert 'sudo tee "$D/awg0.conf"' in s


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
        # битая/оборванная распаковка (tar!=0) больше не рапортует успех
        assert await deploy.restore_snapshot(C("RESTORE_FAIL\n"), tag, "20260710-023528") is False
        with pytest.raises(ValueError):
            await deploy.restore_snapshot(C(), tag, "x; rm -rf /")
    snaps = await deploy.list_snapshots(
        C("20260710-023528|3\n20260709-010101|0\n"), "xray"
    )
    assert snaps == [
        {"id": "20260710-023528", "clients": 3},
        {"id": "20260709-010101", "clients": 0},
    ]
