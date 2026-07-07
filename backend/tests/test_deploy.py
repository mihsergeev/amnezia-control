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
