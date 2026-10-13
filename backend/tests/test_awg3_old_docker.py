"""Сборка AmneziaWG 3.x на Docker со старым seccomp.

Профиль seccomp старого Docker отвечает EPERM на незнакомые ему системные
вызовы, а musl в Alpine 3.14+ откатывается с faccessat2 только по ENOSYS. В
итоге make внутри docker build падал с "/bin/sh: Operation not permitted"
(Ubuntu 20.04: Docker 19.03, а также 20.10.1 с runc 1.0.0-rc92). На таком
Docker бинари компилируются в docker run без seccomp, а образ собирается
поверх готовых.
"""

import re
import shutil
import subprocess

import pytest

from app import deploy


def _scripts():
    return [
        deploy.build_script_v3("deploy", 47300, deploy.generate_server_config_v3(47300)),
        deploy.build_script_upgrade31(deploy.generate_server_config_v3(47180)["conf"]),
    ]


def _probe_line(script: str) -> str:
    line = next(x for x in script.splitlines() if "OLDSC=0" in x)
    # проба - make в Alpine под обычным seccomp, а не номер версии Docker:
    # 20.10.1 с runc rc92 ломается так же, как 19.03
    assert line.startswith("if sudo docker run --rm alpine:")
    assert "make -s -f /tmp/m" in line and "seccomp" not in line
    return line


@pytest.mark.skipif(shutil.which("bash") is None, reason="нужен bash")
@pytest.mark.parametrize("probe_rc,old", [(0, "0"), (2, "1"), (127, "1")])
def test_probe_decides_build_path(probe_rc, old) -> None:
    # make упал (или его не поставить) - идем в сборку без seccomp
    line = _probe_line(_scripts()[0])
    prog = (
        f'sudo() {{ "$@"; }}; docker() {{ return {probe_rc}; }}\n'
        f"{line}\necho $OLDSC\n"
    )
    # полный путь: на Windows голое "bash" находит bash.exe из WSL в System32
    out = subprocess.run(
        [shutil.which("bash"), "-c", prog], capture_output=True, text=True
    )
    assert out.stdout.strip() == old, out.stderr


@pytest.mark.parametrize("script", _scripts())
def test_old_docker_compiles_without_seccomp(script) -> None:
    start = script.index('if [ "$OLDSC" = 1 ]')
    branch = script[start:script.index("\nfi\n", start)]
    old, new = branch.split("\nelse\n")
    # компиляция в docker run без seccomp, оба бинаря на закрепленных тегах
    assert old.count("--security-opt seccomp=unconfined") == 2
    assert deploy.AWG3_GO_TAG in old and deploy.AWG3_TOOLS_TAG in old
    # и образ поверх готовых бинарей, без стадий компиляции
    assert '-f "$BUILD/Dockerfile.prebuilt"' in old
    # обычный путь не изменился
    assert 'sudo docker build -t $IMG "$BUILD"' in new
    assert "seccomp" not in new


def test_prebuilt_image_matches_regular_final_stage() -> None:
    # финальный образ одинаковый на любом Docker, отличается только источник бинарей
    regular = deploy._dockerfile_v3()
    final = regular[regular.rindex("FROM "):]
    prebuilt = deploy._dockerfile_v3_prebuilt()
    src = re.compile(r"^COPY .+ (/usr/bin/\S+)$", re.M)
    assert src.sub(r"COPY X \1", prebuilt) == src.sub(r"COPY X \1", final)
    assert "golang" not in prebuilt and "make" not in prebuilt
    for name in ("amneziawg-go", "awg", "awg-quick"):
        assert f"COPY bin/{name} /usr/bin/{name}" in prebuilt


def test_compiled_binaries_are_reused() -> None:
    # повторная установка на старом Docker не компилирует заново, пока теги те же
    s = _scripts()[0]
    want = f"go={deploy.AWG3_GO_TAG} tools={deploy.AWG3_TOOLS_TAG}"
    assert f'!= "{want}" ]' in s
    assert f'echo "{want}" | sudo tee "$BIN/.tags"' in s
