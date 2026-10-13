"""Сборка AmneziaWG 3.x на Docker до 20.10.

Профиль seccomp старого Docker отвечает EPERM на незнакомые ему системные
вызовы, а musl в Alpine 3.14+ откатывается с faccessat2 только по ENOSYS. В
итоге make внутри docker build падал с "/bin/sh: Operation not permitted"
(Ubuntu 20.04, Docker 19.03). На таком Docker бинари компилируются в docker run
без seccomp, а образ собирается поверх готовых.
"""

import re
from fnmatch import fnmatch

import pytest

from app import deploy


def _scripts():
    return [
        deploy.build_script_v3("deploy", 47300, deploy.generate_server_config_v3(47300)),
        deploy.build_script_upgrade31(deploy.generate_server_config_v3(47180)["conf"]),
    ]


def _old_patterns(script: str) -> list[str]:
    m = re.search(r'case "\$DV" in (\S+)\) OLDSC=1', script)
    assert m, "нет проверки версии Docker"
    return m.group(1).split("|")


@pytest.mark.parametrize("version,old", [
    ("19.03.14", True),
    ("18.09.1", True),
    ("1.13.1", True),  # docker из старых RHEL/CentOS
    ("20.10.0", False),  # с 20.10 незнакомые вызовы получают ENOSYS
    ("20.10.24", False),
    ("24.0.7", False),
    ("28.5.1", False),
    ("", False),  # версию не узнали - обычная сборка, как раньше
])
def test_old_docker_detection(version, old) -> None:
    patterns = _old_patterns(_scripts()[0])
    assert any(fnmatch(version, p) for p in patterns) is old


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
