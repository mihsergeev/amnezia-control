import os
import shutil
import subprocess

import pytest

from app import deploy


@pytest.mark.skipif(shutil.which("bash") is None, reason="requires bash")
@pytest.mark.parametrize(("state", "actions", "success"), [
    ("ready", [], True),
    ("missing", ["up"], True),
    ("partial", ["down", "up"], True),
    ("broken", ["up"], False),
])
def test_awg3_boot_keeps_ready_peers_and_repairs_an_incomplete_interface(tmp_path, state, actions, success):
    scripts = {
        "awg": 'if [ "$STATE" = ready ] || [ -f started ]; then echo 47300; else echo 0; fi',
        "ip": (
            'case "$*" in\n'
            "'-o -4 addr show up dev awg0 scope global')\n"
            '  if [ "$STATE" = ready ] || [ -f started ]; then echo "awg0 up"; fi;;\n'
            "'link show dev awg0') [ \"$STATE\" = partial ];;\n"
            "'-4 route show dev awg0 proto kernel scope link') echo 10.8.3.0/24;;\n"
            'esac'
        ),
        "awg-quick": (
            'printf "%s\\n" "$1" >> actions\n'
            'if [ "$1" = up ]; then [ "$STATE" != broken ] && touch started; fi'
        ),
        "iptables": 'case " $* " in *" -D "*) exit 1;; esac',
    }
    for command, script in scripts.items():
        target = tmp_path / command
        target.write_text("#!/bin/sh\n" + script + "\n", encoding="utf-8", newline="\n")
        target.chmod(0o755)

    env = os.environ | {"STATE": state}
    # Git Bash needs a POSIX path in its PATH, including when pytest runs from C:.
    path = f'export PATH="$(cygpath -u \'{tmp_path.as_posix()}\'):$PATH"\n' if os.name == "nt" else ""
    if os.name != "nt":
        env["PATH"] = str(tmp_path) + os.pathsep + env["PATH"]
    result = subprocess.run(["bash", "-s"], input=(path + deploy._boot_bringup_v3()).encode(),
                            cwd=tmp_path, env=env, capture_output=True, timeout=10)
    assert (result.returncode == 0) is success, result.stderr
    log = tmp_path / "actions"
    assert (log.read_text().splitlines() if log.exists() else []) == actions


def test_awg3_unit_keeps_explicit_reload_available_for_config_changes():
    assert "ready()" in deploy._systemd_unit_v3()
    assert "ready()" not in deploy._systemd_unit_v3(legacy=True)
    assert deploy._bringup(deploy.SUBNET_V3).startswith("awg-quick down ")
