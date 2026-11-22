import shutil
import subprocess

import pytest

from app import sshops


@pytest.mark.parametrize("line, expected", [("SUDO=root", "root"), ("SUDO=yes", "yes"), ("SUDO=no", "no")])
def test_check_reports_sudo_without_listing_it_as_a_container(line, expected) -> None:
    result = sshops._parse_check_output(f"HOST=node-a\n{line}\namnezia-awg\n")
    assert result.sudo == expected
    assert result.containers == ["amnezia-awg"]
    assert result.as_dict()["sudo"] == expected


def test_old_check_output_leaves_sudo_unknown() -> None:
    # фоновый сбор старых нод и записи до обновления: поле есть, значение пустое
    result = sshops._parse_check_output("HOST=node-a\namnezia-awg\n")
    assert result.sudo == "" and result.as_dict()["sudo"] == ""


@pytest.mark.skipif(shutil.which("bash") is None, reason="requires bash")
@pytest.mark.parametrize("uid, sudo_rc, expected", [("0", "1", "root"), ("1000", "0", "yes"), ("1000", "1", "no")])
def test_check_command_detects_passwordless_sudo(uid, sudo_rc, expected) -> None:
    fakes = (
        f"id() {{ echo {uid}; }}\n"
        f"sudo() {{ [ \"$1\" = -n ] && [ \"$2\" = true ] && return {sudo_rc}; return 1; }}\n"
        "docker() { return 1; }\nhostname() { echo node-a; }\nip() { return 1; }\n"
    )
    run = subprocess.run([shutil.which("bash"), "-c", fakes + sshops.CHECK_COMMAND],
                         capture_output=True, text=True, timeout=20)
    assert sshops._parse_check_output(run.stdout).sudo == expected
