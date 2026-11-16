"""GRE helpers must budget the key header as well as the outer IP header."""

import shlex
import shutil
import subprocess

import pytest

from app import cascade, cascade_exit


@pytest.mark.parametrize("current_mtu,repair", [(1476, True), (1472, False)])
def test_entry_heal_repairs_an_existing_keyed_mtu_without_recreating_the_link(tmp_path, current_mtu, repair):
    env = tmp_path / "gre.env"
    env.write_text("IF=acgre\nLOCAL=192.0.2.10\nREMOTE=192.0.2.20\nINNER=198.51.100.1/30\n"
                   "ROLE=exit\nEGRESS=eth0\nNET=198.51.100.0/30\nKEY=123\n",
                   encoding="utf-8", newline="\n")
    functions = r'''
ip() {
  case "$*" in
    '-o link show acgre') echo '7: acgre: <UP> mtu @MTU@ qdisc noqueue';;
    'link show acgre') return 0;;
    'link set acgre mtu 1472 up') echo repaired;;
    'link add '*|'tunnel add '*) echo 'existing tunnel must be preserved' >&2; exit 99;;
  esac
}
iptables() { :; }; modprobe() { :; }; sysctl() { :; }; logger() { :; }
'''.replace("@MTU@", str(current_mtu))
    script = cascade._GRE_TUN_SH.replace(". @DEFAULTS@", ". " + shlex.quote(env.as_posix()))
    result = subprocess.run([shutil.which("bash"), "-s", "--", "heal"],
                            input=functions + script, text=True, capture_output=True, timeout=5)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == ("repaired" if repair else "")


@pytest.mark.parametrize("version,key,mtu", [(4, None, 1476), (4, 123, 1472),
                                           (6, None, 1456), (6, 123, 1452)])
def test_entry_runtime_configures_payload_mtu(tmp_path, version, key, mtu):
    peer = "2001:db8::20" if version == 6 else "192.0.2.20"
    env = tmp_path / "gre.env"
    env.write_text(f"IF=acgre\nLOCAL=192.0.2.10\nREMOTE={peer}\nINNER=198.51.100.1/30\n"
                   f"ROLE=exit\nEGRESS=eth0\nNET=198.51.100.0/30\n"
                   + (f"KEY={key}\n" if key is not None else ""), encoding="utf-8", newline="\n")
    # Execute the installed shell body. No kernel networking is changed.
    functions = r'''
ip() {
  case "$1 $2" in
    'link show') return 1;;
    'link set') printf '%s\n' "$*";;
  esac
}
iptables() { :; }; ip6tables() { :; }; modprobe() { :; }; sysctl() { :; }
'''
    script = cascade._GRE_TUN_SH.replace(". @DEFAULTS@", ". " + shlex.quote(env.as_posix()))
    result = subprocess.run([shutil.which("bash"), "-s", "--", "up"],
                            input=functions + script, text=True, capture_output=True, timeout=5)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == f"link set acgre mtu {mtu} up"


@pytest.mark.parametrize("version,mtu", [(4, 1472), (6, 1452)])
def test_scoped_exit_runtime_configures_keyed_payload_mtu(tmp_path, version, mtu):
    peer = "2001:db8::10" if version == 6 else "192.0.2.10"
    (tmp_path / "exit.env").write_text(
        f"TRANSPORT=gre\nIF=acgx7\nLOCAL=192.0.2.20\nPEER={peer}\nKEY=123\n"
        "OWNER=fixture\nINNER=198.51.100.2\nPEER_INNER=198.51.100.1\nEGRESS=eth0\n",
        encoding="utf-8", newline="\n")
    functions = r'''
ip() {
  case "$1 $2" in
    'link show') return 1;;
    'link set') [ "$3" = dev ] || printf '%s\n' "$*";;
  esac
}
iptables() { :; }; ip6tables() { :; }; flock() { :; }; sysctl() { :; }
'''
    script = cascade_exit.RUNTIME.replace("@BASE@", shlex.quote(tmp_path.as_posix())).replace(
        "@LOCK@", shlex.quote((tmp_path / "lock").as_posix()))
    result = subprocess.run([shutil.which("bash"), "-s", "--", "up"],
                            input=functions + script, text=True, capture_output=True, timeout=5)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == f"link set acgx7 mtu {mtu} up"
