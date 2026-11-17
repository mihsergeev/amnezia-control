import os
import shlex
import shutil
import subprocess

from app import ssh_firewall


def execute(tmp_path, operation, *, extra=""):
    generated = ssh_firewall.script("a" * 32, ["192.0.2.1"], 2222, operation)
    body = shlex.split(generated.split('$SUDO sh -c ', 1)[1])[0]
    body = body.replace('/lib65', tmp_path.as_posix() + '/rootdata')
    fixture = '''
id() { echo 0; }
stat() { echo 0; }
nohup() { :; }
ufw() {
  if [ "$1" = show ]; then cat "$TEST/ufw"; return; fi
  if [ "$1" = --force ]; then shift 2; ACTION=delete; else ACTION=add; fi
  RULE="ufw allow from $3 to any port $7 proto tcp"
  [ "$#" -le 9 ] || RULE="$RULE comment '${11}'"
  if [ "$ACTION" = add ]; then printf '%s\\n' "$RULE" >> "$TEST/ufw";
  else grep -Fvx "$RULE" "$TEST/ufw" > "$TEST/ufw.tmp" || :; mv "$TEST/ufw.tmp" "$TEST/ufw"; fi
}
firewall-cmd() {
  MODE=runtime
  if [ "$1" = --permanent ]; then MODE=permanent; shift; fi
  FILE="$TEST/firewalld-$MODE"
  case "$1" in
    --state) return 0 ;;
    --list-rich-rules) cat "$FILE" ;;
    --query-rich-rule=*) grep -Fxq "${1#*=}" "$FILE" ;;
    --add-rich-rule=*) printf '%s\\n' "${1#*=}" >> "$FILE" ;;
    --remove-rich-rule=*) grep -Fvx "${1#*=}" "$FILE" > "$FILE.tmp" || :; mv "$FILE.tmp" "$FILE" ;;
    *) return 1 ;;
  esac
}
'''
    bash = "C:/Program Files/Git/usr/bin/bash.exe" if os.name == "nt" else shutil.which("bash")
    return subprocess.run([bash, '-s'], input=fixture + extra + body,
                          text=True, capture_output=True, cwd='C:/' if os.name == 'nt' else '/',
                          env={**os.environ, 'TEST': tmp_path.as_posix(), 'PATH': str(__import__('pathlib').Path(bash).parent) + os.pathsep + os.environ['PATH']})


def init(tmp_path):
    for file in ('ufw', 'firewalld-runtime', 'firewalld-permanent'):
        (tmp_path / file).write_text('')


def test_new_firewall_rules_are_removed_and_unrelated_rules_preserved(tmp_path):
    init(tmp_path)
    existing = "ufw allow from 198.51.100.1 to any port 443 proto tcp comment 'admin'\n"
    (tmp_path / 'ufw').write_text(existing)
    result = execute(tmp_path, 'stage')
    assert result.returncode == 0, result.stderr
    assert 'acontrol-ssh-' in (tmp_path / 'ufw').read_text()
    result = execute(tmp_path, 'rollback')
    assert result.returncode == 0, result.stderr
    assert (tmp_path / 'ufw').read_text() == existing
    assert not (tmp_path / 'firewalld-runtime').read_text()
    assert not (tmp_path / 'firewalld-permanent').read_text()


def test_preexisting_identical_rules_are_never_owned_or_deleted(tmp_path):
    init(tmp_path)
    existing = "ufw allow from 192.0.2.1 to any port 2222 proto tcp comment 'admin'\n"
    rich = 'rule family="ipv4" source address="192.0.2.1" port port="2222" protocol="tcp" accept\n'
    (tmp_path / 'ufw').write_text(existing)
    for mode in ('runtime', 'permanent'):
        (tmp_path / f'firewalld-{mode}').write_text(rich)
    assert execute(tmp_path, 'stage').returncode == 0
    assert execute(tmp_path, 'rollback').returncode == 0
    assert (tmp_path / 'ufw').read_text() == existing
    assert (tmp_path / 'firewalld-runtime').read_text() == rich


def test_concurrent_manual_change_blocks_ambiguous_firewalld_cleanup(tmp_path):
    init(tmp_path)
    assert execute(tmp_path, 'stage').returncode == 0
    file = tmp_path / 'firewalld-runtime'
    file.write_text(file.read_text() + 'rule family="ipv4" source address="198.51.100.1" accept\n')
    before = file.read_text()
    result = execute(tmp_path, 'rollback')
    assert result.returncode != 0
    assert file.read_text() == before
    assert 'требуется проверка собственного правила' in result.stderr


def test_explicit_recovery_can_undo_a_lost_commit_reply(tmp_path):
    init(tmp_path)
    assert execute(tmp_path, 'stage').returncode == 0
    assert execute(tmp_path, 'commit').returncode == 0
    result = execute(tmp_path, 'rollback')
    assert result.returncode == 0, result.stderr
    assert not (tmp_path / 'ufw').read_text()
    assert not (tmp_path / 'firewalld-runtime').read_text()
