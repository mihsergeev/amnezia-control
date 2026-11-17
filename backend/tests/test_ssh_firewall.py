import os
import shlex
import shutil
import subprocess
import time

import pytest

from app import ssh_firewall


def execute(tmp_path, operation, *, extra="", addresses=None):
    generated = ssh_firewall.script("a" * 32, ["192.0.2.1"] if addresses is None else addresses, 2222, operation)
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
    if os.name == 'nt':
        fixture += '\nflock() { :; }\n'
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


@pytest.mark.parametrize(('failed_mode', 'legacy_journal'), [('runtime', False), ('permanent', True)])
def test_firewalld_rollback_resumes_after_partial_removal(tmp_path, failed_mode, legacy_journal):
    init(tmp_path)
    foreign = b'rule family="ipv4" source address="192.0.2.7" port port="2222" protocol="tcp" accept\n'
    rulefiles = {mode: tmp_path / f'firewalld-{mode}' for mode in ('runtime', 'permanent')}
    for rules in rulefiles.values():
        rules.write_bytes(foreign)
    addresses = ['192.0.2.1', '2001:db8::/64', '192.0.2.7', '203.0.113.1']
    staged = execute(tmp_path, 'stage', addresses=addresses)
    assert staged.returncode == 0, staged.stderr
    state = tmp_path / 'rootdata/acontrol-ssh-firewall' / ('a' * 32)
    for mode in rulefiles:
        assert foreign not in (state / f'firewalld-{mode}-intents').read_bytes()
        if legacy_journal:
            (state / f'firewalld-{mode}-before').unlink()
    extra = f'FAIL_MODE={failed_mode}\n' + '''eval "$(declare -f firewall-cmd | sed '1s/firewall-cmd/original_firewalld/')"
firewall-cmd() {
  if [ "$1" = --permanent ]; then mode=permanent; arg="$2"; else mode=runtime; arg="$1"; fi
  case "$mode:$arg" in "$FAIL_MODE":--remove-rich-rule=*2001:db8::/64*) return 2 ;; esac
  original_firewalld "$@"
}
'''
    partial = execute(tmp_path, 'rollback', extra=extra)
    assert partial.returncode != 0
    remaining = b'rule family="ipv6" source address="2001:db8::/64" port port="2222" protocol="tcp" accept\n'
    for mode, rules in rulefiles.items():
        assert rules.read_bytes() == foreign + (remaining if mode == failed_mode else b'')
    assert not (state / 'rolledback').exists()
    assert 'ACONTROL_FIREWALL_STATE_STAGED' in execute(tmp_path, 'status').stdout

    affected = rulefiles[failed_mode]
    added = b'rule family="ipv4" source address="198.51.100.1" accept\n'
    for changed in (foreign + remaining + added, remaining):
        affected.write_bytes(changed)
        refused = execute(tmp_path, 'rollback')
        assert refused.returncode != 0
        assert affected.read_bytes() == changed
        assert not (state / 'rolledback').exists()
    affected.write_bytes(foreign + remaining)

    retry = execute(tmp_path, 'rollback')
    assert retry.returncode == 0, retry.stderr
    assert 'ACONTROL_FIREWALL_ROLLEDBACK' in retry.stdout
    assert all(rules.read_bytes() == foreign for rules in rulefiles.values())
    assert (state / 'rolledback').exists()
    assert 'ACONTROL_FIREWALL_STATE_ROLLEDBACK' in execute(tmp_path, 'status').stdout
    assert execute(tmp_path, 'rollback').returncode == 0
    assert execute(tmp_path, 'commit').returncode != 0


def test_committed_firewall_rejects_rollback_and_commit_is_idempotent(tmp_path):
    init(tmp_path)
    assert execute(tmp_path, 'stage').returncode == 0
    assert execute(tmp_path, 'commit').returncode == 0
    original = (tmp_path / 'ufw').read_text()
    result = execute(tmp_path, 'rollback')
    assert result.returncode != 0
    assert (tmp_path / 'ufw').read_text() == original
    assert execute(tmp_path, 'commit').returncode == 0
    assert 'ACONTROL_FIREWALL_STATE_COMMITTED' in execute(tmp_path, 'status').stdout


@pytest.mark.parametrize('outcome', ['not-applied', 'applied-with-lost-reply'])
def test_firewalld_stage_failure_has_journal_for_both_remote_outcomes(tmp_path, outcome):
    init(tmp_path)
    extra = '''eval "$(declare -f firewall-cmd | sed '1s/firewall-cmd/original_firewalld/')"
firewall-cmd() {
  if [ "$1" = --permanent ]; then
    case "$2" in
      --add-rich-rule=*)
'''
    if outcome == 'applied-with-lost-reply':
        extra += '        original_firewalld "$@"\n'
    extra += '''        return 2 ;;
    esac
  fi
  original_firewalld "$@"
}
'''
    assert execute(tmp_path, 'stage', extra=extra).returncode != 0
    assert (tmp_path / 'firewalld-runtime').read_text()
    result = execute(tmp_path, 'rollback')
    assert result.returncode == 0, result.stderr
    assert not (tmp_path / 'firewalld-runtime').read_text()
    assert not (tmp_path / 'firewalld-permanent').read_text()
    assert (tmp_path / 'rootdata/acontrol-ssh-firewall' / ('a' * 32) / 'rolledback').exists()


@pytest.mark.skipif(os.name == 'nt', reason='Kernel flock process-death proof requires Linux; also exercised on a test VM')
def test_firewall_lock_is_released_after_sigkill(tmp_path):
    init(tmp_path)
    assert execute(tmp_path, 'stage').returncode == 0
    lock = tmp_path / 'rootdata/acontrol-ssh-firewall' / ('a' * 32) / 'lock'
    process = subprocess.Popen(['bash', '-c', 'exec 9>"$1"; flock 9; echo READY; exec sleep 60', 'bash', str(lock)], stdout=subprocess.PIPE, text=True)
    try:
        assert process.stdout.readline().strip() == 'READY'
        process.kill(); process.wait(timeout=5)
        assert execute(tmp_path, 'rollback').returncode == 0
    finally:
        if process.poll() is None: process.kill(); process.wait(timeout=5)


@pytest.mark.skipif(os.name == 'nt', reason='Detached watchdog and SIGKILL require Linux; real UFW proof also runs on an isolated test VM')
def test_watchdog_recovers_sigkill_during_first_rule_mutation(tmp_path):
    """The shell can die inside ufw, before stage returns or starts firewalld."""
    commands = tmp_path / 'bin'; commands.mkdir()
    rulefile = tmp_path / 'rules'; rulefile.write_text('')
    (commands / 'stat').write_text('#!/bin/sh\necho 0\n')
    (commands / 'firewall-cmd').write_text('#!/bin/sh\nexit 1\n')
    (commands / 'ufw').write_text('''#!/bin/sh
if [ "$1" = show ]; then cat "$TEST_RULES"; exit 0; fi
if [ "$1" = --force ]; then : > "$TEST_RULES"; exit 0; fi
printf "ufw allow from 192.0.2.1 to any port 2222 proto tcp comment 'acontrol-ssh-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'\\n" > "$TEST_RULES"
touch "$TEST_MUTATED"
kill -KILL "$PPID"
''')
    for path in commands.iterdir(): path.chmod(0o700)
    generated = ssh_firewall.script('a' * 32, ['192.0.2.1'], 2222)
    body = shlex.split(generated.split('$SUDO sh -c ', 1)[1])[0]
    body = body.replace('/lib65', (tmp_path / 'rootdata').as_posix()).replace('"$i" -lt 180', '"$i" -lt 1')
    mutation = tmp_path / 'mutation-observed'
    env = {**os.environ, 'PATH': str(commands) + os.pathsep + os.environ['PATH'],
           'TEST_RULES': str(rulefile), 'TEST_MUTATED': str(mutation)}
    completed = subprocess.run(['sh', '-c', body], text=True, capture_output=True, env=env, timeout=5)
    assert completed.returncode < 0
    assert mutation.exists()  # The allow was applied before process death.
    deadline = time.monotonic() + 8
    state = tmp_path / 'rootdata/acontrol-ssh-firewall' / ('a' * 32)
    while time.monotonic() < deadline and not (state / 'rolledback').exists():
        time.sleep(.05)
    assert (state / 'rolledback').exists(), 'mid-stage process death must still have an armed watchdog'
    assert not rulefile.read_text()
