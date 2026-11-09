import hashlib
import json
import shlex
import shutil
import subprocess

import pytest

from app import xray


FAKE_DOCKER = r'''
sudo() {
  case "$1" in
    docker|ufw|firewall-cmd) "$@" ;;
    *) command "$@" ;;
  esac
}
ufw() { echo firewall-change >> "$TEST_DIR/calls"; }
firewall-cmd() { echo firewall-change >> "$TEST_DIR/calls"; }
docker() {
  printf 'docker %s\n' "$*" >> "$TEST_DIR/calls"
  case "$1 $2" in
    'inspect -f')
      case "$3" in
        *'.State.Running'*) [ "$FAULT" != missing ] && echo true;;
        *'.HostConfig.NetworkMode'*) if [ "$FAULT" = network ]; then echo custom; else echo default; fi;;
        *'.HostConfig.PortBindings'*) echo '19443/tcp|192.0.2.2|18443';;
        *'.Mounts'*)
          echo "$D $D bind true"
          if [ "$FAULT" = mounts ]; then echo '/lab/tls /certs bind false'; fi;;
        *'.State.Status'*) echo 'running|0';;
        *'with index .NetworkSettings.Networks'*) echo '172.17.0.2';;
        *'.NetworkSettings.Networks'*) echo bridge;;
        *) return 99;;
      esac;;
    'ps --filter') :;;
    'build --build-arg') [ "$FAULT" != build ];;
    'run --rm')
      case "$*" in
        *'--entrypoint jq'*) echo 19443;;
        *'--entrypoint xray'*) [[ "$*" == *'.json' ]] && [ "$FAULT" != config-test ];;
        *) return 99;;
      esac;;
    'rename amnezia-xray') printf '%s\n' "$3" > "$TEST_DIR/old-name";;
    'rename amnezia-xray-previous-'*) printf '%s\n' "$3" > "$TEST_DIR/old-name";;
    'stop amnezia-xray-previous-'*) rm "$TEST_DIR/old-running";;
    'run -d')
      [[ "$*" == *'192.0.2.2:18443:19443/tcp'* ]] || return 99
      [[ "$*" == *'--tmpfs /run/acontrol:rw,noexec,nosuid,nodev,mode=0700,size=1m'* ]] || return 99
      cmp -s "$D/server.json" "$TEST_DIR/candidate" || return 99
      while [ "$1" != --cidfile ]; do shift; done
      echo next > "$2"
      touch "$TEST_DIR/next"
      [ "$FAULT" != run ];;
    'exec amnezia-xray')
      case "$*" in
        *'nc -z 172.17.0.2 19443'*) [ "$FAULT" != listen ];;
        *' jq -e '*) :;;
        *'xray api statsquery -s unix:/run/acontrol/xray-api.sock'*) [ "$FAULT" != management ];;
        *) return 99;;
      esac;;
    'start amnezia-xray')
      cmp -s "$D/server.json" "$TEST_DIR/original" && touch "$TEST_DIR/old-running";;
    'rm -f') [ "$3" = next ] && rm "$TEST_DIR/next";;
    'rm amnezia-xray-previous-'*) rm "$TEST_DIR/old-name";;
    'logs amnezia-xray') :;;
    *) return 99;;
  esac
}
sleep() { if [ "$FAULT" = interrupted ]; then kill -TERM "$$"; fi; }
timeout() { echo host-probe >> "$TEST_DIR/calls"; }
'''


def _bash_path(path):
    value = path.as_posix()
    return f"/{value[0].lower()}{value[2:]}" if path.drive else value


@pytest.mark.skipif(shutil.which("bash") is None, reason="Bash is required")
@pytest.mark.parametrize("fault", [
    "missing", "network", "mounts", "build", "config-test", "stale", "run", "listen", "management", "interrupted", "none",
])
def test_xray_upgrade_keeps_original_config_until_replacement_is_ready(tmp_path, fault):
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    original = b'{"inbounds":[{"protocol":"vless","port":19443}]}\n'
    candidate = b'{"inbounds":[{"protocol":"vless","port":19443}],"stats":{}}\n'
    server = config_dir / "server.json"
    server.write_bytes(original)
    (tmp_path / "original").write_bytes(original)
    (tmp_path / "candidate").write_bytes(candidate)
    (tmp_path / "old-name").write_bytes(b"amnezia-xray\n")
    (tmp_path / "old-running").touch()
    state = tmp_path / ".acontrol" / "xray"
    state.mkdir(parents=True)
    staged = state / "stats.ABC12345"
    staged.write_bytes(candidate)
    digest = hashlib.sha256(original if fault != "stale" else b"stale").hexdigest()
    script = xray.build_deploy_script(
        18443, "www.example.com", preserve_port=True, staged_stats=(staged.name, digest),
    ).replace("BUILD=/opt/amnezia-build/xray", f"BUILD={shlex.quote(_bash_path(tmp_path / 'build'))}").replace(
        "D=/opt/amnezia/xray", f"D={shlex.quote(_bash_path(config_dir))}",
    )
    prefix = "\n".join(f"{key}={shlex.quote(value)}" for key, value in {
        "TEST_DIR": _bash_path(tmp_path), "HOME": _bash_path(tmp_path), "FAULT": fault,
    }.items())
    result = subprocess.run([shutil.which("bash"), "-s"], input=(prefix + "\n" + FAKE_DOCKER + script).encode(),
                            capture_output=True, timeout=25)
    output = result.stdout.decode(errors="replace")
    calls = (tmp_path / "calls").read_text()
    assert "firewall-change" not in calls
    if fault in {"missing", "network", "mounts"}:
        assert "docker build" not in calls
        assert "docker rename" not in calls
    assert not staged.exists(), (output, result.stderr)
    assert not list(config_dir.glob(".server-*"))
    if fault == "none":
        assert result.returncode == 0 and "DEPLOY_DONE" in output, (output, result.stderr)
        assert server.read_bytes() == candidate
        assert not (tmp_path / "old-name").exists()
        assert not (tmp_path / "old-running").exists()
        assert (tmp_path / "next").is_file()
    else:
        assert result.returncode != 0 and "DEPLOY_ERROR" in output, (output, result.stderr)
        assert "DEPLOY_DONE" not in output
        assert server.read_bytes() == original
        assert (tmp_path / "old-name").read_bytes() == b"amnezia-xray\n"
        assert (tmp_path / "old-running").is_file()
        assert not (tmp_path / "next").exists()
        if fault == "listen":
            assert "host-probe" not in calls


async def test_stats_stage_uploads_without_writing_to_container():
    class Conn:
        async def run(self, cmd, *, input=None, check):
            if input is None:
                assert "cat /opt/amnezia/xray/server.json" in cmd
                return type("Result", (), {"exit_status": 0, "stdout": raw})
            assert "docker" not in cmd
            assert "mktemp" in cmd and "umask 077" in cmd
            staged = json.loads(input)
            assert staged["api"]["services"] == ["StatsService", "HandlerService"]
            assert staged["api"]["listen"] == xray.MANAGEMENT_API_LISTEN
            assert staged["inbounds"][0]["tag"] == "acontrol-vless"
            return type("Result", (), {"exit_status": 0, "stdout": "stats.ABC12345\n"})

    raw = '{"inbounds":[{"protocol":"vless","port":19443}]}\n'
    assert await xray.stage_update_stats(Conn(), xray.CONTAINER_NAME) == (
        "stats.ABC12345", hashlib.sha256(raw.encode()).hexdigest(),
    )
