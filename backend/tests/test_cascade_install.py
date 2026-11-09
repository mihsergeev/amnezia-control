import shlex
import shutil
import subprocess

import pytest

from app import cascade, cascade_awg, cascade_exit


OLD = "a" * 64
NEXT = "b" * 64

FAKE_ENTRY = r'''
docker() {
  echo "docker $*" >> "$STATE/calls"
  case "$1 $2" in
    'container ls')
      case "$*" in
        *'--filter label='*) if [ -f "$STATE/next.name" ]; then echo "$NEXT"; fi;;
        *'--filter id='*) if [ -f "$STATE/old.name" ]; then echo "$OLD"; fi;;
        *) for key in old next; do
             [ -f "$STATE/$key.name" ] || continue
             if [ "$key" = old ]; then id=$OLD; else id=$NEXT; fi
             echo "$(cat "$STATE/$key.name") $id"
           done;;
      esac
      ;;
    'container inspect')
      case "$4" in
        *'.Mounts'*) echo "$DIR/config";;
        *'.HostConfig.RestartPolicy'*) echo "true $(cat "$STATE/old.policy") 0";;
        *'.State.Running'*) if [ -f "$STATE/next.running" ]; then echo true; else echo false; fi;;
        *) return 99;;
      esac
      ;;
    'pull -q') [ "$FAULT" != pull ];;
    'run --rm') [ "$FAULT" != invalid-config ];;
    'create --name')
      [ "$FAULT" != create ] || return 1
      printf '%s\n' "$3" > "$STATE/next.name"
      echo "$NEXT"
      ;;
    'update --restart='*) printf '%s\n' "${2#--restart=}" > "$STATE/old.policy";;
    'stop -t') rm -f "$STATE/old.running";;
    "start $NEXT")
      [ "$FAULT" != start ] || return 1
      touch "$STATE/next.running"
      ;;
    "start $OLD") touch "$STATE/old.running";;
    "rename $OLD") printf '%s\n' "$3" > "$STATE/old.name";;
    "rename $NEXT")
      [ "$FAULT" != promote ] || return 1
      printf '%s\n' "$3" > "$STATE/next.name"
      ;;
    "rm $OLD") rm -f "$STATE/old.name";;
    'rm -f') rm -f "$STATE/next.name" "$STATE/next.running";;
    *) return 99;;
  esac
}
sudo() {
  case "$1" in
    docker) shift; docker "$@";;
    stat) echo 0:700;;
    mkdir) if [ "$2" = -m ]; then command mkdir "$4"; else command "$@"; fi;;
    install) cp "$4" "$5";;
    sh)
      if [[ "$5" == /etc/systemd/system/* ]]; then
        sh "$2" "$3" "$4" "$STATE/units/${5##*/}" "$6"
      else
        command "$@"
      fi
      ;;
    systemctl)
      echo "$*" >> "$STATE/calls"
      case "$2" in
        is-active) test -f "$STATE/$4";;
        enable)
          if [ "$4" = acontrol-cascade-heal.service ] && [ "$FAULT" = heal ]; then return 1; fi
          touch "$STATE/$4"
          ;;
        disable) rm -f "$STATE/$4";;
        daemon-reload|stop) return 0;;
        *) return 99;;
      esac
      ;;
    */cascade-tproxy.sh)
      echo "tproxy-$2" >> "$STATE/calls"
      [ "$2" != heal ] || [ "$FAULT" != tproxy-rules ]
      ;;
    ip|iptables) return 0;;
    *) command "$@";;
  esac
}
iptables() { :; }
sleep() { :; }
curl() {
  case "$*" in
    *--socks5*) [ "$FAULT" != egress ] && echo 198.51.100.20;;
    *) echo 192.0.2.10;;
  esac
}
'''


@pytest.mark.skipif(shutil.which("bash") is None, reason="Bash is required")
@pytest.mark.parametrize("fault", ["pull", "invalid-config", "create", "start", "egress", "promote", "tproxy-rules", "heal",
                                    "interrupted", "first-heal", "none"])
def test_gateway_reinstall_keeps_previous_container_config_and_rules(tmp_path, monkeypatch, fault):
    state = tmp_path / "state"
    state.mkdir()
    (state / "units").mkdir()
    base = tmp_path / "cascade"
    (base / "config").mkdir(parents=True)
    (base / "geo").mkdir()
    config = base / "config" / "config.json"
    first = fault == "first-heal"
    for name in ("geoip.dat", "geosite.dat"):
        (base / "geo" / name).write_bytes(b"geo fixture")
    if not first:
        config.write_bytes(b"original config")
        for name, value in (("old.name", cascade.GATEWAY), ("old.policy", "unless-stopped")):
            (state / name).write_text(value, encoding="utf-8")
        (state / "old.running").touch()
        (state / "acontrol-cascade-tproxy.service").touch()
    if fault not in ("heal", "first-heal"):
        (state / "acontrol-cascade-heal.service").touch()
    if fault == "interrupted":
        tx = base / "gateway-transaction"
        tx.mkdir()
        (tx / "state").write_bytes(f"{'c' * 32} {OLD} true unless-stopped\n".encode())
        (tx / "switch").touch()
        (tx / "config.previous").write_bytes(config.read_bytes())
        config.write_bytes(b"interrupted candidate config")
        (state / "old.name").write_text(f"{cascade.GATEWAY}-previous", encoding="utf-8")
        (state / "old.running").unlink()
        (state / "old.policy").write_text("no", encoding="utf-8")
        (state / "next.name").write_text(cascade.GATEWAY, encoding="utf-8")
        (state / "next.running").touch()

    monkeypatch.setattr(cascade, "DIR", base.as_posix())
    monkeypatch.setattr(cascade, "_reality_encryption_command", lambda: "true")
    params = cascade.new_vless_params() | {"port": 8443}
    script = cascade.build_entry_script("vless", "198.51.100.20", 7, params, "DE")
    injected = {"interrupted": "create", "first-heal": "heal"}.get(fault, fault)
    values = {"FAULT": injected, "STATE": state.as_posix(), "DIR": base.as_posix(), "OLD": OLD, "NEXT": NEXT}
    prefix = "\n".join(f"{key}={shlex.quote(value)}" for key, value in values.items())
    result = subprocess.run([shutil.which("bash"), "-s"], input=(prefix + "\n" + FAKE_ENTRY + script).encode(),
                            capture_output=True, timeout=15)

    calls = (state / "calls").read_text(encoding="utf-8")
    assert (state / "acontrol-cascade-tproxy.service").is_file() == (not first)
    assert ("tproxy-down" in calls) == first
    output = result.stdout.decode(errors="replace")
    assert not (base / "gateway-transaction").exists(), (output, result.stderr.decode(errors="replace"), calls)
    if fault == "none":
        assert result.returncode == 0 and "DEPLOY_DONE" in output
        assert (state / "next.name").read_text().strip() == cascade.GATEWAY
        assert not (state / "old.name").exists()
        assert config.read_bytes() != b"original config"
    elif first:
        assert result.returncode != 0 and "DEPLOY_DONE" not in output
        assert not (state / "next.name").exists()
        assert not config.exists()
    else:
        assert result.returncode != 0 and "DEPLOY_DONE" not in output
        assert (state / "old.name").read_text().strip() == cascade.GATEWAY
        assert (state / "old.running").is_file()
        assert (state / "old.policy").read_text().strip() == "unless-stopped"
        assert not (state / "next.name").exists()
        assert config.read_bytes() == b"original config"
        if fault in ("pull", "invalid-config", "create"):
            assert "docker stop" not in calls
        if fault == "interrupted":
            assert calls.index(f"docker start {OLD}") < calls.index("docker create")


@pytest.mark.parametrize("transport", ["awg", "gre"])
def test_exit_runtime_is_written_before_env_and_cleanup_accepts_an_older_partial_install(transport):
    params = {"runtime_layout": 2, "runtime_owner": "a" * 32, "inner_net": "10.99.3.0/30",
              "entry_ip": "192.0.2.10", "exit_ip": "198.51.100.20", "gre_key": 123456}
    if transport == "awg":
        params |= cascade_awg.new_params() | {"entry_port": 51830, "exit_port": 51831}
    paths = cascade_exit.paths(7)
    env = "node.env" if transport == "awg" else "exit.env"
    runtime = paths["script"] if transport == "awg" else f"{paths['base']}/exit.sh"
    script = cascade.build_exit_script(transport, params["entry_ip"], 7, params)
    assert script.index(f"{runtime} 700") < script.index(f"mv -f {paths['base']}/{env}.next")

    removal = cascade.build_remove_exit(transport, 7, params)
    assert f"if sudo test -x {runtime}; then" in removal
    assert "sudo bash -s -- down <<" in removal
    assert "CASCADE_REMOVED=yes" in removal


@pytest.mark.skipif(shutil.which("bash") is None, reason="Bash is required")
@pytest.mark.parametrize("transport", ["awg", "gre"])
def test_remove_executes_fallback_for_a_missing_exit_runtime(tmp_path, monkeypatch, transport):
    original = cascade_awg.resources
    paths = cascade_exit.paths(7)
    base = tmp_path / "exit"
    base.mkdir()
    paths |= {"base": base.as_posix(), "script": (base / "awg.sh").as_posix(),
              "lock": (tmp_path / "exit.lock").as_posix()}
    owner = "a" * 32
    if transport == "awg":
        env = ("CID=7\nROLE=exit\nPORT=51831\nPUBLIC=own-public\nPEER=192.0.2.10\n"
               "PEER_INNER=10.99.3.1\nEGRESS=eth0\n")
        (base / "node.env").write_text(env, encoding="utf-8", newline="\n")
    else:
        env = (f"OWNER={owner}\nTRANSPORT=gre\nIF=acgx7\nPEER=192.0.2.10\n"
               "PEER_INNER=10.99.3.1\nEGRESS=eth0\n")
        (base / "exit.env").write_text(env, encoding="utf-8", newline="\n")

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    commands = {
        "docker": 'case "$1 $2" in "container inspect") exit 1;; "rm -f") echo "No such container:" >&2; exit 1;; esac',
        "flock": "exit 0",
        "ip": "exit 1",
        "iptables": "exit 1",
        "ufw": "exit 0",
    }
    for name, command in commands.items():
        path = bin_dir / name
        path.write_text(f"#!/bin/sh\n{command}\n", encoding="utf-8", newline="\n")
        path.chmod(0o755)
    monkeypatch.setattr(cascade_exit, "preflight", lambda *_args: "")
    monkeypatch.setattr(cascade_exit, "paths", lambda _cid: paths)
    monkeypatch.setattr(cascade_awg, "resources", lambda cid=None: paths if cid == 7 else original(cid))
    prefix = f"AC_TEST_BIN={shlex.quote(bin_dir.as_posix())}\n" + r'''
if command -v cygpath >/dev/null; then AC_TEST_BIN=$(cygpath -u "$AC_TEST_BIN"); fi
export PATH="$AC_TEST_BIN:$PATH"
sudo() {
  case "$*" in
    'systemctl show '*) echo not-found;;
    'systemctl daemon-reload'|'rm -f /etc/systemd/system/'*) return 0;;
    *) command "$@";;
  esac
}
'''
    script = cascade_exit.remove(7, transport, {"runtime_owner": owner})
    result = subprocess.run([shutil.which("bash"), "-s"], input=(prefix + script).encode(),
                            capture_output=True, timeout=15)
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert b"CASCADE_REMOVED=yes" in result.stdout
    assert not base.exists()
