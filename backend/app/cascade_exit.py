"""Per-pair exit resources. Legacy cascades keep their original layout."""

import ipaddress
import json
import shlex

from app import cascade_awg


def scoped(params: dict) -> bool:
    return params.get("runtime_layout") == 2


def paths(cid: int) -> dict[str, str]:
    result = cascade_awg.resources(cid)
    result["interface_gre"] = f"acgx{cid:x}"
    result["container_xray"] = f"acontrol-cascade-exit-{cid}-xray"
    return result


def network(cid: int, params: dict) -> tuple[str, str, str]:
    if not scoped(params):
        n = cid % 254 + 1
        net = ipaddress.IPv4Network(f"10.99.{n}.0/30")
    else:
        net = ipaddress.IPv4Network(params["inner_net"])
        if net.prefixlen != 30 or not net.subnet_of(ipaddress.IPv4Network("10.99.0.0/16")):
            raise ValueError("Invalid cascade subnet")
    return str(net), str(net[1]) + "/30", str(net[2]) + "/30"


def _owner(cid: int, transport: str, params: dict) -> dict:
    owner = params["runtime_owner"]
    if len(owner) != 32 or any(c not in "0123456789abcdef" for c in owner):
        raise ValueError("Invalid cascade owner")
    return {"cascade_id": cid, "transport": transport, "owner": owner, "layout": 2}


def entry_preflight(cid: int, transport: str, params: dict) -> str:
    expected = _owner(cid, transport, params)
    code = r'''
import ipaddress,json,pathlib,shutil,subprocess,sys
expected=json.loads(sys.argv[1]); base=pathlib.Path('/opt/acontrol/cascade'); marker=base/'owner.json'
if base.is_symlink() or marker.is_symlink():sys.exit(73)
owned=False
if base.exists():
 if not marker.is_file() or marker.stat().st_uid!=0 or marker.stat().st_size>1024:sys.exit(73)
 if json.loads(marker.read_text())!=expected:sys.exit(73)
 owned=True
for name in ('acontrol-cascade','acontrol-cascade-awg','acontrol-cascade-exit','xray-cascade'):
 if not shutil.which('docker'):continue
 r=subprocess.run(['docker','container','inspect',name],capture_output=True,timeout=10)
 if r.returncode==0:
  labels=json.loads(r.stdout)[0]['Config'].get('Labels') or {}
  if name in ('xray-cascade','acontrol-cascade-exit') or not owned or labels.get('org.amnezia.control.owner')!=expected['owner']:sys.exit(73)
 elif b'No such object:' not in r.stderr and b'No such container:' not in r.stderr:sys.exit(73)
for name in ('acgre','acawg'):
 r=subprocess.run(['ip','-j','-d','link','show','dev',name],capture_output=True)
 if r.returncode==0:
  if not owned:sys.exit(73)
  if name=='acgre':
   x=json.loads(r.stdout)[0];d=x.get('linkinfo',{});key=d.get('info_data',{}).get('ikey',0)
   key=int(key) if str(key).isdigit() else int(ipaddress.IPv4Address(key))
   if expected['transport']!='gre' or d.get('info_kind')!='gre' or key!=int(sys.argv[2]):sys.exit(73)
print('CASCADE_AVAILABLE')
'''
    return cascade_awg.foreign_guard() + "sudo -n python3 -c " + shlex.quote(code) + " " + shlex.quote(json.dumps(expected)) + " " + str(int(params.get("gre_key", 0))) + " || exit 73\n"


def network_preflight(cid: int, transport: str, params: dict, role: str) -> str:
    if transport == "vless":
        return ""
    iface = ("acawg" if transport == "awg" else "acgre") if role == "entry" else paths(cid)["interface" if transport == "awg" else "interface_gre"]
    code = r'''
import ipaddress,json,subprocess,sys
network=ipaddress.ip_network(sys.argv[1]); own=sys.argv[2]
def overlaps(destination):
 return network.overlaps(ipaddress.ip_network(destination,strict=False))
for row in json.loads(subprocess.check_output(['ip','-j','-4','address','show'],timeout=5)):
 if row['ifname']==own:continue
 for item in row.get('addr_info',[]):
  if overlaps(item['local']+'/'+str(item['prefixlen'])):sys.exit(73)
for row in json.loads(subprocess.check_output(['ip','-j','-4','route','show','table','all'],timeout=5)):
 if row.get('dev')==own or row.get('dst','default')=='default':continue
 if overlaps(row['dst']):sys.exit(73)
'''
    return "sudo -n python3 -c " + shlex.quote(code) + " " + shlex.quote(params["inner_net"]) + " " + iface + " || exit 73\n"


def preflight(cid: int, transport: str, params: dict) -> str:
    p = paths(cid)
    expected = _owner(cid, transport, params)
    code = r'''
import json,pathlib,shutil,subprocess,sys
base=pathlib.Path(sys.argv[1]); expected=json.loads(sys.argv[2]); marker=base/'owner.json'
if base.parent.is_symlink() or base.is_symlink() or marker.is_symlink():sys.exit(73)
owned=False
if base.exists():
 if not marker.is_file() or marker.stat().st_uid!=0 or marker.stat().st_size>1024:sys.exit(73)
 if json.loads(marker.read_text())!=expected:sys.exit(73)
 owned=True
allowed=sys.argv[3] if expected['transport']=='awg' else sys.argv[4] if expected['transport']=='vless' else ''
for name in sys.argv[3:5]:
 if not shutil.which('docker'):continue
 r=subprocess.run(['docker','container','inspect',name],capture_output=True,timeout=10)
 if r.returncode==0:
  labels=json.loads(r.stdout)[0]['Config'].get('Labels') or {}
  if name!=allowed or not owned or labels.get('org.amnezia.control.owner')!=expected['owner']:sys.exit(73)
 elif b'No such object:' not in r.stderr and b'No such container:' not in r.stderr:sys.exit(73)
for name in sys.argv[5:]:
 path=pathlib.Path('/etc/systemd/system',name)
 if path.is_symlink() or (path.exists() and not owned):sys.exit(73)
print('CASCADE_AVAILABLE')
'''
    args = [p["base"], json.dumps(expected), p["container"], p["container_xray"],
            p["unit"], p["timer"], p["heal"]]
    return "sudo -n python3 -c " + shlex.quote(code) + " " + " ".join(map(shlex.quote, args)) + " || exit 73\n"


RUNTIME = r'''#!/bin/bash
set -eu
BASE=@BASE@
. "$BASE/exit.env"
exec 9>@LOCK@
flock -x -w 10 9 || exit 73
DOCKER_BIN=$(command -v docker || true)
docker() { [ -n "$DOCKER_BIN" ] && timeout 15s "$DOCKER_BIN" "$@"; }
remove_container() {
  RESULT=$(docker rm -f "$CONT" 2>&1) && return 0
  case "$RESULT" in *'No such container:'*|*'No such object:'*) return 0;; *) exit 73;; esac
}
rule() { t=$1; c=$2; shift 2; iptables -w -t "$t" -C "$c" "$@" -m comment --comment "$OWNER" 2>/dev/null || iptables -w -t "$t" -I "$c" 1 "$@" -m comment --comment "$OWNER"; }
unrule() { t=$1; c=$2; shift 2; while iptables -w -t "$t" -C "$c" "$@" -m comment --comment "$OWNER" 2>/dev/null; do iptables -w -t "$t" -D "$c" "$@" -m comment --comment "$OWNER"; done; }
owner() {
  if [ "$TRANSPORT" = gre ]; then
    if ip link show "$IF" >/dev/null 2>&1; then
      ip -j -d link show "$IF" | python3 -c 'import ipaddress,json,sys;x=json.load(sys.stdin)[0];d=x.get("linkinfo",{});v=d.get("info_data",{});key=lambda n:int(n) if str(n).isdigit() else int(ipaddress.IPv4Address(n));assert d.get("info_kind")=="gre" and v.get("local")==sys.argv[2] and v.get("remote")==sys.argv[3] and key(v.get("ikey",0))==int(sys.argv[4]) and key(v.get("okey",0))==int(sys.argv[4]) and x.get("ifalias",sys.argv[1])==sys.argv[1]' "$OWNER" "$LOCAL" "$PEER" "$KEY" || exit 73
    fi
  else
    NAMES=$(docker container ls -a --format '{{.Names}}') || exit 73
    if printf '%s\n' "$NAMES" | grep -Fxq "$CONT"; then
      [ "$(docker container inspect -f '{{ index .Config.Labels "org.amnezia.control.owner" }}' "$CONT")" = "$OWNER" ] || exit 73
    fi
  fi
}
rules() {
  action=$1
  if [ "$TRANSPORT" = gre ]; then
    "$action" filter INPUT -p gre -s "$PEER" -j ACCEPT
    "$action" filter FORWARD -i "$IF" -s "$PEER_INNER/32" -o "$EGRESS" -j ACCEPT
    "$action" filter FORWARD -i "$EGRESS" -o "$IF" -d "$PEER_INNER/32" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    "$action" mangle FORWARD -i "$IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    "$action" mangle FORWARD -o "$IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    "$action" nat POSTROUTING -s "$PEER_INNER/32" -o "$EGRESS" -j MASQUERADE
  else
    "$action" filter INPUT -p tcp -s "$PEER" --dport "$PORT" -j ACCEPT
    "$action" filter INPUT -p tcp ! -s "$PEER" --dport "$PORT" -j DROP
  fi
}
up() {
  owner
  if [ "$TRANSPORT" = gre ]; then
    ip link show "$IF" >/dev/null 2>&1 || ip link add "$IF" type gre local "$LOCAL" remote "$PEER" key "$KEY" ttl 64
    ip link set dev "$IF" alias "$OWNER"
    ip addr replace "$INNER/32" dev "$IF"
    ip link set "$IF" mtu 1476 up
    ip route replace "$PEER_INNER/32" dev "$IF" src "$INNER"
    sysctl -qw "net.ipv4.conf.$IF.rp_filter=2" net.ipv4.ip_forward=1
  else
    if printf '%s\n' "$NAMES" | grep -Fxq "$CONT"; then
      if [ "$(docker container inspect -f '{{.State.Running}}' "$CONT")" != true ]; then docker start "$CONT" >/dev/null; fi
    else
      [ -z "$(ss -lntH "sport = :$PORT")" ] || exit 73
      docker run -d --name "$CONT" --label "org.amnezia.control.owner=$OWNER" --label "org.amnezia.control.cascade=$CID" --restart always --network host -e GODEBUG=multipathtcp=0 --user 0:0 --read-only --cap-drop ALL --cap-add NET_BIND_SERVICE --security-opt no-new-privileges:true --log-opt max-size=10m --log-opt max-file=3 -v "$BASE/xray:/usr/local/etc/xray:ro" @XRAY@ >/dev/null
    fi
  fi
  rules rule
}
down() {
  owner
  rules unrule
  if [ "$TRANSPORT" = gre ]; then
    if ip link show "$IF" >/dev/null 2>&1; then ip link del "$IF"; fi
  else remove_container; fi
}
case "${1:-}" in up|heal) up;; down) down;; *) exit 2;; esac
'''


def install(cid: int, transport: str, peer: str, params: dict) -> list[str]:
    from app import cascade
    p = paths(cid)
    owner = _owner(cid, transport, params)
    _net, entry, exit_ = network(cid, params)
    lines = [preflight(cid, transport, params).replace("exit 73", "fail 'exit ownership'"),
             network_preflight(cid, transport, params, "exit").replace("exit 73", "fail 'cascade subnet overlaps an existing route'"),
             f"sudo install -d -m 700 {p['base']}",
             cascade._put(p["base"] + "/owner.json", json.dumps(owner), "600")]
    if transport == "awg":
        lines += cascade_awg.install("exit", peer, cid, params, entry.split('/')[0],
                                     exit_.split('/')[0], scoped_exit=True)
        return lines
    values = {"CID": str(cid), "OWNER": owner["owner"], "TRANSPORT": transport,
              "IF": p["interface_gre"], "CONT": p["container_xray"],
              "PEER": str(ipaddress.IPv4Address(peer)), "INNER": exit_.split('/')[0],
              "PEER_INNER": entry.split('/')[0], "KEY": str(int(params.get("gre_key", 0))),
              "PORT": str(int(params.get("port", 0)))}
    runtime = RUNTIME.replace("@BASE@", p["base"]).replace("@LOCK@", p["lock"]).replace("@XRAY@", cascade.XRAY_IMAGE)
    script = p["base"] + "/exit.sh"
    lines += ["EGRESS=$(ip -4 route show default | awk '/^default/ {print $5; exit}')",
              '[ -n "$EGRESS" ] || fail "exit egress"',
              "LOCAL=$(ip -4 route get " + values["PEER"] + " | " + cascade._SRC_OF + " | head -1)",
              '[ -n "$LOCAL" ] || fail "exit source address"',
              cascade._put(script, runtime, "700"),
              cascade._put(p["base"] + "/exit.env.next", ''.join(f"{k}={shlex.quote(v)}\n" for k,v in values.items()), "600"),
              f"printf 'EGRESS=%q\\nLOCAL=%q\\n' \"$EGRESS\" \"$LOCAL\" | sudo tee -a {p['base']}/exit.env.next >/dev/null || fail 'exit environment'",
              f"sudo mv -f {p['base']}/exit.env.next {p['base']}/exit.env || fail 'exit environment'"]
    if transport == "vless":
        lines += ["NAMES=$(sudo docker container ls -a --format '{{.Names}}') || fail 'exit containers'",
                  f"if ! printf '%s\\n' \"$NAMES\" | grep -Fxq {p['container_xray']}; then",
                  f"  sudo install -d -m 700 {p['base']}/xray || fail 'exit config directory'",
                  "  " + cascade._put(p["base"] + "/xray/config.json", cascade.exit_vless_config(params), "600"),
                  f"  sudo docker pull -q {cascade.XRAY_IMAGE} >/dev/null || fail 'docker pull'",
                  "fi"]
    unit = ("[Unit]\nDescription=Cascade exit\nAfter=network-online.target docker.service\nWants=network-online.target\n"
            f"[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart={script} up\n[Install]\nWantedBy=multi-user.target\n")
    heal = f"[Unit]\nDescription=Repair cascade exit\n[Service]\nType=oneshot\nExecStart={script} heal\n"
    timer = f"[Timer]\nOnBootSec=20\nOnUnitActiveSec=20\nUnit={p['heal']}\n[Install]\nWantedBy=timers.target\n"
    for name, text in ((p["unit"],unit),(p["heal"],heal),(p["timer"],timer)):
        lines.append(cascade._put("/etc/systemd/system/" + name, text))
    lines += ["sudo systemctl daemon-reload",
              f"sudo systemctl enable {p['unit']} {p['timer']} >/dev/null 2>&1 || fail 'exit enable'",
              f"sudo systemctl restart {p['unit']} || fail 'exit start'",
              f"sudo systemctl start {p['timer']} || fail 'exit heal'"]
    return lines


def remove(cid: int, transport: str, params: dict) -> str:
    from app import cascade

    guard = preflight(cid, transport, params)
    if transport == "awg":
        return guard + cascade_awg.remove(cid, scoped_exit=True, owner=params["runtime_owner"]) + "echo CASCADE_REMOVED=yes\n"

    p = paths(cid)
    script = p["base"] + "/exit.sh"
    runtime = RUNTIME.replace("@BASE@", p["base"]).replace("@LOCK@", p["lock"]).replace("@XRAY@", cascade.XRAY_IMAGE)
    return guard + cascade.stop_units(p["timer"], p["heal"], p["unit"]) + f'''
if sudo test -L {p['base']}/exit.env || sudo test -L {script}; then exit 73; fi
if sudo test -f {p['base']}/exit.env; then
  sudo grep -qx 'OWNER={params["runtime_owner"]}' {p['base']}/exit.env || exit 73
  sudo grep -qx 'TRANSPORT={transport}' {p['base']}/exit.env || exit 73
  if sudo test -x {script}; then
    sudo {script} down || exit 73
  else
    sudo bash -s -- down <<'AC_CASCADE_EXIT_RUNTIME' || exit 73
{runtime}AC_CASCADE_EXIT_RUNTIME
  fi
fi
sudo rm -f /etc/systemd/system/{p['timer']} /etc/systemd/system/{p['heal']} /etc/systemd/system/{p['unit']} || exit 73
sudo rm -rf {p['base']} || exit 73
sudo systemctl daemon-reload || exit 73
echo CASCADE_REMOVED=yes
'''
