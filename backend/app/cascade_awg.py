"""Isolated AWG 3.1 underlay for panel-managed cascades.

Only marked gateway sockets use this link. Existing VPN containers, host default
routes and externally managed GRE-over-AWG links are never adopted or changed.
"""

import base64
import ipaddress
import secrets
import shlex

from app import awg, deploy

BASE = "/opt/acontrol/cascade-awg"
SCRIPT = "/lib65/scripts/acontrol-cascade-awg.sh"
CONTAINER = "acontrol-cascade-awg"
IMAGE = "acontrol-cascade-awg3"
INTERFACE = "acawg"
LABEL = "org.amnezia.control.cascade"
UNIT = "acontrol-cascade-awg.service"
TIMER = "acontrol-cascade-awg-heal.timer"
PORTS = (51830, 51831, 51832, 51833, 51834)


def new_params() -> dict:
    entry_private, entry_public = awg.generate_keypair()
    exit_private, exit_public = awg.generate_keypair()
    profile = deploy.generate_awg3_params()
    profile.update(Jc=5, Jmin=50, Jmax=100, S1=16, S2=16, S3=16, S4=16,
                   H1=1, H2=2, H3=3, H4=4, I1=deploy._DEFAULT_SPECIAL_JUNK_1)
    return {
        "entry_private": entry_private, "entry_public": entry_public,
        "exit_private": exit_private, "exit_public": exit_public,
        "psk": base64.b64encode(secrets.token_bytes(32)).decode(),
        "profile": profile,
    }


def config(role: str, params: dict) -> str:
    peer = "exit" if role == "entry" else "entry"
    # Explicit IPv4 endpoints avoid DNS changes and route recursion.
    endpoint = str(ipaddress.IPv4Address(params[f"{peer}_ip"]))
    own_port, peer_port = int(params[f"{role}_port"]), int(params[f"{peer}_port"])
    if not 1 <= own_port <= 65535 or not 1 <= peer_port <= 65535:
        raise ValueError("Invalid AWG port")
    profile = params["profile"]
    lines = ["[Interface]", f"PrivateKey = {params[f'{role}_private']}",
             f"ListenPort = {own_port}", "FwMark = 1024"]
    lines += [f"{key} = {profile[key]}" for key in deploy._AWG3_ACTIVE_ORDER]
    lines += [f"I1 = {profile['I1']}", "", "[Peer]",
              f"PublicKey = {params[f'{peer}_public']}",
              f"PresharedKey = {params['psk']}",
              "AllowedIPs = " + ("0.0.0.0/0" if role == "entry" else params["entry_inner"] + "/32"),
              f"Endpoint = {endpoint}:{peer_port}", "PersistentKeepalive = 25", ""]
    return "\n".join(lines)


def _put(path: str, text: str, mode: str = "600") -> str:
    data = base64.b64encode(text.encode()).decode()
    return (f"echo {data} | base64 -d | sudo sh -c "
            "'umask 077; cat > \"$1.tmp\" && chmod \"$2\" \"$1.tmp\" "
            "&& mv -f \"$1.tmp\" \"$1\"' sh "
            f"{path} {mode} || fail 'write AWG file'")


# No keys are printed, even on tool failure. Configuration is mounted as a
# directory, so atomic updates are visible after an own-container restart.
RUNTIME = r'''#!/bin/bash
set -eu
BASE=@BASE@
CONT=@CONT@
IF=@IF@
SCOPED_EXIT=@SCOPED_EXIT@
EXPECTED_OWNER=@OWNER@
LABEL=@LABEL@
die() { echo 'AWG operation refused or failed' >&2; exit 1; }
DOCKER_BIN=$(command -v docker)
docker() { timeout 15s "$DOCKER_BIN" "$@"; }
exec 9>@LOCK@
flock -x -w 5 9 || die
[ -f "$BASE/node.env" ] || die
. "$BASE/node.env"
[ "$SCOPED_EXIT" != yes ] || [ "$ROLE" = exit ] || die
owner() {
  if [ "$SCOPED_EXIT" != yes ]; then
    [ ! -e /lib65/scripts/acontrol-awg-link/node.json ] || return 1
    [ ! -e /etc/systemd/system/acontrol-awg-link.service ] || return 1
  fi
  NAMES=$(docker container ls -a --format '{{.Names}}') || return 1
  OWNED=no
  if printf '%s\n' "$NAMES" | grep -Fxq "$CONT"; then
    [ "$(docker container inspect -f '{{ index .Config.Labels "@LABEL@" }}' "$CONT")" = "$CID" ] || return 1
    [ -z "$EXPECTED_OWNER" ] || [ "$(docker container inspect -f '{{ index .Config.Labels "org.amnezia.control.owner" }}' "$CONT")" = "$EXPECTED_OWNER" ] || return 1
    OWNED=yes
  fi
  if ip link show "$IF" >/dev/null 2>&1; then
    [ "$OWNED" = yes ] || return 1
    [ "$(docker container inspect -f '{{.State.Running}}' "$CONT")" = true ] || return 1
    if [ "$(docker container inspect -f '{{.State.Running}}' "$CONT")" = true ]; then
      PUB=$(docker exec "$CONT" awg show "$IF" public-key 2>/dev/null || true)
      if [ "$PUB" != "$PUBLIC" ]; then
        # A restarted own userspace device is initially unconfigured.
        [ -z "$PUB" ] || [ "$PUB" = '(none)' ] || return 1
        [ -z "$(docker exec "$CONT" awg show "$IF" peers 2>/dev/null)" ] || return 1
      fi
    fi
  fi
}
rule() { table=$1; chain=$2; shift 2; iptables -w -t "$table" -C "$chain" "$@" 2>/dev/null || iptables -w -t "$table" -I "$chain" 1 "$@"; }
unrule() { table=$1; chain=$2; shift 2; while iptables -w -t "$table" -C "$chain" "$@" 2>/dev/null; do iptables -w -t "$table" -D "$chain" "$@"; done; }
remove_container() {
  RESULT=$(docker rm -f "$CONT" 2>&1) && return 0
  case "$RESULT" in *'No such container:'*|*'No such object:'*) return 0;; *) die;; esac
}
guard() {
  if [ "$ROLE" = entry ]; then
    # Install the kill switch before touching routes or the device.
    rule filter OUTPUT -m mark --mark 0x200 ! -o "$IF" -j DROP
    ip rule show | grep -q '1011:.*fwmark 0x200 unreachable' || ip rule add pref 1011 fwmark 0x200 unreachable
    # Independent of iptables/routing repairs. Update this table atomically.
    nft list table inet ac_cascade_awg >/dev/null 2>&1 || nft add table inet ac_cascade_awg
    nft -f - <<'NFT'
flush table inet ac_cascade_awg
add chain inet ac_cascade_awg output { type filter hook output priority -5; policy accept; }
add rule inet ac_cascade_awg output meta mark 0x200 oifname != "acawg" counter drop
NFT
  fi
}
up() {
  owner || die
  guard
  if [ "$OWNED" != yes ]; then
    # A host listener cannot be a Docker port publisher with host networking.
    [ -z "$(ss -lnuH "sport = :$PORT")" ] || die
    docker run -d --name "$CONT" --label "$LABEL=$CID" @OWNER_LABEL@ --restart always --network host \
      --cap-drop ALL --cap-add NET_ADMIN --device /dev/net/tun \
      --read-only --tmpfs /run --tmpfs /tmp --security-opt no-new-privileges:true \
      --log-opt max-size=10m --log-opt max-file=2 -e GODEBUG=multipathtcp=0 \
      -v "$BASE:/etc/acontrol-awg:ro" --entrypoint /usr/bin/amneziawg-go \
      @IMAGE@ -f "$IF" >/dev/null 2>&1 || die
  else
    if [ "$(docker container inspect -f '{{.State.Running}}' "$CONT")" != true ]; then
      docker start "$CONT" >/dev/null 2>&1 || die
    fi
  fi
  for n in $(seq 1 20); do
    docker exec "$CONT" awg show "$IF" >/dev/null 2>&1 && break
    sleep 1
  done
  # setconf also repairs a restarted userspace device with zero peers.
  docker exec "$CONT" awg setconf "$IF" /etc/acontrol-awg/link.conf >/dev/null 2>&1 || die
  ip address replace "$INNER/30" dev "$IF"
  ip link set "$IF" mtu 1280 up
  sysctl -qw "net.ipv4.conf.$IF.rp_filter=2"
  ip route replace "$PEER_INNER/32" dev "$IF" src "$INNER"
  rule filter INPUT -p udp -s "$PEER" --dport "$PORT" -j ACCEPT
  rule filter INPUT -i "$IF" -s "$PEER_INNER/32" -p icmp -j ACCEPT
  if [ "$ROLE" = entry ]; then
    ip route replace default dev "$IF" src "$INNER" table 242
    ip rule show | grep -q '1010:.*fwmark 0x200 lookup 242' || ip rule add pref 1010 fwmark 0x200 table 242
    # Outer UDP has its own mark and always follows the host main table.
    ip rule show | grep -q '1009:.*fwmark 0x400 lookup main' || ip rule add pref 1009 fwmark 0x400 table main
  else
    sysctl -qw net.ipv4.ip_forward=1
    rule filter FORWARD -i "$IF" -s "$PEER_INNER/32" -o "$EGRESS" -j ACCEPT
    rule filter FORWARD -i "$EGRESS" -o "$IF" -d "$PEER_INNER/32" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    rule mangle FORWARD -i "$IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    rule mangle FORWARD -o "$IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    rule nat POSTROUTING -s "$PEER_INNER/32" -o "$EGRESS" -j MASQUERADE
  fi
}
status() {
  echo CASCADE_ENCRYPTION=awg
  if ! owner || ! docker exec "$CONT" awg show "$IF" peers 2>/dev/null | grep -Fxq "$PEER_PUBLIC"; then
    echo CASCADE_ENCRYPTED=no; echo CASCADE_AWG=no; return
  fi
  ALLOWED=$(docker exec "$CONT" awg show "$IF" allowed-ips 2>/dev/null | awk -v p="$PEER_PUBLIC" '$1 == p {print $2}')
  WANT="$PEER_INNER/32"; [ "$ROLE" != entry ] || WANT=0.0.0.0/0
  if [ "$ALLOWED" != "$WANT" ] || [ "$(docker exec "$CONT" awg show "$IF" fwmark 2>/dev/null)" != 0x400 ] \
     || [ "$(docker exec "$CONT" awg show "$IF" listen-port 2>/dev/null)" != "$PORT" ]; then
    echo CASCADE_ENCRYPTED=unknown; echo CASCADE_AWG=no; return
  fi
  echo CASCADE_ENCRYPTED=yes
  HS=$(docker exec "$CONT" awg show "$IF" latest-handshakes 2>/dev/null | awk -v p="$PEER_PUBLIC" '$1 == p {print $2}')
  NOW=$(date +%s); AGE=-1
  [ "${HS:-0}" -le 0 ] || AGE=$((NOW-HS))
  echo "CASCADE_HANDSHAKE=$AGE"
  GOOD=no
  if [ "$AGE" -ge 0 ] && [ "$AGE" -le 180 ]; then
    if [ "$ROLE" = exit ] || {
      iptables -w -C OUTPUT -m mark --mark 0x200 ! -o "$IF" -j DROP 2>/dev/null &&
      ip rule show | grep -q '1011:.*fwmark 0x200 unreachable' &&
      ip rule show | grep -q '1010:.*fwmark 0x200 lookup 242' &&
      nft list chain inet ac_cascade_awg output | grep -Eq 'mark (0x0*200|512).*oifname != "acawg".*drop' &&
      ip route show table 242 | grep -q '^default dev acawg';
    }; then GOOD=yes; fi
  fi
  echo "CASCADE_AWG=$GOOD"
}
down() {
  owner || die
  # Caller stops interception first. Never remove another owner's interface.
  remove_container
  ip link delete "$IF" 2>/dev/null || true
  ip route del "$PEER_INNER/32" dev "$IF" 2>/dev/null || true
  unrule filter INPUT -p udp -s "$PEER" --dport "$PORT" -j ACCEPT
  unrule filter INPUT -i "$IF" -s "$PEER_INNER/32" -p icmp -j ACCEPT
  if [ "$ROLE" = entry ]; then
    ip rule del pref 1009 fwmark 0x400 table main 2>/dev/null || true
    ip rule del pref 1010 fwmark 0x200 table 242 2>/dev/null || true
    ip rule del pref 1011 fwmark 0x200 unreachable 2>/dev/null || true
    ip route flush table 242
    unrule filter OUTPUT -m mark --mark 0x200 ! -o "$IF" -j DROP
    nft delete table inet ac_cascade_awg 2>/dev/null || true
  else
    unrule filter FORWARD -i "$IF" -s "$PEER_INNER/32" -o "$EGRESS" -j ACCEPT
    unrule filter FORWARD -i "$EGRESS" -o "$IF" -d "$PEER_INNER/32" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    unrule mangle FORWARD -i "$IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    unrule mangle FORWARD -o "$IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    unrule nat POSTROUTING -s "$PEER_INNER/32" -o "$EGRESS" -j MASQUERADE
  fi
  if command -v ufw >/dev/null; then ufw --force delete allow from "$PEER" to any port "$PORT" proto udp >/dev/null 2>&1 || true; fi
}
case "${1:-}" in
  guard) owner || die; guard ;;
  up|heal) up ;;
  status) status ;;
  down) down ;;
  *) die ;;
esac
'''


def resources(cascade_id: int | None = None) -> dict[str, str]:
    if cascade_id is None:
        return dict(base=BASE, script=SCRIPT, container=CONTAINER, interface=INTERFACE,
                    unit=UNIT, timer=TIMER, heal="acontrol-cascade-awg-heal.service",
                    lock="/run/acontrol-cascade-awg.lock")
    if not 0 < cascade_id <= 2147483647:
        raise ValueError("Invalid cascade id")
    stem = f"acontrol-cascade-exit-{cascade_id}"
    base = f"/lib65/scripts/acontrol-cascade-exits/{cascade_id}"
    return dict(base=base, script=base + "/awg.sh", container=stem + "-awg",
                interface=f"acax{cascade_id:x}", unit=stem + ".service",
                timer=stem + "-heal.timer", heal=stem + "-heal.service",
                lock=f"/run/{stem}.lock")


def runtime_script(cascade_id: int | None = None, owner: str = "") -> str:
    if owner and (len(owner) != 32 or any(c not in "0123456789abcdef" for c in owner)):
        raise ValueError("Invalid cascade owner")
    paths = resources(cascade_id)
    text = RUNTIME
    for key, value in {"BASE": paths["base"], "CONT": paths["container"], "LABEL": LABEL,
                       "IMAGE": IMAGE, "IF": paths["interface"], "LOCK": paths["lock"],
                       "SCOPED_EXIT": "yes" if cascade_id is not None else "no",
                       "OWNER": shlex.quote(owner), "OWNER_LABEL":
                       f"--label org.amnezia.control.owner={owner}" if owner else ""}.items():
        text = text.replace(f"@{key}@", value)
    return text


def foreign_guard() -> str:
    """Must run before generic GRE install/delete can touch an external link."""
    return (
        "if sudo test -e /etc/systemd/system/acontrol-awg-link.service "
        "|| sudo test -e /lib65/scripts/acontrol-awg-link/node.json "
        "|| sudo docker container inspect acontrol-awg-link >/dev/null 2>&1 "
        "|| ip -d tunnel show acgre 2>/dev/null | grep -q 'dev acawg'; then "
        "echo 'CASCADE_EXTERNAL_UNDERLAY'; exit 73; fi\n"
    )


def preflight_command(cascade_id: int | None = None, *, scoped_exit: bool = False) -> str:
    if scoped_exit:
        paths = resources(cascade_id)
        base, cont, iface = paths["base"], paths["container"], paths["interface"]
        return f'''if sudo test -L {base} || sudo test -L {base}/node.env; then exit 73; fi
L=$(sudo docker container inspect -f '{{{{ index .Config.Labels "{LABEL}" }}}}' {cont} 2>/dev/null || true)
if sudo test -f {base}/node.env && ! {{ sudo grep -qx 'CID={cascade_id}' {base}/node.env && sudo grep -qx 'ROLE=exit' {base}/node.env; }}; then exit 73; fi
if ! sudo test -f {base}/node.env && {{ sudo docker container inspect {cont} >/dev/null 2>&1 || ip link show {iface} >/dev/null 2>&1; }}; then exit 73; fi
if sudo docker container inspect {cont} >/dev/null 2>&1 && [ "$L" != "{cascade_id}" ]; then exit 73; fi
if ip link show {iface} >/dev/null 2>&1 && [ "$L" != "{cascade_id}" ]; then exit 73; fi
echo CASCADE_AVAILABLE
'''
    cid = str(cascade_id or "")
    return foreign_guard() + f'''L=$(sudo docker container inspect -f '{{{{ index .Config.Labels "{LABEL}" }}}}' {CONTAINER} 2>/dev/null || true)
if sudo test -f {BASE}/node.env && ! sudo grep -qx 'CID={cid}' {BASE}/node.env; then echo CASCADE_CONFLICT; exit 73; fi
if ! sudo test -f {BASE}/node.env && {{ sudo docker container inspect {CONTAINER} >/dev/null 2>&1 || ip link show {INTERFACE} >/dev/null 2>&1; }}; then echo CASCADE_CONFLICT; exit 73; fi
OWNED=no
if [ -n "{cid}" ] && sudo test -f {BASE}/node.env && sudo grep -qx 'CID={cid}' {BASE}/node.env; then OWNED=yes; fi
if sudo docker container inspect {CONTAINER} >/dev/null 2>&1 && {{ [ -z "{cid}" ] || [ "$L" != "{cid}" ]; }}; then echo CASCADE_CONFLICT; exit 73; fi
if ip link show {INTERFACE} >/dev/null 2>&1 && {{ [ -z "{cid}" ] || [ "$L" != "{cid}" ]; }}; then echo CASCADE_CONFLICT; exit 73; fi
if ip link show acgre >/dev/null 2>&1; then echo CASCADE_CONFLICT; exit 73; fi
if sudo docker container inspect xray-cascade >/dev/null 2>&1; then echo CASCADE_CONFLICT; exit 73; fi
if [ "$OWNED" != yes ] && {{ sudo docker container inspect acontrol-cascade >/dev/null 2>&1 || sudo docker container inspect acontrol-cascade-exit >/dev/null 2>&1 || sudo test -e /etc/default/acontrol-gre; }}; then echo CASCADE_CONFLICT; exit 73; fi
if [ "$OWNED" != yes ] && {{ ip route show table 242 2>/dev/null | grep -q . || ip rule show | grep -Eq '^(1009|1010|1011):'; }}; then echo CASCADE_CONFLICT; exit 73; fi
if [ "$OWNED" != yes ] && sudo nft list table inet ac_cascade_awg >/dev/null 2>&1; then echo CASCADE_CONFLICT; exit 73; fi
echo CASCADE_AVAILABLE
'''


def install(role: str, peer_ip: str, cascade_id: int, params: dict,
            entry_inner: str, exit_inner: str, *, scoped_exit: bool = False) -> list[str]:
    if scoped_exit and role != "exit":
        raise ValueError("Only exit resources may be shared")
    paths = resources(cascade_id if scoped_exit else None)
    BASE, SCRIPT, CONTAINER, INTERFACE, UNIT, TIMER = (paths[k] for k in
        ("base", "script", "container", "interface", "unit", "timer"))
    peer_ip = str(ipaddress.IPv4Address(peer_ip))
    params = params | {"entry_inner": entry_inner, "exit_inner": exit_inner}
    peer_role = "exit" if role == "entry" else "entry"
    values = {
        "CID": str(cascade_id), "ROLE": role, "PORT": str(int(params[f"{role}_port"])),
        "PEER": peer_ip, "PUBLIC": params[f"{role}_public"],
        "PEER_PUBLIC": params[f"{peer_role}_public"],
        "INNER": params[f"{role}_inner"], "PEER_INNER": params[f"{peer_role}_inner"],
    }
    env = "\n".join(f"{key}={shlex.quote(value)}" for key, value in values.items()) + "\n"
    unit = f'''[Unit]
Description=Encrypted cascade link
After=network-online.target docker.service
Wants=network-online.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart={SCRIPT} up
# No ExecStop: stopping a service must not remove the fail-closed guard.
[Install]
WantedBy=multi-user.target
'''
    heal = f'''[Unit]
Description=Repair encrypted cascade link
After=docker.service
[Service]
Type=oneshot
ExecStart={SCRIPT} heal
'''
    timer = '''[Unit]
Description=Check encrypted cascade link
[Timer]
OnBootSec=20
OnUnitActiveSec=20
Unit=@HEAL@
[Install]
WantedBy=timers.target
'''
    timer = timer.replace("@HEAL@", paths["heal"])
    lines = [preflight_command(cascade_id, scoped_exit=scoped_exit).replace("exit 73", "fail 'foreign cascade underlay'"),
             "if ! command -v nft >/dev/null 2>&1; then "
             "sudo apt-get update -qq && sudo apt-get install -y -qq nftables >/dev/null 2>&1 "
             "|| fail 'nftables is required for AWG'; fi",
             f"sudo install -d -m 700 {BASE} {BASE}/build",
             "sudo install -d -m 755 /lib65/scripts",
             "EGRESS=$(ip -4 route show default | awk '/^default/ {print $5; exit}')",
             '[ -n "$EGRESS" ] || fail "AWG egress interface"',
             _put(SCRIPT, runtime_script(cascade_id if scoped_exit else None, params.get("runtime_owner", "")), "700"),
             _put(f"{BASE}/link.conf", config(role, params)),
             _put(f"{BASE}/node.env.next", env),
             f"printf 'EGRESS=%q\\n' \"$EGRESS\" | sudo tee -a {BASE}/node.env.next >/dev/null || fail 'AWG environment'",
             f"sudo mv -f {BASE}/node.env.next {BASE}/node.env || fail 'AWG environment'",
             _put(f"{BASE}/build/Dockerfile", deploy._dockerfile_v3()),
             _put(f"{BASE}/build/start.sh", "#!/bin/sh\nexit 1\n", "700"),
             f"BUILD={BASE}/build; IMG={IMAGE}; CONT={CONTAINER}",
             f"if ! sudo docker image inspect {IMAGE} >/dev/null 2>&1; then"]
    lines += ["  " + line for line in deploy._v3_build_lines(8)]
    lines += ["fi", _put(f"/etc/systemd/system/{UNIT}", unit, "644"),
              _put(f"/etc/systemd/system/{paths['heal']}", heal, "644"),
              _put(f"/etc/systemd/system/{TIMER}", timer, "644"),
              "sudo systemctl daemon-reload",
              f"sudo systemctl enable {UNIT} {TIMER} >/dev/null 2>&1 || fail 'AWG enable'",
              f"sudo {SCRIPT} guard || fail 'AWG guard'",
              f"sudo systemctl restart {UNIT} || fail 'AWG start'",
              f"sudo systemctl start {TIMER} || fail 'AWG timer'",
              "if command -v ufw >/dev/null 2>&1; then "
              f"sudo ufw allow from {peer_ip} to any port {int(params[f'{role}_port'])} proto udp >/dev/null 2>&1 || fail 'AWG firewall'; fi"]
    if role == "entry":
        lines += [f"for n in $(seq 1 45); do ping -c 1 -W 1 {exit_inner} >/dev/null 2>&1 || true; "
                  f"sudo {SCRIPT} status | grep -q '^CASCADE_AWG=yes$' && break; sleep 1; done",
                  f"sudo {SCRIPT} status | grep -q '^CASCADE_AWG=yes$' || fail 'AWG handshake or routing'",
                  f"sudo {SCRIPT} status"]
    return lines


def remove(cascade_id: int, *, scoped_exit: bool = False, owner: str = "") -> str:
    from app import cascade

    paths = resources(cascade_id if scoped_exit else None)
    BASE, SCRIPT, UNIT, TIMER = (paths[k] for k in ("base", "script", "unit", "timer"))
    # A failed first install may have no device yet. Ownership remains mandatory.
    return ((preflight_command(cascade_id, scoped_exit=True) if scoped_exit else foreign_guard()) + f'''
{cascade.stop_units(TIMER, paths['heal'], UNIT)}
if sudo test -f {BASE}/node.env; then
  sudo grep -qx 'CID={int(cascade_id)}' {BASE}/node.env || exit 73
  if sudo test -x {SCRIPT}; then
    sudo {SCRIPT} down || exit 73
  else
    sudo bash -s -- down <<'AC_CASCADE_AWG_RUNTIME' || exit 73
{runtime_script(cascade_id if scoped_exit else None, owner)}AC_CASCADE_AWG_RUNTIME
  fi
fi
sudo rm -f /etc/systemd/system/{UNIT} /etc/systemd/system/{TIMER} /etc/systemd/system/{paths['heal']} || exit 73
sudo rm -rf {BASE} || exit 73
sudo rm -f {SCRIPT} || exit 73
sudo systemctl daemon-reload || exit 73
''')


def check_command() -> str:
    return (f"if sudo test -x {SCRIPT}; then timeout 15s sudo {SCRIPT} status; fi\n")
