"""Owned native VPN containers; client keys/configuration survive image updates."""

import base64
import json
import secrets
import shlex
from dataclasses import dataclass

from app import awg

LABEL = "org.amnezia.control.native"


@dataclass(frozen=True)
class Spec:
    protocol: str
    container: str
    image: str
    directory: str
    port: int
    subnet: str
    interface: str
    data_path: str

    @property
    def script(self):
        return f"/lib65/scripts/{self.container}-start.sh"


SPECS = {
    "wireguard": Spec("wireguard", "acontrol-wireguard", "acontrol-wireguard", "/opt/acontrol/native-wireguard",
                      51820, "10.85.0.0/24", "wg0", "/opt/amnezia/awg"),
    "openvpn-native": Spec("openvpn-native", "acontrol-openvpn-native", "acontrol-openvpn-native", "/opt/acontrol/native-openvpn",
                           1194, "10.84.0.0/24", "tun0", "/opt/amnezia/openvpn"),
}

WG_DOCKERFILE = """FROM alpine:3.24
RUN apk add --no-cache wireguard-go wireguard-tools iproute2 iptables bash dumb-init curl
ENTRYPOINT ["dumb-init","/bin/sh","/entrypoint.sh"]
"""
OVPN_DOCKERFILE = """FROM alpine:3.24
RUN apk add --no-cache openvpn easy-rsa openssl iproute2 iptables dumb-init socat curl
RUN ln -s /run/openvpn/status.log /openvpn-status.log
ENTRYPOINT ["dumb-init","/bin/sh","/entrypoint.sh"]
"""

WG_START = r'''#!/bin/sh
set -eu
D=/opt/amnezia/awg
wireguard-go -f wg0 &
PID=$!
trap 'kill "$PID" 2>/dev/null || true' TERM INT EXIT
for n in $(seq 1 40); do wg show wg0 >/dev/null 2>&1 && break; sleep 0.1; done
wg-quick strip "$D/wg0.conf" > /run/wg0.conf
chmod 600 /run/wg0.conf
wg setconf wg0 /run/wg0.conf
ip address add 10.85.0.1/24 dev wg0
ip link set wg0 mtu 1380 up
iptables -t nat -A POSTROUTING -s 10.85.0.0/24 ! -o wg0 -j MASQUERADE
iptables -t mangle -A FORWARD -i wg0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
iptables -t mangle -A FORWARD -o wg0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
iptables -A FORWARD -i wg0 -s 10.85.0.0/24 -j ACCEPT
iptables -A FORWARD -o wg0 -d 10.85.0.0/24 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
wait "$PID"
'''

OVPN_START = r'''#!/bin/sh
set -eu
mkdir -p /run/openvpn
chmod 770 /run/openvpn
chown nobody /run/openvpn
iptables -t nat -A POSTROUTING -s 10.84.0.0/24 ! -o tun0 -j MASQUERADE
iptables -A FORWARD -i tun0 -s 10.84.0.0/24 -j ACCEPT
iptables -A FORWARD -o tun0 -d 10.84.0.0/24 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
exec openvpn --config /opt/amnezia/openvpn/server.conf
'''

OVPN_GEN = r'''set -eu
umask 077
export EASYRSA_PKI=/opt/amnezia/openvpn/pki EASYRSA_BATCH=1
cd /usr/share/easy-rsa
./easyrsa init-pki >/dev/null 2>&1
EASYRSA_REQ_CN=NativeVPN ./easyrsa build-ca nopass >/dev/null 2>&1
./easyrsa build-server-full server nopass >/dev/null 2>&1
./easyrsa gen-crl >/dev/null 2>&1
D=/opt/amnezia/openvpn
cp "$EASYRSA_PKI/ca.crt" "$D/ca.crt"
cp "$EASYRSA_PKI/issued/server.crt" "$D/server.crt"
cp "$EASYRSA_PKI/private/server.key" "$D/server.key"
cp "$EASYRSA_PKI/crl.pem" "$D/crl.pem"
openvpn --genkey secret "$D/ta.key"
mkdir -p "$D/ccd"
chmod 755 "$D" "$D/ccd"
chmod 644 "$D/ca.crt" "$D/server.crt" "$D/crl.pem"
printf '[]\n' > "$D/clientsTable"
'''


def ovpn_server_config(port: int, transport: str, dns: str) -> str:
    dns_values = [p.strip() for p in dns.split(",") if p.strip()] or ["1.1.1.1", "1.0.0.1"]
    lines = [f"port {port}", f"proto {'udp' if transport == 'udp' else 'tcp-server'}", "dev tun0",
             "topology subnet", "server 10.84.0.0 255.255.255.0", "dh none",
             "ca /opt/amnezia/openvpn/ca.crt", "cert /opt/amnezia/openvpn/server.crt",
             "key /opt/amnezia/openvpn/server.key", "tls-auth /opt/amnezia/openvpn/ta.key 0",
             "crl-verify /opt/amnezia/openvpn/crl.pem", "client-config-dir /opt/amnezia/openvpn/ccd",
             "ifconfig-pool-persist /run/openvpn/ipp.txt", "status /run/openvpn/status.log 5",
             "management /run/openvpn/management.sock unix", "management-client-user root",
             "keepalive 10 60", "persist-key", "persist-tun", "user nobody", "group nobody",
             "tls-server", "tls-version-min 1.2", "auth SHA256",
             "data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305",
             'push "redirect-gateway def1 bypass-dhcp"',
             # OpenVPN's documented IPv4-only VPN policy: install IPv6 routes
             # into the tunnel and answer with no-route, never bypass it.
             'push "ifconfig-ipv6 fd84:6e61:7469::2/64 fd84:6e61:7469::1"',
             'push "redirect-gateway ipv6"', "block-ipv6", "verb 2"]
    lines += [f'push "dhcp-option DNS {value}"' for value in dns_values]
    return "\n".join(lines) + "\n"


def _put(path: str, content: str, mode="600") -> str:
    encoded = base64.b64encode(content.encode()).decode()
    target = f'"{path}"' if path.startswith(("$A/", "$BUILD/")) else shlex.quote(path)
    return (f"printf '%s' {shlex.quote(encoded)} | base64 -d | sudo sh -c "
            "'umask 077; cat > \"$1.tmp\" && chmod \"$2\" \"$1.tmp\" && mv -f \"$1.tmp\" \"$1\"' sh "
            f"{target} {mode}")


def build_script(protocol: str, port: int, transport: str, dns: str) -> str:
    spec = SPECS[protocol]
    if not 1 <= port <= 65535 or transport not in {"udp", "tcp"}:
        raise ValueError("Invalid native VPN listener")
    if protocol == "wireguard" and transport != "udp":
        raise ValueError("WireGuard requires UDP")
    dockerfile = WG_DOCKERFILE if protocol == "wireguard" else OVPN_DOCKERFILE
    start = WG_START if protocol == "wireguard" else OVPN_START
    metadata = json.dumps({"protocol": protocol, "port": port, "transport": transport}) + "\n"
    health = (
        'test "$(wg show wg0 public-key)" = "$(cat /opt/amnezia/awg/wireguard_server_public_key.key)" '
        "&& ip -4 address show dev wg0 | grep -q '10.85.0.1/24'"
    ) if protocol == "wireguard" else (
        "printf 'state\\n' | socat -t 3 - UNIX-CONNECT:/run/openvpn/management.sock "
        "| grep -q ',CONNECTED,SUCCESS,'"
    )
    # Only these two fixed container names and their explicit ownership labels
    # may be replaced. No legacy container, PKI, interface, or client is adopted.
    lines = ["#!/bin/bash", "set -Eeuo pipefail", "umask 077",
             "fail(){ echo \"DEPLOY_ERROR: $1\"; exit 1; }",
             f"C={spec.container}; D={spec.directory}; A=$D/data; IMAGE={spec.image}",
             f"OWNER={shlex.quote(LABEL)}; PROTO={protocol}",
             "mkdir -p \"$HOME/.acontrol\"; exec 9>\"$HOME/.acontrol/$PROTO.install.lock\"",
             "flock -n 9 || fail 'native deployment busy'",
             "command -v docker >/dev/null || fail 'install Docker before deploying native VPN'",
             'container_present(){ local output; if output=$(sudo docker container inspect "$1" 2>&1); then return 0; fi; '
             'case "$output" in *"No such container:"*|*"No such object:"*) return 1 ;; *) fail "cannot inspect native container" ;; esac; }',
             'for path in /opt/acontrol "$D" "$D/.native-protocol" "$D/start.previous" "$A" "$A/native.json" /lib65/scripts ' + shlex.quote(spec.script) + '; do '
             'sudo test ! -L "$path" || fail "unsafe native path"; done',
             "if container_present \"$C\"; then",
             "  L=$(sudo docker container inspect -f '{{ index .Config.Labels \"org.amnezia.control.native\" }}' \"$C\")",
             "  [ \"$L\" = \"$PROTO\" ] || fail 'container is not owned by this protocol'", "fi",
             'if sudo test -d "$D" && ! sudo test -f "$D/.native-protocol"; then fail "unowned native directory"; fi',
             'if sudo test -f "$D/.native-protocol"; then [ "$(sudo cat "$D/.native-protocol")" = "$PROTO" ] || fail "native directory belongs to another protocol"; fi',
             'sudo mkdir -p "$D" /lib65/scripts; sudo chmod 700 "$D"',
             f"printf '%s\\n' {protocol} | sudo tee \"$D/.native-protocol\" >/dev/null",
             'BUILD=$(mktemp -d); STAGE=""; '
             'cleanup(){ rm -rf "$BUILD"; if [ -n "$STAGE" ]; then case "$STAGE" in "$D"/.initial.*) sudo rm -rf "$STAGE" ;; esac; fi; }; trap cleanup EXIT',
             _put("$BUILD/Dockerfile", dockerfile),
             f'sudo docker build --pull -q -t "$IMAGE" "$BUILD" >/dev/null',
             'if sudo test -f ' + shlex.quote(spec.script) + '; then sudo cp ' + shlex.quote(spec.script) + ' "$D/start.previous"; fi',
             _put(spec.script, start, "755"),
             'if ! sudo test -f "$A/native.json"; then',
             '  if sudo test -d "$A" && [ -n "$(sudo find "$A" -mindepth 1 -maxdepth 1 -print -quit)" ]; then fail "incomplete native data: restore a configuration snapshot"; fi',
             '  STAGE=$(sudo mktemp -d "$D/.initial.XXXXXX"); A=$STAGE']
    if protocol == "wireguard":
        private, public = awg.generate_keypair()
        psk = base64.b64encode(secrets.token_bytes(32)).decode()
        config = f"[Interface]\nPrivateKey = {private}\nListenPort = {port}\nAddress = 10.85.0.1/24\n"
        for name, value in (("wg0.conf", config), ("wireguard_server_public_key.key", public + "\n"),
                            ("wireguard_server_private_key.key", private + "\n"), ("wireguard_psk.key", psk + "\n"),
                            ("clientsTable", "[]\n")):
            lines.append(_put(f"$A/{name}", value))
    else:
        lines += [f'if container_present {spec.container}-init; then fail "native initialization container already exists"; fi',
                  f"sudo docker run --rm --name {spec.container}-init --label {LABEL}={protocol} "
                  f"-v \"$A:{spec.data_path}\" --entrypoint sh \"$IMAGE\" -c {shlex.quote(OVPN_GEN)}",
                  _put("$A/server.conf", ovpn_server_config(port, transport, dns))]
    lines += [_put("$A/native.json", metadata),
              '  if sudo test -d "$D/data"; then sudo rmdir "$D/data"; fi; sudo mv "$A" "$D/data"; A=$D/data; STAGE=""', "fi",
              'OLD=""; OLD_RENAMED=no; NEW_ATTEMPT=no; FINISHED=no',
              'rollback(){ set +e; if [ "$FINISHED" != yes ]; then '
              'if [ "$NEW_ATTEMPT" = yes ]; then L=$(sudo docker container inspect -f \'{{ index .Config.Labels "org.amnezia.control.native" }}\' "$C" 2>/dev/null); '
              '[ "$L" != "$PROTO" ] || sudo docker rm -f "$C" >/dev/null 2>&1; fi; '
              'if sudo test -f "$D/start.previous"; then sudo cp "$D/start.previous" ' + shlex.quote(spec.script) + '; fi; '
              'if [ "$OLD_RENAMED" = yes ]; then sudo docker rename "$OLD" "$C"; fi; '
              'if [ -n "$OLD" ]; then sudo docker update --restart=unless-stopped "$C" >/dev/null; sudo docker start "$C" >/dev/null; fi; fi; }',
              "trap 'rc=$?; rollback; echo DEPLOY_ERROR: native_container_start_failed; exit \"$rc\"' ERR",
              'if container_present "$C"; then '
              'L=$(sudo docker container inspect -f \'{{ index .Config.Labels "org.amnezia.control.native" }}\' "$C"); '
              '[ "$L" = "$PROTO" ] || fail "container ownership changed during deployment"; '
              'OLD="$C-previous-$(date +%s)-$$"; '
              'sudo docker update --restart=no "$C" >/dev/null; sudo docker stop -t 10 "$C" >/dev/null; '
              'sudo docker rename "$C" "$OLD"; OLD_RENAMED=yes; fi',
              'SYSCTL=(); [ ! -e /proc/sys/net/mptcp/enabled ] || SYSCTL=(--sysctl net.mptcp.enabled=0)',
              'NEW_ATTEMPT=yes',
              f"sudo docker run -d --name \"$C\" --label {LABEL}={protocol} --restart unless-stopped "
              "--cap-drop ALL --cap-add NET_ADMIN --cap-add NET_BIND_SERVICE --cap-add SETUID --cap-add SETGID --cap-add CHOWN "
              "--device /dev/net/tun --sysctl net.ipv4.ip_forward=1 \"${SYSCTL[@]}\" "
              f"-p {port}:{port}/{transport} -v \"$A:{spec.data_path}\" -v {spec.script}:/entrypoint.sh:ro "
              "--read-only --tmpfs /run --tmpfs /tmp --security-opt no-new-privileges:true "
              "--log-opt max-size=10m --log-opt max-file=2 -e GODEBUG=multipathtcp=0 \"$IMAGE\" >/dev/null",
              f'for n in $(seq 1 60); do sudo docker exec "$C" sh -c {shlex.quote(health)} >/dev/null 2>&1 && break; sleep 1; done',
              f'sudo docker exec "$C" sh -c {shlex.quote(health)} >/dev/null 2>&1',
              f'if command -v ufw >/dev/null; then sudo ufw allow {port}/{transport} >/dev/null; '
              f'sudo ufw route allow proto {transport} from any to any port {port} >/dev/null; fi',
              'FINISHED=yes; if [ -n "$OLD" ]; then sudo docker rm "$OLD" >/dev/null; fi',
              'echo DEPLOY_DONE']
    return "\n".join(lines) + "\n"
