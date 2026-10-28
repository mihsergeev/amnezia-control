"""Каскад из двух серверов: клиенты подключаются ко входу, в интернет выходят
с адреса выхода. Российские адреса и домены вход выпускает напрямую.

Устройство на нодах (все в /opt/acontrol/cascade, службы systemd):
- вход: шлюз acontrol-cascade (xray-core в сети хоста). Исходящий трафик
  VPN-контейнеров с docker0 заворачивается в него через tproxy
  (cascade-tproxy.sh), он раскладывает по геобазам runetfreedom: российское
  напрямую, остальное на выход. Если шлюз лежит, трафик клиентов не уходит
  никуда, утечки мимо выхода нет;
- связь вход -> выход одна из двух:
  vless - VLESS Reality до контейнера acontrol-cascade-exit на выходе. Снаружи
          похоже на HTTPS, но бывают провайдеры, где TCP в сеть выхода
          замерзает после нескольких десятков килобайт отправки;
  gre   - голый GRE-туннель acgre (gre-tun.sh), выход маскарадит сеть туннеля.
          IP-протокол 47 такие фильтры не трогают, но шифрования нет.

Сначала ставится выход, потом вход; tproxy на входе включается последним,
после проверки, что через шлюз открывается интернет. До этого клиенты входа
ходят напрямую, как раньше.
"""

import asyncio
import base64
import ipaddress
import json
import os
import random
import re
import uuid

import asyncssh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

XRAY_IMAGE = "ghcr.io/xtls/xray-core:26.3.27"
DIR = "/opt/acontrol/cascade"
EXIT_DIR = "/opt/acontrol/cascade-exit"
GATEWAY = "acontrol-cascade"
EXIT_CONTAINER = "acontrol-cascade-exit"
GRE_IF = "acgre"
GRE_DEFAULTS = "/etc/default/acontrol-gre"
TPROXY_PORT = 12350
SOCKS_PORT = 10818
# метки и таблицы маршрутизации - свои, чтобы не задеть чужие правила на ноде
TPROXY_MARK = "0x100"
TPROXY_TABLE = 241
GRE_MARK = 0x200
GRE_TABLE = 242
REALITY_SITE = "www.googletagmanager.com"
# порты VLESS на выходе по порядку предпочтения: 443 похож на обычный HTTPS
VLESS_PORTS = (443, 8443, 2083, 2096)
TAG = "cascade"  # каталог деплоя на нодах ($HOME/.acontrol/cascade)
TRANSPORTS = ("vless", "gre")

# проверка канала: сколько отправляем со входа на выход и сколько ждем
PROBE_BYTES = 20 * 1024 * 1024
PROBE_SECONDS = 15
# меньше этого дошло - канал замерзает (у таких фильтров обрыв на десятках кб)
PROBE_OK_BYTES = 2 * 1024 * 1024
PROBE_GRE_IF = "acgretst"


class CascadeError(Exception):
    pass


def _b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def inner_net(cascade_id: int) -> tuple[str, str, str]:
    """(сеть, адрес входа, адрес выхода) внутри GRE: своя /30 на каждый каскад."""
    n = cascade_id % 254 + 1
    return f"10.99.{n}.0/30", f"10.99.{n}.1/30", f"10.99.{n}.2/30"


def new_vless_params() -> dict[str, str]:
    key = X25519PrivateKey.generate()

    def b64(b: bytes) -> str:
        return base64.urlsafe_b64encode(b).decode().rstrip("=")

    priv = key.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    pub = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return {
        "uuid": str(uuid.uuid4()),
        "private_key": b64(priv),
        "public_key": b64(pub),
        "short_id": os.urandom(8).hex(),
        "sni": REALITY_SITE,
    }


# --- скрипты на нодах --------------------------------------------------------

_GRE_TUN_SH = r"""#!/bin/sh
# Amnezia Control: GRE-туннель каскада. Параметры в @DEFAULTS@:
#   IF, LOCAL, REMOTE, INNER (адрес/30 внутри туннеля), ROLE=entry|exit
#   entry: трафик с меткой MARK уходит в туннель (таблица TABLE), без туннеля никуда
#   exit:  выпускает сеть туннеля NET в интернет через EGRESS
#   gre-tun.sh up|down|status
set -u
. @DEFAULTS@

rule() { t=$1; shift; iptables -t "$t" -C "$@" 2>/dev/null || iptables -t "$t" -I "$@"; }
unrule() { t=$1; shift; while iptables -t "$t" -D "$@" 2>/dev/null; do :; done; }

up() {
  modprobe ip_gre 2>/dev/null || true
  ip link show "$IF" >/dev/null 2>&1 || ip tunnel add "$IF" mode gre local "$LOCAL" remote "$REMOTE" ttl 64 || exit 1
  ip addr replace "$INNER" dev "$IF"
  ip link set "$IF" mtu 1476 up
  # ответы из туннеля приходят с внешних адресов, строгий rp_filter их бы выкинул
  sysctl -qw "net.ipv4.conf.$IF.rp_filter=2"
  rule filter INPUT -p gre -s "$REMOTE" -j ACCEPT
  rule mangle FORWARD -o "$IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
  rule mangle FORWARD -i "$IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
  if [ "$ROLE" = exit ]; then
    sysctl -qw net.ipv4.ip_forward=1
    rule filter FORWARD -i "$IF" -o "$EGRESS" -j ACCEPT
    rule filter FORWARD -i "$EGRESS" -o "$IF" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    rule nat POSTROUTING -s "$NET" -o "$EGRESS" -j MASQUERADE
  else
    ip route replace default dev "$IF" table "$TABLE"
    # туннеля нет - таблица пустая, помеченный трафик упирается в unreachable
    ip rule show | grep -q "fwmark $MARK lookup $TABLE" || ip rule add fwmark "$MARK" lookup "$TABLE" pref 1010
    ip rule show | grep -q "fwmark $MARK unreachable" || ip rule add fwmark "$MARK" unreachable pref 1011
  fi
}

down() {
  if [ "$ROLE" = exit ]; then
    unrule filter FORWARD -i "$IF" -o "$EGRESS" -j ACCEPT
    unrule filter FORWARD -i "$EGRESS" -o "$IF" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    unrule nat POSTROUTING -s "$NET" -o "$EGRESS" -j MASQUERADE
  else
    while ip rule del fwmark "$MARK" lookup "$TABLE" 2>/dev/null; do :; done
    while ip rule del fwmark "$MARK" unreachable 2>/dev/null; do :; done
    ip route flush table "$TABLE" 2>/dev/null || true
  fi
  unrule filter INPUT -p gre -s "$REMOTE" -j ACCEPT
  unrule mangle FORWARD -o "$IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
  unrule mangle FORWARD -i "$IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
  ip link del "$IF" 2>/dev/null || true
}

status() {
  ip -br a show "$IF" 2>/dev/null || echo "no $IF"
  [ "$ROLE" = exit ] || ip rule show | grep "fwmark $MARK" || echo "no ip rule"
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  status) status ;;
  *) echo "usage: $0 up|down|status" >&2; exit 2 ;;
esac
"""

_GRE_UNIT = """[Unit]
Description=Amnezia Control: cascade GRE tunnel
After=network-online.target systemd-networkd.service
Wants=network-online.target
# networkd при рестарте чистит чужие ip rule, ставим заново
PartOf=systemd-networkd.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=@DIR@/gre-tun.sh up
ExecStop=@DIR@/gre-tun.sh down

[Install]
WantedBy=multi-user.target
"""

_TPROXY_SH = r"""#!/bin/sh
# Amnezia Control: заворачивает исходящий трафик VPN-контейнеров (docker0) в
# шлюз каскада (tproxy на 127.0.0.1:@PORT@). Дальше шлюз решает, куда выпустить.
#   cascade-tproxy.sh up|down|status
set -u
IF=docker0
PORT=@PORT@
MARK=@MARK@
TABLE=@TABLE@
CHAIN=ACONTROL_CASCADE
# не трогаем локальные и служебные сети (в т.ч. docker) и адреса самой ноды
SKIP="0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16 224.0.0.0/4 240.0.0.0/4"

up() {
  modprobe xt_TPROXY 2>/dev/null || true
  ip rule show | grep -q "fwmark $MARK lookup $TABLE" || ip rule add fwmark $MARK lookup $TABLE
  ip route replace local 0.0.0.0/0 dev lo table $TABLE
  iptables -t mangle -N $CHAIN 2>/dev/null || iptables -t mangle -F $CHAIN
  OWN=$(ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1)
  for net in $SKIP $OWN; do
    iptables -t mangle -A $CHAIN -d "$net" -j RETURN
  done
  # ответы контейнеров на входящие к опубликованным портам
  iptables -t mangle -A $CHAIN -m conntrack --ctstate DNAT -j RETURN
  iptables -t mangle -A $CHAIN -p tcp -j TPROXY --on-ip 127.0.0.1 --on-port $PORT --tproxy-mark $MARK/$MARK
  iptables -t mangle -A $CHAIN -p udp -j TPROXY --on-ip 127.0.0.1 --on-port $PORT --tproxy-mark $MARK/$MARK
  iptables -t mangle -C PREROUTING -i $IF -j $CHAIN 2>/dev/null || iptables -t mangle -A PREROUTING -i $IF -j $CHAIN
  # INPUT бывает по умолчанию DROP (ufw): пропускаем то, что завернули в шлюз
  iptables -C INPUT -i $IF -m mark --mark $MARK/$MARK -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -i $IF -m mark --mark $MARK/$MARK -j ACCEPT
}

down() {
  iptables -D INPUT -i $IF -m mark --mark $MARK/$MARK -j ACCEPT 2>/dev/null || true
  iptables -t mangle -D PREROUTING -i $IF -j $CHAIN 2>/dev/null || true
  iptables -t mangle -F $CHAIN 2>/dev/null || true
  iptables -t mangle -X $CHAIN 2>/dev/null || true
  ip rule del fwmark $MARK lookup $TABLE 2>/dev/null || true
  ip route flush table $TABLE 2>/dev/null || true
}

status() {
  ip rule show | grep "lookup $TABLE" || echo "no ip rule"
  iptables -t mangle -S PREROUTING | grep $CHAIN || echo "no PREROUTING jump"
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  status) status ;;
  *) echo "usage: $0 up|down|status" >&2; exit 2 ;;
esac
"""

_TPROXY_UNIT = """[Unit]
Description=Amnezia Control: VPN containers egress into the cascade gateway
After=network-online.target docker.service ufw.service systemd-networkd.service
Wants=network-online.target docker.service
PartOf=systemd-networkd.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=@DIR@/cascade-tproxy.sh up
ExecStop=@DIR@/cascade-tproxy.sh down

[Install]
WantedBy=multi-user.target
"""

_GEO_SH = r"""#!/bin/sh
# Amnezia Control: обновляет геобазы runetfreedom (geoip.dat, geosite.dat) для
# шлюза каскада и перезапускает его, если базы изменились. Качает через выход
# каскада (из России github бывает медленным), без шлюза или при ошибке напрямую.
# Сначала сверяет контрольные суммы и не качает базы, которые не менялись.
# Новые базы проверяются через xray -test до подмены, при ошибке остаются старые.
set -eu
DIR=@DIR@/geo
BASE=https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
cd "$TMP"
VIA=direct
if docker ps --format "{{.Names}}" | grep -qx @GATEWAY@; then
  VIA="127.0.0.1:@SOCKS@ direct"
fi
fetch() {
  for via in $VIA; do
    opt=""
    [ "$via" = direct ] || opt="--socks5-hostname $via"
    # shellcheck disable=SC2086
    curl -fsSL --retry 1 -m "$1" $opt -o "$2" "$BASE/$2" && return 0
  done
  return 1
}
changed=0
for f in geoip.dat geosite.dat; do
  fetch 60 "$f.sha256sum"
  if [ -s "$DIR/$f" ] && (cd "$DIR" && sha256sum -c "$TMP/$f.sha256sum" >/dev/null 2>&1); then
    cp "$DIR/$f" "$f"
    continue
  fi
  fetch 900 "$f"
  sha256sum -c "$f.sha256sum" >/dev/null
  changed=1
done
[ "$changed" = 1 ] || exit 0
mkdir -p "$TMP/geo" "$DIR"
cp geoip.dat geosite.dat "$TMP/geo/"
docker run --rm --user 0:0 -e XRAY_LOCATION_ASSET=/geo -v "$TMP/geo:/geo:ro" -v @DIR@/config:/cfg:ro \
  @IMAGE@ run -test -confdir /cfg >/dev/null
install -m 644 geoip.dat geosite.dat "$DIR/"
if docker ps --format "{{.Names}}" | grep -qx @GATEWAY@; then
  docker restart @GATEWAY@ >/dev/null
fi
echo "geo updated: $(date -Is)"
"""

_GEO_UNIT = """[Unit]
Description=Amnezia Control: cascade geo databases update
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=@DIR@/geo-update.sh
"""

_GEO_TIMER = """[Unit]
Description=Amnezia Control: daily cascade geo databases update

[Timer]
OnCalendar=*-*-* 04:30:00
RandomizedDelaySec=30m
Persistent=true

[Install]
WantedBy=timers.target
"""

_UNITS = {
    "acontrol-gre.service": _GRE_UNIT,
    "acontrol-cascade-tproxy.service": _TPROXY_UNIT,
    "acontrol-cascade-geo.service": _GEO_UNIT,
    "acontrol-cascade-geo.timer": _GEO_TIMER,
}


def _fill(text: str) -> str:
    return (
        text.replace("@DIR@", DIR)
        .replace("@DEFAULTS@", GRE_DEFAULTS)
        .replace("@PORT@", str(TPROXY_PORT))
        .replace("@MARK@", TPROXY_MARK)
        .replace("@TABLE@", str(TPROXY_TABLE))
        .replace("@IMAGE@", XRAY_IMAGE)
        .replace("@GATEWAY@", GATEWAY)
        .replace("@SOCKS@", str(SOCKS_PORT))
    )


def _put(path: str, text: str, mode: str = "644") -> str:
    """Строка скрипта: записать файл через sudo (redirect до sudo шел бы не от root)."""
    return (
        f"echo {_b64(text)} | base64 -d | sudo tee {path} >/dev/null "
        f"&& sudo chmod {mode} {path} || fail 'write {path}'"
    )


_HEAD = """set +e
fail() { echo "DEPLOY_ERROR: $1"; exit 1; }
log(){ echo "[$(date +%H:%M:%S)] $*"; }
"""

_DOCKER = (
    "command -v docker >/dev/null 2>&1 || { curl -fsSL https://get.docker.com "
    "| sudo sh >/dev/null || fail 'docker install'; }"
)

_SRC_OF = "sed -n 's/.* src \\([0-9.]*\\).*/\\1/p'"
_DEV_OF = "sed -n 's/.* dev \\([^ ]*\\).*/\\1/p'"


def _gre_defaults(role: str, remote: str, inner: str, net: str) -> str:
    lines = [
        f"IF={GRE_IF}", "LOCAL=$LOCAL", f"REMOTE={remote}", f"INNER={inner}", f"ROLE={role}",
    ]
    if role == "exit":
        lines += ["EGRESS=$EGRESS", f"NET={net}"]
    else:
        lines += [f"MARK={hex(GRE_MARK)}", f"TABLE={GRE_TABLE}"]
    return "\n".join(lines) + "\n"


def _gre_install(role: str, remote: str, inner: str, net: str) -> list[str]:
    """Строки скрипта: поставить и поднять GRE-службу. LOCAL - адрес, с которого
    нода ходит к соседу (за NAT это внутренний адрес), EGRESS - внешний интерфейс."""
    defaults = _gre_defaults(role, remote, inner, net)
    return [
        f'LOCAL=$(ip -4 route get {remote} | {_SRC_OF} | head -1)',
        '[ -n "$LOCAL" ] || fail "no route to peer"',
        f"EGRESS=$(ip -4 route get 1.1.1.1 | {_DEV_OF} | head -1)",
        '[ -n "$EGRESS" ] || fail "no default route"',
        f"sudo mkdir -p {DIR} || fail mkdir",
        _put(f"{DIR}/gre-tun.sh", _fill(_GRE_TUN_SH), "755"),
        # в файле параметров нужны значения LOCAL и EGRESS, поэтому heredoc, а не base64
        f"sudo tee {GRE_DEFAULTS} >/dev/null <<EOF\n{defaults}EOF",
        _put("/etc/systemd/system/acontrol-gre.service", _fill(_GRE_UNIT)),
        f"if command -v ufw >/dev/null 2>&1; then sudo ufw allow proto gre from {remote} >/dev/null 2>&1 || true; fi",
        "sudo systemctl daemon-reload",
        "sudo systemctl restart acontrol-gre.service || fail 'gre up'",
        "sudo systemctl enable acontrol-gre.service >/dev/null 2>&1",
        f'log "{GRE_IF}: $LOCAL -> {remote}, {inner}"',
    ]


def build_exit_script(transport: str, entry_ip: str, cascade_id: int, params: dict) -> str:
    net, _ein, xin = inner_net(cascade_id)
    lines = [_HEAD]
    if transport == "gre":
        lines += ['log "[1/2] GRE-туннель до входа"']
        lines += _gre_install("exit", entry_ip, xin, net)
        lines += [
            'log "[2/2] выпуск в интернет"',
            'if command -v ufw >/dev/null 2>&1; then '
            f'sudo ufw route allow in on {GRE_IF} out on "$EGRESS" >/dev/null 2>&1 || true; fi',
            f"sudo {DIR}/gre-tun.sh status",
        ]
    else:
        port = int(params["port"])
        lines += [
            'log "[1/3] docker"',
            _DOCKER,
            'log "[2/3] конфиг VLESS Reality"',
            f"sudo mkdir -p {EXIT_DIR} || fail mkdir",
            _put(f"{EXIT_DIR}/config.json", exit_vless_config(params), "600"),
            f"sudo docker pull -q {XRAY_IMAGE} >/dev/null || fail 'docker pull'",
            f'log "[3/3] контейнер, порт {port}/tcp открыт только для {entry_ip}"',
            f"sudo docker rm -f {EXIT_CONTAINER} >/dev/null 2>&1",
            f"sudo docker run -d --name {EXIT_CONTAINER} --restart always --network host "
            "--user 0:0 --read-only --cap-drop ALL --cap-add NET_BIND_SERVICE "
            "--security-opt no-new-privileges:true --log-opt max-size=10m --log-opt max-file=3 "
            f"-v {EXIT_DIR}:/usr/local/etc/xray:ro {XRAY_IMAGE} >/dev/null || fail 'docker run'",
            "sleep 3",
            f"sudo docker ps --format '{{{{.Names}}}}' | grep -qx {EXIT_CONTAINER} "
            f"|| fail \"xray: $(sudo docker logs --tail 3 {EXIT_CONTAINER} 2>&1 | tr '\\n' ' ')\"",
            "if command -v ufw >/dev/null 2>&1; then "
            f"sudo ufw allow from {entry_ip} to any port {port} proto tcp >/dev/null 2>&1 || true; fi",
            "if command -v firewall-cmd >/dev/null 2>&1; then sudo firewall-cmd --permanent "
            f"--add-rich-rule='rule family=ipv4 source address={entry_ip} port port={port} "
            "protocol=tcp accept' >/dev/null 2>&1 && sudo firewall-cmd --reload >/dev/null 2>&1; fi",
        ]
    lines += ['echo "DEPLOY_DONE"']
    return "\n".join(lines) + "\n"


def exit_vless_config(params: dict) -> str:
    sni = params["sni"]
    cfg = {
        # без журнала доступа: иначе на выходе копятся адреса сайтов клиентов
        "log": {"loglevel": "warning", "access": "none"},
        "inbounds": [{
            "tag": "from-entry", "listen": "0.0.0.0", "port": int(params["port"]),
            "protocol": "vless",
            "settings": {
                "clients": [{"id": params["uuid"], "flow": "xtls-rprx-vision"}],
                "decryption": "none",
            },
            "streamSettings": {
                "network": "tcp", "security": "reality",
                "realitySettings": {
                    "target": f"{sni}:443", "serverNames": [sni],
                    "privateKey": params["private_key"], "shortIds": [params["short_id"]],
                },
            },
            "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": True},
        }],
        "outbounds": [
            {"tag": "direct", "protocol": "freedom", "settings": {"domainStrategy": "UseIPv4"}},
            {"tag": "block", "protocol": "blackhole"},
        ],
        "routing": {"rules": [
            {"ip": ["geoip:private"], "outboundTag": "block"},
            {"protocol": ["bittorrent"], "outboundTag": "block"},
        ]},
    }
    return json.dumps(cfg, indent=2)


def entry_gateway_config(transport: str, exit_ip: str, params: dict, bootstrap: bool = False) -> str:
    """Конфиг шлюза на входе. Первый outbound (exit) - путь по умолчанию.
    bootstrap: без правил по геобазам, чтобы скачать их через выход, пока их еще нет."""
    if transport == "gre":
        out = {
            "tag": "exit", "protocol": "freedom",
            "settings": {"domainStrategy": "UseIPv4"},
            # метка уводит в таблицу GRE (gre-tun.sh), без туннеля - unreachable
            "streamSettings": {"sockopt": {"mark": GRE_MARK}},
        }
    else:
        out = {
            "tag": "exit", "protocol": "vless",
            "settings": {"vnext": [{
                "address": exit_ip, "port": int(params["port"]),
                "users": [{
                    "id": params["uuid"], "encryption": "none",
                    "flow": "xtls-rprx-vision-udp443",
                }],
            }]},
            "streamSettings": {
                "network": "tcp", "security": "reality",
                "realitySettings": {
                    "serverName": params["sni"], "fingerprint": "chrome",
                    "publicKey": params["public_key"], "shortId": params["short_id"],
                },
            },
        }
    cfg = {
        "log": {"loglevel": "warning", "access": "none"},
        "inbounds": [
            {
                "tag": "tproxy", "listen": "127.0.0.1", "port": TPROXY_PORT,
                "protocol": "dokodemo-door",
                "settings": {"network": "tcp,udp", "followRedirect": True},
                "streamSettings": {"sockopt": {"tproxy": "tproxy"}},
                "sniffing": {
                    "enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": True,
                },
            },
            # для проверок панели: curl --socks5 с самой ноды
            {
                "tag": "check", "listen": "127.0.0.1", "port": SOCKS_PORT,
                "protocol": "socks", "settings": {"udp": False},
            },
        ],
        "outbounds": [
            out,
            {"tag": "direct", "protocol": "freedom", "settings": {"domainStrategy": "UseIPv4"}},
            {"tag": "block", "protocol": "blackhole"},
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {"ip": ["geoip:private"], "outboundTag": "block"},
                {"domain": ["geosite:ru-blocked"], "outboundTag": "exit"},
                {"ip": ["geoip:ru-blocked"], "outboundTag": "exit"},
                {
                    "domain": [
                        "geosite:ru-available-only-inside", "geosite:category-ru",
                        "domain:ru", "domain:su", "domain:xn--p1ai",
                    ],
                    "outboundTag": "direct",
                },
                {"ip": ["geoip:ru"], "outboundTag": "direct"},
            ],
        },
    }
    if bootstrap:
        cfg["routing"] = {"rules": []}
    return json.dumps(cfg, indent=2)


# адрес выхода и российский адрес через шлюз (socks-вход check)
_CHECK_LINES = [
    f"EG=$(curl -4 -fsS -m 20 --socks5-hostname 127.0.0.1:{SOCKS_PORT} https://api.ipify.org 2>/dev/null)",
    # российский сервис на домене .ru: шлюз обязан выпустить его напрямую
    f"RU=$(curl -4 -fsS -m 15 --socks5-hostname 127.0.0.1:{SOCKS_PORT} https://ip.nic.ru 2>/dev/null "
    "| grep -oE '([0-9]{1,3}[.]){3}[0-9]{1,3}' | head -1)",
    'echo "CASCADE_EGRESS=$EG"',
    'echo "CASCADE_RU=$RU"',
]


def gateway_run(confdir: str) -> str:
    """Строка скрипта: запустить шлюз каскада с конфигом из confdir."""
    return (
        f"sudo docker run -d --name {GATEWAY} --restart always --network host "
        "--user 0:0 --read-only --cap-drop ALL --cap-add NET_ADMIN --cap-add NET_BIND_SERVICE "
        "--security-opt no-new-privileges:true --log-opt max-size=10m --log-opt max-file=3 "
        "-e XRAY_LOCATION_ASSET=/usr/local/share/xray "
        f"-v {confdir}:/usr/local/etc/xray:ro -v {DIR}/geo:/usr/local/share/xray:ro "
        f"{XRAY_IMAGE} >/dev/null || fail 'docker run'"
    )


def build_entry_script(transport: str, exit_ip: str, cascade_id: int, params: dict) -> str:
    net, ein, _xin = inner_net(cascade_id)
    lines = [_HEAD, 'log "[1/5] docker"', _DOCKER]
    if transport == "gre":
        lines += ['log "[2/5] GRE-туннель до выхода"']
        lines += _gre_install("entry", exit_ip, ein, net)
        xpeer = inner_net(cascade_id)[2].split("/")[0]
        lines += [
            f"ping -c 3 -W 2 {xpeer} >/dev/null 2>&1 && log 'туннель отвечает' "
            "|| log 'выход не отвечает на ping внутри туннеля, проверю через шлюз'",
        ]
    else:
        lines += ['log "[2/5] связь VLESS Reality, настроит шлюз"']
    lines += [
        'log "[3/5] геобазы российских сайтов"',
        f"sudo mkdir -p {DIR}/config {DIR}/geo || fail mkdir",
        _put(f"{DIR}/config/config.json", entry_gateway_config(transport, exit_ip, params), "600"),
        f"sudo mkdir -p {DIR}/boot || fail mkdir",
        _put(f"{DIR}/boot/config.json",
             entry_gateway_config(transport, exit_ip, params, bootstrap=True), "600"),
        _put(f"{DIR}/geo-update.sh", _fill(_GEO_SH), "755"),
        _put(f"{DIR}/cascade-tproxy.sh", _fill(_TPROXY_SH), "755"),
    ]
    for name in ("acontrol-cascade-tproxy.service", "acontrol-cascade-geo.service",
                 "acontrol-cascade-geo.timer"):
        lines.append(_put(f"/etc/systemd/system/{name}", _fill(_UNITS[name])))
    lines += [
        "sudo systemctl daemon-reload",
        f"sudo docker pull -q {XRAY_IMAGE} >/dev/null || fail 'docker pull'",
        # первая установка: баз еще нет, а без них шлюз с полными правилами не
        # запустится. Поднимаем его без правил и качаем базы через выход
        f"if ! sudo test -s {DIR}/geo/geosite.dat; then",
        f"  sudo docker rm -f {GATEWAY} >/dev/null 2>&1",
        "  " + gateway_run(f"{DIR}/boot"),
        "  sleep 3",
        "fi",
        f"sudo {DIR}/geo-update.sh 2>&1 | tail -2",
        f"sudo test -s {DIR}/geo/geosite.dat || fail 'geo download (github.com)'",
        'log "[4/5] шлюз каскада"',
        f"sudo docker rm -f {GATEWAY} >/dev/null 2>&1",
        gateway_run(f"{DIR}/config"),
        "sleep 3",
        f"sudo docker ps --format '{{{{.Names}}}}' | grep -qx {GATEWAY} "
        f"|| fail \"xray: $(sudo docker logs --tail 3 {GATEWAY} 2>&1 | tr '\\n' ' ')\"",
        'log "[5/5] проверка через шлюз"',
        *_CHECK_LINES,
        '[ -n "$EG" ] || fail "через выход интернет не открывается"',
        'log "выход в интернет: $EG"',
        # только теперь заворачиваем клиентов: до этого они ходили напрямую
        "sudo systemctl enable --now acontrol-cascade-tproxy.service >/dev/null 2>&1 "
        "|| fail 'tproxy'",
        "sudo systemctl enable --now acontrol-cascade-geo.timer >/dev/null 2>&1",
        'echo "DEPLOY_DONE"',
    ]
    return "\n".join(lines) + "\n"


def build_check_command() -> str:
    """Разовая проверка каскада на входе: службы, шлюз, адреса через шлюз."""
    return "\n".join([
        f"GW=$(sudo docker ps --format '{{{{.Names}}}}' | grep -qx {GATEWAY} && echo yes || echo no)",
        "TP=$(systemctl is-active acontrol-cascade-tproxy.service 2>/dev/null)",
        f"TUN=$(ip -br link show {GRE_IF} 2>/dev/null | awk '{{print $2}}')",
        'echo "CASCADE_GW=$GW"',
        'echo "CASCADE_TPROXY=$TP"',
        'echo "CASCADE_TUN=$TUN"',
        *_CHECK_LINES,
    ]) + "\n"


def parse_kv(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in (text or "").splitlines():
        m = re.match(r"^CASCADE_([A-Z]+)=(.*)$", line.strip())
        if m:
            out[m.group(1).lower()] = m.group(2).strip()
    return out


def _ip_or_empty(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return ""


def check_result(kv: dict[str, str]) -> dict[str, str]:
    """Адреса из вывода проверки: мусор вместо адреса (страница ошибки) - пусто."""
    return {"egress": _ip_or_empty(kv.get("egress", "")), "ru": _ip_or_empty(kv.get("ru", ""))}


def build_remove_entry() -> str:
    units = "acontrol-cascade-tproxy.service acontrol-cascade-geo.timer acontrol-gre.service"
    return "\n".join([
        f"sudo systemctl disable --now {units} >/dev/null 2>&1",
        f"sudo docker rm -f {GATEWAY} >/dev/null 2>&1",
        _remove_common(),
    ]) + "\n"


def build_remove_exit() -> str:
    return "\n".join([
        "sudo systemctl disable --now acontrol-gre.service >/dev/null 2>&1",
        f"sudo docker rm -f {EXIT_CONTAINER} >/dev/null 2>&1",
        f"sudo rm -rf {EXIT_DIR}",
        _remove_common(),
    ]) + "\n"


def _remove_common() -> str:
    # правила ufw по адресу соседа снимает панель отдельно (адрес известен ей)
    files = " ".join(f"/etc/systemd/system/{u}" for u in _UNITS)
    return (
        f"sudo rm -rf {DIR} {GRE_DEFAULTS} {files}\n"
        "sudo systemctl daemon-reload\n"
        "echo CASCADE_REMOVED=yes"
    )


def ufw_cleanup(peer_ip: str, port: int | None) -> str:
    if not peer_ip:
        return "true\n"
    cmds = [f"sudo ufw delete allow proto gre from {peer_ip}"]
    if port:
        cmds.append(f"sudo ufw delete allow from {peer_ip} to any port {int(port)} proto tcp")
    cmds.append(f"sudo ufw route delete allow in on {GRE_IF} out on $(ip -4 route get 1.1.1.1 | {_DEV_OF} | head -1)")
    body = "; ".join(f"{c} >/dev/null 2>&1" for c in cmds)
    return f"if command -v ufw >/dev/null 2>&1; then {body}; fi; true\n"


# --- проверка канала ---------------------------------------------------------

_RECV_PY = r"""
import json, socket, sys, time
bind, port, wait = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((bind, port))
s.listen(1)
s.settimeout(wait)
try:
    c, _ = s.accept()
except OSError:
    print(json.dumps({"bytes": 0, "secs": 0, "connected": False}))
    sys.exit()
c.settimeout(6)
t0 = time.time()
n = 0
while time.time() - t0 < wait:
    try:
        d = c.recv(262144)
    except OSError:
        break
    if not d:
        break
    n += len(d)
print(json.dumps({"bytes": n, "secs": round(time.time() - t0, 2), "connected": True}))
"""

_SEND_PY = r"""
import json, socket, sys, time
host, port, total, wait = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), float(sys.argv[4])
t0 = time.time()
s = None
while time.time() - t0 < 10:
    try:
        s = socket.create_connection((host, port), timeout=5)
        break
    except OSError as e:
        err = str(e)
        time.sleep(0.5)
if s is None:
    print(json.dumps({"sent": 0, "error": err}))
    sys.exit()
s.settimeout(wait)
buf = b"\0" * 65536
sent = 0
t1 = time.time()
try:
    while sent < total and time.time() - t1 < wait:
        sent += s.send(buf)
except OSError as e:
    print(json.dumps({"sent": sent, "error": str(e)}))
    sys.exit()
s.close()
print(json.dumps({"sent": sent, "error": ""}))
"""


def _json_line(text: str) -> dict:
    for line in reversed((text or "").strip().splitlines()):
        try:
            v = json.loads(line)
        except ValueError:
            continue
        if isinstance(v, dict):
            return v
    return {}


def probe_verdict(recv: dict, send: dict) -> dict:
    n = int(recv.get("bytes") or 0)
    secs = float(recv.get("secs") or 0)
    ok = n >= PROBE_OK_BYTES
    mbps = round(n * 8 / secs / 1e6) if ok and secs > 0 else 0
    error = ""
    if not recv.get("connected"):
        error = send.get("error") or "не подключилось"
    return {"ok": ok, "bytes": n, "secs": secs, "mbps": mbps, "error": error}


async def _has_python(conn: asyncssh.SSHClientConnection) -> bool:
    r = await conn.run("command -v python3", check=False)
    return r.exit_status == 0


async def _pair(
    exit_conn, entry_conn, bind: str, target: str, port: int
) -> dict:
    wait = PROBE_SECONDS
    recv_task = exit_conn.run(
        f"python3 - {bind} {port} {wait}", input=_RECV_PY, check=False, timeout=wait * 3,
    )
    send_task = entry_conn.run(
        f"python3 - {target} {port} {PROBE_BYTES} {wait}", input=_SEND_PY, check=False,
        timeout=wait * 3,
    )
    recv_r, send_r = await asyncio.gather(recv_task, send_task, return_exceptions=True)
    recv = _json_line(recv_r.stdout) if not isinstance(recv_r, BaseException) else {}
    send = _json_line(send_r.stdout) if not isinstance(send_r, BaseException) else {}
    return probe_verdict(recv, send)


async def probe_tcp(exit_conn, entry_conn, entry_ip: str, exit_ip: str) -> dict:
    port = random.randint(40000, 49999)
    allow = f"INPUT -p tcp -s {entry_ip} --dport {port} -j ACCEPT"
    await exit_conn.run(f"sudo iptables -I {allow}", check=False)
    try:
        return await _pair(exit_conn, entry_conn, "0.0.0.0", exit_ip, port)
    finally:
        await exit_conn.run(f"sudo iptables -D {allow}", check=False)


async def _tmp_gre(conn, peer: str, inner: str) -> list[str]:
    """Временный туннель для проверки; возвращает команды уборки."""
    rules = [f"INPUT -p gre -s {peer} -j ACCEPT", f"INPUT -i {PROBE_GRE_IF} -j ACCEPT"]
    script = "\n".join([
        f"LOCAL=$(ip -4 route get {peer} | {_SRC_OF} | head -1)",
        "sudo modprobe ip_gre 2>/dev/null",
        f"sudo ip link del {PROBE_GRE_IF} 2>/dev/null",
        f'sudo ip tunnel add {PROBE_GRE_IF} mode gre local "$LOCAL" remote {peer} ttl 64',
        f"sudo ip addr add {inner} dev {PROBE_GRE_IF}",
        f"sudo ip link set {PROBE_GRE_IF} mtu 1476 up",
        f"sudo sysctl -qw net.ipv4.conf.{PROBE_GRE_IF}.rp_filter=2",
        *[f"sudo iptables -I {r}" for r in rules],
    ])
    await conn.run(script, check=False)
    return [f"sudo iptables -D {r}" for r in rules] + [f"sudo ip link del {PROBE_GRE_IF}"]


async def probe_gre(exit_conn, entry_conn, entry_ip: str, exit_ip: str) -> dict:
    port = random.randint(40000, 49999)
    undo_exit = await _tmp_gre(exit_conn, entry_ip, "10.98.255.2/30")
    undo_entry = await _tmp_gre(entry_conn, exit_ip, "10.98.255.1/30")
    try:
        return await _pair(exit_conn, entry_conn, "10.98.255.2", "10.98.255.2", port)
    finally:
        await exit_conn.run("; ".join(undo_exit) + "; true", check=False)
        await entry_conn.run("; ".join(undo_entry) + "; true", check=False)


def recommend(tcp: dict, gre: dict) -> str:
    if tcp.get("ok"):
        return "vless"
    if gre.get("ok"):
        return "gre"
    return ""


async def public_ip(conn: asyncssh.SSHClientConnection) -> str:
    """Внешний адрес ноды, с которого она ходит наружу (за NAT это не адрес интерфейса)."""
    r = await conn.run(
        "curl -4 -fsS -m 8 https://api.ipify.org 2>/dev/null "
        "|| wget -qO- -T 8 https://api.ipify.org 2>/dev/null",
        check=False,
    )
    return _ip_or_empty(r.stdout if isinstance(r.stdout, str) else "")


def _is_public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def pick_source(route_src: str, exit_ip: str, nat_ip: str) -> str:
    """С какого адреса выход видит вход. Обычно это адрес интерфейса, с которого
    вход ходит к выходу. Если он внутренний, а выход в интернете, вход за NAT и
    выход увидит внешний адрес; если оба в одной внутренней сети - внутренний."""
    if route_src and (_is_public(route_src) or not _is_public(exit_ip)):
        return route_src
    return nat_ip or route_src


async def entry_source_ip(conn: asyncssh.SSHClientConnection, exit_ip: str) -> str:
    r = await conn.run(f"ip -4 route get {exit_ip} | {_SRC_OF} | head -1", check=False)
    src = _ip_or_empty(r.stdout if isinstance(r.stdout, str) else "")
    nat = "" if src and (_is_public(src) or not _is_public(exit_ip)) else await public_ip(conn)
    return pick_source(src, exit_ip, nat)


async def probe(exit_conn, entry_conn, entry_ip: str, exit_ip: str) -> dict:
    if not (await _has_python(exit_conn) and await _has_python(entry_conn)):
        missing = {"ok": False, "bytes": 0, "secs": 0, "mbps": 0,
                   "error": "на сервере нет python3, проверить нечем"}
        return {"tcp": missing, "gre": missing, "recommend": ""}
    tcp = await probe_tcp(exit_conn, entry_conn, entry_ip, exit_ip)
    gre = await probe_gre(exit_conn, entry_conn, entry_ip, exit_ip)
    return {"tcp": tcp, "gre": gre, "recommend": recommend(tcp, gre)}
