"""Чтение OpenVPN(+Cloak) с ноды: список клиентов из clientsTable.

Модель Amnezia: контейнер amnezia-openvpn-cloak, easy-rsa PKI в
/opt/amnezia/openvpn/pki, клиенты — сертификаты (clientId = CN), имена в
/opt/amnezia/openvpn/clientsTable. Выдача/отзыв (PKI + Cloak) — отдельно.
"""

import base64
import json
import secrets
import shlex
import string
import struct
import zlib
from dataclasses import dataclass

import asyncssh
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

OVPN_DIR = "/opt/amnezia/openvpn"
CLOAK_DIR = "/opt/amnezia/cloak"
SS_DIR = "/opt/amnezia/shadowsocks"
PKI = f"{OVPN_DIR}/pki"
EASYRSA = "/usr/share/easy-rsa"
CONTAINER_NAME = "amnezia-openvpn-cloak"
_DOCKER = 'DOCKER=$(docker info >/dev/null 2>&1 && echo docker || echo "sudo -n docker"); '

# Шаблон .ovpn (формат «Для приложения AmneziaVPN»): DNS шаблонизирован,
# remote — на локальный Cloak-клиент (127.0.0.1:1194), сертификаты встроены.
OVPN_TEMPLATE = """client
dev tun
proto tcp
resolv-retry infinite
nobind
persist-key
persist-tun

cipher AES-256-GCM
auth SHA512
verb 3
tls-client
tls-version-min 1.2
key-direction 1
remote-cert-tls server
redirect-gateway def1 bypass-dhcp

dhcp-option DNS $PRIMARY_DNS
dhcp-option DNS $SECONDARY_DNS
block-outside-dns

route {host} 255.255.255.255 net_gateway
remote 127.0.0.1 1194



<ca>
{ca}

</ca>
<cert>
{cert}

</cert>
<key>
{key}

</key>
<tls-auth>
{ta}

</tls-auth>
"""


def _new_client_id() -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(32))


class OpenVpnError(Exception):
    pass


@dataclass
class OvpnClient:
    client_id: str
    name: str
    creation_date: str


async def _run(conn: asyncssh.SSHClientConnection, cmd: str) -> str:
    result = await conn.run(cmd, check=False)
    if result.exit_status != 0:
        err = (result.stderr or "").strip() or (result.stdout or "").strip()
        raise OpenVpnError(err or f"код {result.exit_status}")
    return result.stdout or ""


def _docker_exec(container: str, inner: str) -> str:
    return _DOCKER + f"$DOCKER exec {shlex.quote(container)} sh -c {shlex.quote(inner)}"


async def detect_container(conn: asyncssh.SSHClientConnection) -> str:
    cmd = _DOCKER + "$DOCKER ps --format '{{.Names}}' | grep -m1 amnezia-openvpn"
    out = (await _run(conn, cmd)).strip()
    if not out:
        raise OpenVpnError("Контейнер amnezia-openvpn на сервере не найден")
    return out.splitlines()[0].strip()


def parse_clients(text: str) -> list[OvpnClient]:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return []
    clients = []
    for entry in data:
        ud = entry.get("userData", {})
        clients.append(
            OvpnClient(
                client_id=entry.get("clientId", ""),
                name=ud.get("clientName", "—") or "—",
                creation_date=ud.get("creationDate", ""),
            )
        )
    return clients


async def read_clients(conn: asyncssh.SSHClientConnection) -> list[OvpnClient]:
    container = await detect_container(conn)
    text = await _run(conn, _docker_exec(container, f"cat {OVPN_DIR}/clientsTable"))
    return parse_clients(text)


def _docker_exec_i(container: str, inner: str) -> str:
    return _DOCKER + f"$DOCKER exec -i {shlex.quote(container)} sh -c {shlex.quote(inner)}"


async def _read_table(conn, container) -> list:
    text = await _run(conn, _docker_exec(container, f"cat {OVPN_DIR}/clientsTable"))
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return []


async def _write_table(conn, container, data: list) -> None:
    payload = json.dumps(data, indent=4, ensure_ascii=False) + "\n"
    await conn.run(
        _docker_exec_i(container, f"cat > {OVPN_DIR}/clientsTable"),
        input=payload, check=False,
    )


def _section(bundle: str, name: str) -> str:
    marker = f"==={name}==="
    start = bundle.find(marker)
    if start == -1:
        return ""
    rest = bundle[start + len(marker):]
    nxt = rest.find("\n===")
    return (rest[:nxt] if nxt != -1 else rest).strip("\n")


def _gen_key_csr(cid: str) -> tuple[str, str]:
    """Генерит на панели клиентскую пару RSA-2048 + CSR (CN=clientId).

    Как в Amnezia: приватный ключ создаётся на стороне клиента (у нас — панели)
    и на ноду не попадает; на ноду уходит только CSR для подписи.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cid)]))
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode().strip()
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
    return key_pem, csr_pem


async def _sign_csr(
    conn: asyncssh.SSHClientConnection, container: str, cid: str, csr_pem: str
) -> str:
    """Импортирует CSR на ноду и подписывает его CA (easy-rsa), возвращает cert."""
    csr_b64 = base64.b64encode(csr_pem.encode()).decode()
    pki_env = f"EASYRSA_PKI={PKI} EASYRSA_BATCH=1"
    inner = (
        f"echo {csr_b64} | base64 -d > /tmp/{cid}.req && "
        f"cd {EASYRSA} && "
        f"{pki_env} ./easyrsa import-req /tmp/{cid}.req {cid} >/dev/null 2>&1 && "
        f"{pki_env} ./easyrsa sign-req client {cid} >/dev/null 2>&1; "
        f"rm -f /tmp/{cid}.req; "
        f"test -f {PKI}/issued/{cid}.crt && echo SIGNED_OK && cat {PKI}/issued/{cid}.crt"
    )
    out = await _run(conn, _docker_exec_i(container, inner))
    if "SIGNED_OK" not in out:
        raise OpenVpnError("не удалось подписать сертификат easy-rsa")
    return out.split("SIGNED_OK\n", 1)[1]


async def read_server_bits(
    conn: asyncssh.SSHClientConnection, container: str
) -> dict:
    """Читает статичные per-server данные (CA/TA/Cloak/Shadowsocks/порт)."""
    port_out = await _run(
        conn, _DOCKER + f"$DOCKER port {shlex.quote(container)} 443/tcp 2>/dev/null | head -1"
    )
    cloak_port = port_out.strip().rsplit(":", 1)[-1].strip() or "8080"
    inner = (
        f"echo ===CA===; cat {OVPN_DIR}/ca.crt; "
        f"echo ===TA===; cat {OVPN_DIR}/ta.key; "
        f"echo ===CKPUB===; cat {CLOAK_DIR}/cloak_public.key; "
        f"echo ===CKUID===; cat {CLOAK_DIR}/cloak_bypass_uid.key; "
        f"echo ===CKCFG===; cat {CLOAK_DIR}/ck-config.json; "
        f"echo ===SSCFG===; cat {SS_DIR}/ss-config.json 2>/dev/null; echo ===END==="
    )
    bundle = await _run(conn, _docker_exec(container, inner))
    try:
        ck = json.loads(_section(bundle, "CKCFG"))
    except (json.JSONDecodeError, ValueError):
        ck = {}
    try:
        ss = json.loads(_section(bundle, "SSCFG"))
    except (json.JSONDecodeError, ValueError):
        ss = {}
    return {
        "ca": _section(bundle, "CA"),
        "ta": _section(bundle, "TA"),
        "cloak_pub": _section(bundle, "CKPUB").strip(),
        "cloak_uid": _section(bundle, "CKUID").strip(),
        "redir": ck.get("RedirAddr", "tile.openstreetmap.org"),
        "cloak_port": cloak_port,
        "ss_method": ss.get("method", "chacha20-ietf-poly1305"),
        "ss_password": ss.get("password", ""),
        "ss_server_port": str(ss.get("server_port", "6789")),
    }


async def issue_client(
    conn: asyncssh.SSHClientConnection,
    container: str,
    name: str,
    host: str,
    description: str,
    dns1: str,
    dns2: str,
) -> tuple[OvpnClient, str]:
    """Выдаёт клиента и возвращает (клиент, vpn://).

    Пара ключей генерится на панели, CSR подписывается CA на ноде, приватный
    ключ вшивается только в возвращаемый конфиг (на ноде его нет).
    """
    cid = _new_client_id()
    key_pem, csr_pem = _gen_key_csr(cid)
    cert = await _sign_csr(conn, container, cid, csr_pem)
    bits = await read_server_bits(conn, container)
    link = assemble_ovpn_link(
        host=host, description=description, dns1=dns1, dns2=dns2,
        client_id=cid, ca=bits["ca"], cert=cert, key=key_pem, ta=bits["ta"],
        cloak_pub=bits["cloak_pub"], cloak_uid=bits["cloak_uid"],
        redir=bits["redir"], cloak_port=bits["cloak_port"],
        ss_method=bits["ss_method"], ss_password=bits["ss_password"],
        ss_server_port=bits["ss_server_port"],
    )
    date = (await _run(conn, 'date "+%a %b %e %H:%M:%S %Y"')).strip()
    data = await _read_table(conn, container)
    data.append(
        {"clientId": cid, "userData": {"clientName": name, "creationDate": date}}
    )
    await _write_table(conn, container, data)
    return OvpnClient(client_id=cid, name=name, creation_date=date), link


async def reissue_client(
    conn: asyncssh.SSHClientConnection,
    container: str,
    old_client_id: str,
    name: str,
    host: str,
    description: str,
    dns1: str,
    dns2: str,
) -> tuple[OvpnClient, str]:
    """Перевыпуск: отзыв старого сертификата + выдача нового (новый clientId)."""
    await revoke_client(conn, container, old_client_id)
    return await issue_client(conn, container, name, host, description, dns1, dns2)


async def revoke_client(
    conn: asyncssh.SSHClientConnection, container: str, client_id: str
) -> None:
    """Отзывает клиента: easy-rsa revoke + gen-crl + CRL + чистка файлов + table."""
    if not client_id or "/" in client_id or ".." in client_id:
        raise OpenVpnError("некорректный clientId")
    cid = shlex.quote(client_id)
    pki_env = f"EASYRSA_PKI={PKI} EASYRSA_BATCH=1"
    inner = (
        f"cd {EASYRSA} && "
        f"{pki_env} ./easyrsa revoke {cid} >/dev/null 2>&1; "
        f"{pki_env} ./easyrsa gen-crl >/dev/null 2>&1 && "
        f"cp {PKI}/crl.pem {OVPN_DIR}/crl.pem && "
        f"rm -f {PKI}/issued/{cid}.crt {PKI}/reqs/{cid}.req "
        f"{OVPN_DIR}/clients/{cid}.req && echo REVOKED_OK"
    )
    out = await _run(conn, _docker_exec(container, inner))
    if "REVOKED_OK" not in out:
        raise OpenVpnError("не удалось отозвать сертификат / обновить CRL")

    data = await _read_table(conn, container)
    data = [e for e in data if e.get("clientId") != client_id]
    await _write_table(conn, container, data)


# --- Разворачивание OpenVPN/Cloak на чистой ноде (build-on-target) ------------

# Свой Alpine-образ: openvpn + easy-rsa + shadowsocks-rust(ssserver) + ck-server
# (Cloak). ifconfig — из net-tools, killall — из psmisc.
_OVPN_DOCKERFILE = """FROM alpine:3.20
LABEL maintainer="AmneziaVPN"
RUN apk add --no-cache openvpn easy-rsa iptables ip6tables net-tools psmisc \\
  dumb-init shadowsocks-rust openssl bash curl ca-certificates
RUN curl -fsSL -o /usr/local/bin/ck-server \\
  https://github.com/cbeuw/Cloak/releases/download/v2.12.0/ck-server-linux-amd64-v2.12.0 \\
  && chmod +x /usr/local/bin/ck-server
ENTRYPOINT ["dumb-init","/opt/amnezia/start.sh"]
"""

# Скрипт генерации PKI + Cloak-ключей + shadowsocks; запускается ВНУТРИ образа
# (одноразовый контейнер с монтированием /opt/amnezia). RedirAddr берётся из
# $AMNEZIA_SITE. Идемпотентность обеспечивает вызывающий (проверка ca.crt).
_OVPN_GEN = """#!/bin/sh
set -e
O=/opt/amnezia/openvpn
K=/opt/amnezia/cloak
S=/opt/amnezia/shadowsocks
mkdir -p "$O" "$K" "$S"

export EASYRSA_PKI="$O/pki" EASYRSA_BATCH=1
cd /usr/share/easy-rsa
./easyrsa init-pki
EASYRSA_REQ_CN=AmneziaVPN ./easyrsa build-ca nopass
./easyrsa build-server-full AmneziaReq nopass
./easyrsa gen-dh
./easyrsa gen-crl
cp "$EASYRSA_PKI/ca.crt" "$O/ca.crt"
cp "$EASYRSA_PKI/issued/AmneziaReq.crt" "$O/AmneziaReq.crt"
cp "$EASYRSA_PKI/private/AmneziaReq.key" "$O/AmneziaReq.key"
cp "$EASYRSA_PKI/dh.pem" "$O/dh.pem"
cp "$EASYRSA_PKI/crl.pem" "$O/crl.pem"
openvpn --genkey --secret "$O/ta.key"
printf '[]\\n' > "$O/clientsTable"

cat > "$O/server.conf" <<'EOF'
port 1194
proto tcp
dev tun
ca /opt/amnezia/openvpn/ca.crt
cert /opt/amnezia/openvpn/AmneziaReq.crt
key /opt/amnezia/openvpn/AmneziaReq.key
dh /opt/amnezia/openvpn/dh.pem
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
duplicate-cn
keepalive 10 120
cipher AES-256-GCM
data-ciphers AES-256-GCM
auth SHA512
user nobody
group nobody
persist-key
persist-tun
crl-verify /opt/amnezia/openvpn/crl.pem
status openvpn-status.log
verb 1
tls-server
tls-version-min 1.2
tls-auth /opt/amnezia/openvpn/ta.key 0
EOF

KP=$(ck-server -k)
PUB=$(printf '%s' "$KP" | cut -d, -f1 | tr -d ' \\r\\n')
PRIV=$(printf '%s' "$KP" | cut -d, -f2 | tr -d ' \\r\\n')
AUID=$(ck-server -u | tr -d ' \\r\\n')
BUID=$(ck-server -u | tr -d ' \\r\\n')
printf '%s\\n' "$PUB"  > "$K/cloak_public.key"
printf '%s\\n' "$PRIV" > "$K/cloak_private.key"
printf '%s\\n' "$AUID" > "$K/cloak_admin_uid.key"
printf '%s\\n' "$BUID" > "$K/cloak_bypass_uid.key"
SITE="${AMNEZIA_SITE:-tile.openstreetmap.org}"
cat > "$K/ck-config.json" <<EOF
{
    "ProxyBook": { "openvpn": ["tcp", "localhost:1194"], "shadowsocks": ["tcp", "localhost:6789"] },
    "BypassUID": ["$BUID"],
    "BindAddr": [":443"],
    "RedirAddr": "$SITE",
    "PrivateKey": "$PRIV",
    "AdminUID": "$AUID",
    "DatabasePath": "userinfo.db",
    "StreamTimeout": 300
}
EOF

SSPW=$(openssl rand -base64 32 | tr -d '\\r\\n')
printf '%s\\n' "$SSPW" > "$S/shadowsocks.key"
cat > "$S/ss-config.json" <<EOF
{
    "local_port": 8585,
    "method": "chacha20-ietf-poly1305",
    "password": "$SSPW",
    "server": "0.0.0.0",
    "server_port": 6789,
    "timeout": 60
}
EOF
echo GEN_OK
"""


def _b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def build_deploy_script(port: int, site: str, server_ip: str = "") -> str:
    """Скрипт build-on-target для OpenVPN/Cloak: собирает образ, генерит PKI +
    Cloak + shadowsocks, поднимает контейнер. Запускается от ssh_user через sudo,
    файлы в /opt пишутся через `base64 -d | sudo tee`. Маркеры DEPLOY_DONE /
    DEPLOY_ERROR (их читает deploy.read_status).

    server_ip — публичный IP ноды для `ifconfig eth0:0` внутри контейнера; если
    пусто или это хостнейм, определяется на ноде (`ip route get`).
    """
    port = int(port)
    if not site or any(ch in site for ch in " \t\n'\"$`\\;&|<>()"):
        site = "tile.openstreetmap.org"
    if any(ch in server_ip for ch in " \t\n'\"$`\\;&|<>()"):
        server_ip = ""
    df_b64 = _b64(_OVPN_DOCKERFILE)
    gen_b64 = _b64(_OVPN_GEN)
    lines = [
        "set +e",
        'fail(){ echo "DEPLOY_ERROR: $1"; exit 1; }',
        'log(){ echo "[$(date +%H:%M:%S)] $*"; }',
        f"PORT={port}",
        f"SITE={site}",
        f"SRVIP={server_ip}",
        # если IP не задан или это хостнейм — определяем основной IP ноды
        "case \"$SRVIP\" in \"\"|*[!0-9.]*) "
        "SRVIP=$(ip route get 1.1.1.1 2>/dev/null | sed -n 's/.*src \\([0-9.]*\\).*/\\1/p' | head -1) ;; esac",
        "IMG=amnezia-openvpn-cloak",
        "C=amnezia-openvpn-cloak",
        "BUILD=/opt/amnezia-build/ovpn",
        "D=/opt/amnezia",
        "",
        'log "[1/6] docker"',
        "command -v docker >/dev/null 2>&1 || "
        '{ curl -fsSL https://get.docker.com | sudo sh >/dev/null || fail "docker install"; }',
        "",
        'log "[2/6] Dockerfile + gen.sh"',
        'sudo mkdir -p "$BUILD" "$D" || fail mkdir',
        f'echo {df_b64} | base64 -d | sudo tee "$BUILD/Dockerfile" >/dev/null || fail dockerfile',
        f'echo {gen_b64} | base64 -d | sudo tee "$BUILD/gen.sh" >/dev/null || fail genwrite',
        "",
        'log "[3/6] docker build"',
        # `| tail` маскирует код build → проверяем PIPESTATUS, иначе битая сборка
        # прошла бы к rm+run (снос рабочего контейнера ради несобравшегося образа)
        'sudo docker build -t "$IMG" "$BUILD" 2>&1 | tail -3',
        '[ ${PIPESTATUS[0]} -eq 0 ] || fail build',
        "",
        'log "[4/6] конфиг (PKI + Cloak + shadowsocks)"',
        # КРИТИЧНО: вытащить PKI/конфиг из ЖИВОГО контейнера на хост ДО guard.
        # У родного Amnezia-openvpn конфиг лежит ВНУТРИ контейнера (не на хост-
        # маунте) — иначе guard ниже сгенерил бы НОВЫЙ CA и все клиентские
        # сертификаты стали бы невалидны (тот же класс, что инцидент de-hz).
        'SRC=$(sudo docker ps --format "{{.Names}}" | grep -iE "openvpn|cloak" | head -1 || true)',
        'if [ -n "$SRC" ]; then',
        '  if ! sudo test -f "$D/openvpn/ca.crt"; then',
        '    sudo docker exec "$SRC" tar -czf - -C / opt/amnezia/openvpn '
        'opt/amnezia/cloak opt/amnezia/shadowsocks 2>/dev/null '
        '| sudo tar -xzf - -C / 2>/dev/null '
        '&& log "конфиг перечитан из контейнера $SRC" || true;',
        '  fi',
        # порт клиента может отличаться от переданного — берём опубликованный порт
        # живого контейнера, иначе у клиентов (endpoint зашит) отвалится коннект
        '  DPORT=$(sudo docker inspect "$SRC" --format '
        '"{{range \\$p,\\$c := .NetworkSettings.Ports}}{{range \\$c}}{{.HostPort}} {{end}}{{end}}" '
        '2>/dev/null | grep -o "[0-9]*" | head -1 || true); [ -n "$DPORT" ] && PORT=$DPORT;',
        '  log "порт контейнера: $PORT"',
        'fi',
        'if ! sudo test -f "$D/openvpn/ca.crt"; then',
        '  log "генерация нового конфига (новый сервер)"',
        '  sudo docker run --rm -e AMNEZIA_SITE="$SITE" -v "$D":/opt/amnezia '
        '-v "$BUILD/gen.sh":/gen.sh --entrypoint sh "$IMG" /gen.sh 2>&1 | tail -4',
        '  sudo test -f "$D/openvpn/ca.crt" || fail gen',
        "else",
        '  log "конфиг уже есть — сохранён, клиенты не тронуты"',
        "fi",
        "",
        'log "[5/6] start.sh + фаервол"',
        'sudo tee "$D/start.sh" >/dev/null <<EOF',
        "#!/bin/bash",
        'echo "Container startup"',
        "ifconfig eth0:0 $SRVIP netmask 255.255.255.255 up",
        "if [ ! -c /dev/net/tun ]; then mkdir -p /dev/net; mknod /dev/net/tun c 10 200; fi",
        "iptables -A INPUT -i tun0 -j ACCEPT",
        "iptables -A FORWARD -i tun0 -j ACCEPT",
        "iptables -A OUTPUT -o tun0 -j ACCEPT",
        "iptables -A FORWARD -i tun0 -o eth0 -s 10.8.0.0/24 -j ACCEPT",
        "iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT",
        "iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE",
        "killall -KILL openvpn 2>/dev/null",
        "killall -KILL ck-server 2>/dev/null",
        "killall -KILL ssserver 2>/dev/null",
        "if [ -f /opt/amnezia/openvpn/ca.crt ]; then "
        "(openvpn --config /opt/amnezia/openvpn/server.conf --daemon); fi",
        "if [ -f /opt/amnezia/shadowsocks/ss-config.json ]; then "
        "(ssserver -c /opt/amnezia/shadowsocks/ss-config.json &); fi",
        "if [ -f /opt/amnezia/cloak/ck-config.json ]; then "
        "(ck-server -c /opt/amnezia/cloak/ck-config.json &); fi",
        "tail -f /dev/null",
        "EOF",
        'sudo chmod +x "$D/start.sh"',
        # Cloak слушает TCP → открываем PORT/tcp наружу (Docker публикует, но
        # ufw/firewalld могут блокировать)
        'if command -v ufw >/dev/null 2>&1; then sudo ufw allow "$PORT"/tcp >/dev/null 2>&1 || true; '
        'sudo ufw route allow proto tcp from any to any port "$PORT" >/dev/null 2>&1 || true; fi',
        'if command -v firewall-cmd >/dev/null 2>&1; then '
        'sudo firewall-cmd --permanent --add-port="$PORT"/tcp >/dev/null 2>&1 && '
        'sudo firewall-cmd --reload >/dev/null 2>&1 || true; fi',
        "",
        'log "[6/6] контейнер"',
        # сносим ЛЮБОЙ openvpn/cloak-контейнер (включая родной), иначе останется
        # параллельный, а панель поднимет новый на том же порту (конфликт/дубль)
        'OLD=$(sudo docker ps -aq --filter "name=openvpn" --filter "name=cloak" 2>/dev/null | sort -u); '
        '[ -n "$OLD" ] && sudo docker rm -f $OLD >/dev/null 2>&1 || true',
        'sudo docker rm -f "$C" >/dev/null 2>&1 || true',
        'sudo docker run -d --name "$C" --restart always --privileged --cap-add=NET_ADMIN \\',
        '  -p "${PORT}":443/tcp -v "$D":/opt/amnezia "$IMG" >/dev/null || fail run',
        "sleep 6",
        "sudo docker ps --format '{{.Names}}' | grep -Fx \"$C\" >/dev/null || "
        '{ sudo docker logs "$C" 2>&1 | tail -20; fail notrunning; }',
        'log "openvpn-cloak запущен, Cloak на хост-порту $PORT"',
        "echo DEPLOY_DONE",
    ]
    return "\n".join(lines) + "\n"


def assemble_ovpn_link(
    *, host, description, dns1, dns2, client_id, ca, cert, key, ta,
    cloak_pub, cloak_uid, redir, cloak_port, ss_method, ss_password, ss_server_port,
) -> str:
    """Чистая сборка vpn:// из готовых материалов (тестируется без SSH)."""
    ovpn_config = OVPN_TEMPLATE.format(
        host=host, ca=ca.strip(), cert=cert.strip(), key=key.strip(), ta=ta.strip()
    )

    def dump(obj: dict) -> str:
        return json.dumps(obj, indent=4, ensure_ascii=False, sort_keys=True) + "\n"

    container_obj = {
        "cloak": {
            "last_config": dump({
                "BrowserSig": "chrome",
                "EncryptionMethod": "aes-gcm",
                "NumConn": 1,
                "ProxyMethod": "openvpn",
                "PublicKey": cloak_pub,
                "RemoteHost": host,
                "RemotePort": cloak_port,
                "ServerName": redir,
                "StreamTimeout": 300,
                "Transport": "direct",
                "UID": cloak_uid,
            }),
            "port": cloak_port,
            "subnet_address": "10.8.1.0",
            "transport_proto": "tcp",
        },
        "container": "amnezia-openvpn-cloak",
        "openvpn": {"last_config": dump({"clientId": client_id, "config": ovpn_config})},
        "shadowsocks": {"last_config": dump({
            "local_port": "8585",
            "method": ss_method,
            "password": ss_password,
            "server": host,
            "server_port": ss_server_port,
            "timeout": 60,
        })},
    }
    top = {
        "containers": [container_obj],
        "defaultContainer": "amnezia-openvpn-cloak",
        "description": description,
        "dns1": dns1,
        "dns2": dns2,
        "hostName": host,
    }
    payload = json.dumps(top, ensure_ascii=False, sort_keys=True).encode()
    compressed = struct.pack(">I", len(payload)) + zlib.compress(payload)
    return "vpn://" + base64.urlsafe_b64encode(compressed).decode().rstrip("=")
