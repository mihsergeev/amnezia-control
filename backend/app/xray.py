"""Управление XRay (VLESS+REALITY) на ноде.

Модель Amnezia: контейнер amnezia-xray, конфиг /opt/amnezia/xray/server.json
(VLESS inbound на 443, REALITY). Клиенты — UUID'ы в inbounds[0].settings.clients,
имена в /opt/amnezia/xray/clientsTable (массив {clientId, userData}). Дефолтный
UUID (xray_uuid.key) из пользовательского списка исключаётся. Ключи REALITY:
xray_public.key, xray_short_id.key. Выдача/отзыв — правка server.json + docker restart.
"""

import base64
import json
import re
import shlex
import struct
import uuid
import zlib
from dataclasses import dataclass

import asyncssh
import httpx

XRAY_RELEASE = "v26.3.27"  # фолбэк-версия xray-core, если GitHub недоступен
XRAY_DIR = "/opt/amnezia/xray"
SERVER_JSON = f"{XRAY_DIR}/server.json"
CLIENTS_TABLE = f"{XRAY_DIR}/clientsTable"
FLOW = "xtls-rprx-vision"
CONTAINER_NAME = "amnezia-xray"
_DOCKER = 'DOCKER=$(docker info >/dev/null 2>&1 && echo docker || echo "sudo -n docker"); '


class XrayError(Exception):
    pass


@dataclass
class XrayClient:
    client_id: str  # UUID
    name: str
    creation_date: str


async def _run(conn: asyncssh.SSHClientConnection, cmd: str) -> str:
    result = await conn.run(cmd, check=False)
    if result.exit_status != 0:
        err = (result.stderr or "").strip() or (result.stdout or "").strip()
        raise XrayError(err or f"код {result.exit_status}")
    return result.stdout or ""


def _docker_exec(container: str, inner: str) -> str:
    return _DOCKER + f"$DOCKER exec {shlex.quote(container)} sh -c {shlex.quote(inner)}"


def _docker_exec_i(container: str, inner: str) -> str:
    return _DOCKER + f"$DOCKER exec -i {shlex.quote(container)} sh -c {shlex.quote(inner)}"


async def detect_container(conn: asyncssh.SSHClientConnection) -> str:
    cmd = _DOCKER + "$DOCKER ps --format '{{.Names}}' | grep -m1 amnezia-xray"
    out = (await _run(conn, cmd)).strip()
    if not out:
        raise XrayError("Контейнер amnezia-xray на сервере не найден")
    return out.splitlines()[0].strip()


async def _read_server(conn, container) -> dict:
    text = await _run(conn, _docker_exec(container, f"cat {SERVER_JSON}"))
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError) as exc:
        raise XrayError("не удалось прочитать server.json") from exc


async def _write_server(conn, container, data: dict) -> None:
    payload = json.dumps(data, indent=4, ensure_ascii=False) + "\n"
    await conn.run(
        _docker_exec_i(container, f"cat > {SERVER_JSON}"), input=payload, check=False
    )


async def _read_table(conn, container) -> list:
    text = await _run(conn, _docker_exec(container, f"cat {CLIENTS_TABLE} 2>/dev/null"))
    try:
        data = json.loads(text)
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, ValueError):
        return []


async def _write_table(conn, container, data: list) -> None:
    payload = json.dumps(data, indent=4, ensure_ascii=False) + "\n"
    await conn.run(
        _docker_exec_i(container, f"cat > {CLIENTS_TABLE}"), input=payload, check=False
    )


async def _default_uuid(conn, container) -> str:
    out = await _run(
        conn, _docker_exec(container, f"cat {XRAY_DIR}/xray_uuid.key 2>/dev/null")
    )
    return out.strip()


def _client_list(server: dict) -> list:
    try:
        return server["inbounds"][0]["settings"]["clients"]
    except (KeyError, IndexError, TypeError):
        return []


async def read_clients(conn: asyncssh.SSHClientConnection) -> list[XrayClient]:
    container = await detect_container(conn)
    server = await _read_server(conn, container)
    default = await _default_uuid(conn, container)
    table = await _read_table(conn, container)
    names = {
        e.get("clientId"): e.get("userData", {})
        for e in table
        if isinstance(e, dict)
    }
    clients: list[XrayClient] = []
    for c in _client_list(server):
        uid = c.get("id") if isinstance(c, dict) else None
        if not uid or uid == default:
            continue
        ud = names.get(uid, {})
        clients.append(
            XrayClient(
                client_id=uid,
                name=ud.get("clientName", "—") or "—",
                creation_date=ud.get("creationDate", ""),
            )
        )
    return clients


async def read_server_bits(conn, container) -> dict:
    """REALITY-параметры сервера для сборки клиентского конфига."""
    inner = (
        f"echo ===PUB===; cat {XRAY_DIR}/xray_public.key 2>/dev/null; "
        f"echo ===SID===; cat {XRAY_DIR}/xray_short_id.key 2>/dev/null; echo ===END==="
    )
    bundle = await _run(conn, _docker_exec(container, inner))

    def _sec(name):
        m = f"==={name}==="
        s = bundle.find(m)
        if s == -1:
            return ""
        rest = bundle[s + len(m):]
        nxt = rest.find("\n===")
        return (rest[:nxt] if nxt != -1 else rest).strip("\n").strip()

    server = await _read_server(conn, container)
    inbound = (server.get("inbounds") or [{}])[0]
    port = inbound.get("port", 443)
    reality = (inbound.get("streamSettings") or {}).get("realitySettings", {})
    names = reality.get("serverNames") or ["www.googletagmanager.com"]
    site = names[0] if names else "www.googletagmanager.com"
    clients = _client_list(server)
    flow = clients[0].get("flow", FLOW) if clients else FLOW
    return {
        "pub": _sec("PUB"),
        "short": _sec("SID"),
        "site": site,
        "port": int(port) if str(port).isdigit() else 443,
        "flow": flow or FLOW,
    }


async def node_version(conn, container) -> str | None:
    """Версия xray-core в контейнере (напр. '25.8.3')."""
    out = await _run(
        conn, _docker_exec(container, "xray version 2>/dev/null | head -1")
    )
    m = re.search(r"[Xx]ray\s+v?(\d+\.\d+\.\d+)", out)
    return m.group(1) if m else None


async def latest_release() -> dict:
    """Последний релиз XTLS/Xray-core с GitHub: {version, tag, updated}."""
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(
            "https://api.github.com/repos/XTLS/Xray-core/releases/latest",
            headers={"Accept": "application/vnd.github+json"},
        )
        r.raise_for_status()
        data = r.json()
    tag = data.get("tag_name", "") or ""
    return {
        "version": tag.lstrip("v"),
        "tag": tag,
        "updated": data.get("published_at", "") or "",
    }


def assemble_xray_link(
    *, host, description, dns1, dns2, client_id, port, pub, short, site, flow
) -> str:
    """vpn:// «Для приложения AmneziaVPN» для XRay/REALITY-клиента."""
    users = {"id": client_id, "encryption": "none"}
    if flow:
        users["flow"] = flow
    client = {
        "log": {"loglevel": "error"},
        "inbounds": [
            {"listen": "127.0.0.1", "port": 10808, "protocol": "socks",
             "settings": {"udp": True}}
        ],
        "outbounds": [
            {
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {"address": host, "port": int(port), "users": [users]}
                    ]
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "fingerprint": "chrome",
                        "serverName": site,
                        "publicKey": pub,
                        "shortId": short,
                        "spiderX": "",
                    },
                },
            }
        ],
    }
    last_config = json.dumps(client, separators=(",", ":"), ensure_ascii=False)
    container_obj = {
        "container": "amnezia-xray",
        "xray": {
            "last_config": last_config,
            "port": str(port),
            "transport_proto": "tcp",
        },
    }
    top = {
        "containers": [container_obj],
        "defaultContainer": "amnezia-xray",
        "description": description,
        "dns1": dns1,
        "dns2": dns2,
        "hostName": host,
    }
    payload = json.dumps(top, ensure_ascii=False, sort_keys=True).encode()
    compressed = struct.pack(">I", len(payload)) + zlib.compress(payload)
    return "vpn://" + base64.urlsafe_b64encode(compressed).decode().rstrip("=")


async def _restart(conn, container) -> None:
    await _run(conn, _DOCKER + f"$DOCKER restart {shlex.quote(container)} >/dev/null")
    # проверим, что контейнер поднялся с новым конфигом
    out = await _run(
        conn,
        _DOCKER + f"$DOCKER ps --format '{{{{.Names}}}}' | grep -Fx {shlex.quote(container)} || true",
    )
    if container not in out:
        raise XrayError("контейнер xray не поднялся после рестарта (проверьте server.json)")


async def issue_client(
    conn: asyncssh.SSHClientConnection,
    container: str,
    name: str,
    host: str,
    description: str,
    dns1: str,
    dns2: str,
) -> tuple[XrayClient, str]:
    """Выдаёт клиента: новый UUID → clients[] + clientsTable → restart → vpn://."""
    cid = str(uuid.uuid4())
    server = await _read_server(conn, container)
    _client_list(server).append({"id": cid, "flow": FLOW})
    await _write_server(conn, container, server)

    date = (await _run(conn, 'date "+%a %b %e %H:%M:%S %Y"')).strip()
    table = await _read_table(conn, container)
    table.append(
        {"clientId": cid, "userData": {"clientName": name, "creationDate": date}}
    )
    await _write_table(conn, container, table)

    bits = await read_server_bits(conn, container)
    await _restart(conn, container)

    link = assemble_xray_link(
        host=host, description=description, dns1=dns1, dns2=dns2, client_id=cid,
        port=bits["port"], pub=bits["pub"], short=bits["short"], site=bits["site"],
        flow=bits["flow"],
    )
    return XrayClient(client_id=cid, name=name, creation_date=date), link


async def revoke_client(
    conn: asyncssh.SSHClientConnection, container: str, client_id: str
) -> None:
    """Отзывает клиента: удаляет UUID из clients[] и clientsTable → restart."""
    if not client_id:
        raise XrayError("некорректный clientId")
    server = await _read_server(conn, container)
    try:
        clients = server["inbounds"][0]["settings"]["clients"]
    except (KeyError, IndexError, TypeError) as exc:
        raise XrayError("некорректный server.json") from exc
    server["inbounds"][0]["settings"]["clients"] = [
        c for c in clients if not (isinstance(c, dict) and c.get("id") == client_id)
    ]
    await _write_server(conn, container, server)

    table = await _read_table(conn, container)
    table = [e for e in table if e.get("clientId") != client_id]
    await _write_table(conn, container, table)

    await _restart(conn, container)


_XRAY_DOCKERFILE = """FROM alpine:3.15
LABEL maintainer="AmneziaVPN"
ARG XRAY_RELEASE="v26.3.27"
RUN apk add --no-cache curl unzip bash openssl netcat-openbsd dumb-init rng-tools xz
RUN apk --update upgrade --no-cache
RUN mkdir -p /opt/amnezia/xray
RUN curl -L https://github.com/XTLS/Xray-core/releases/download/${XRAY_RELEASE}/Xray-linux-64.zip > /root/xray.zip; \\
  unzip /root/xray.zip -d /usr/bin/; \\
  chmod a+x /usr/bin/xray;
ENV TZ=Asia/Shanghai
ENTRYPOINT ["dumb-init","tail","-f","/dev/null"]
"""


def build_deploy_script(port: int, site: str, xray_release: str = XRAY_RELEASE) -> str:
    """Скрипт build-on-target: ставит docker, собирает amnezia-xray, конфигурит, запускает.

    Запускается от ssh_user (не root), поэтому все привилегированные операции —
    через sudo, а файлы в /opt пишутся через `base64 -d | sudo tee` (redirect
    выполняется НЕ-root'ом до sudo). Маркеры DEPLOY_DONE / DEPLOY_ERROR.
    xray_release — тег релиза XTLS/Xray-core (для деплоя/обновления ядра).
    """
    if not site or any(ch in site for ch in " \t\n'\"$`\\;&|<>()"):
        site = "www.googletagmanager.com"
    if not re.fullmatch(r"v?\d+\.\d+\.\d+", xray_release or ""):
        xray_release = XRAY_RELEASE
    port = int(port)
    dockerfile_b64 = base64.b64encode(_XRAY_DOCKERFILE.encode()).decode()
    return f"""set +e
fail() {{ echo "DEPLOY_ERROR: $1"; exit 1; }}
log(){{ echo "[$(date +%H:%M:%S)] $*"; }}
XRAY_SERVER_PORT={port}
XRAY_SITE_NAME={site}
IMG=amnezia-xray
C=amnezia-xray
BUILD=/opt/amnezia-build/xray
D=/opt/amnezia/xray

log "[1/5] docker"
command -v docker >/dev/null 2>&1 || {{ curl -fsSL https://get.docker.com | sudo sh >/dev/null || fail "docker install"; }}

log "[2/5] Dockerfile"
sudo mkdir -p "$BUILD" "$D" || fail mkdir
echo {dockerfile_b64} | base64 -d | sudo tee "$BUILD/Dockerfile" >/dev/null || fail dockerfile

log "[3/5] docker build (xray {xray_release})"
sudo docker build --build-arg XRAY_RELEASE={xray_release} -t "$IMG" "$BUILD" 2>&1 | tail -3 || fail build

log "[4/5] конфиг"
# перед пересборкой вытаскиваем конфиг из ЖИВОГО контейнера на хост-маунт
# (конфиг мог лежать ВНУТРИ контейнера) — иначе guard сгенерит пустой и потеряет клиентов
if sudo docker ps --format '{{{{.Names}}}}' | grep -qx "$C"; then
  for f in server.json clientsTable xray_uuid.key xray_public.key xray_private.key xray_short_id.key; do
    B=$(sudo docker exec "$C" cat "/opt/amnezia/xray/$f" 2>/dev/null | base64 -w0 2>/dev/null || true)
    [ -n "$B" ] && echo "$B" | base64 -d | sudo tee "$D/$f" >/dev/null || true
  done
fi
if ! sudo test -f "$D/server.json"; then
  log "генерация ключей + server.json (новый сервер)"
  sudo docker run --rm -v "$D":/opt/amnezia/xray --entrypoint sh "$IMG" -c 'cd /opt/amnezia/xray; xray uuid > xray_uuid.key; openssl rand -hex 8 > xray_short_id.key; xray x25519 > xray_x25519.raw 2>&1' || fail keys
  UUID=$(sudo cat "$D/xray_uuid.key" | tr -d " \\r\\n")
  SID=$(sudo cat "$D/xray_short_id.key" | tr -d " \\r\\n")
  PRIV=$(sudo cat "$D/xray_x25519.raw" | grep -i private | head -1 | sed 's/.*: *//' | tr -d " \\r\\n")
  PUB=$(sudo cat "$D/xray_x25519.raw" | grep -iE 'public|password' | head -1 | sed 's/.*: *//' | tr -d " \\r\\n")
  echo "$PRIV" | sudo tee "$D/xray_private.key" >/dev/null
  echo "$PUB" | sudo tee "$D/xray_public.key" >/dev/null
  [ -n "$UUID" ] && [ -n "$PRIV" ] && [ -n "$PUB" ] || fail emptykeys
  sudo tee "$D/server.json" >/dev/null <<EOF
{{
    "log": {{ "loglevel": "error" }},
    "inbounds": [
        {{
            "port": $XRAY_SERVER_PORT,
            "protocol": "vless",
            "settings": {{
                "clients": [ {{ "id": "$UUID", "flow": "{FLOW}" }} ],
                "decryption": "none"
            }},
            "streamSettings": {{
                "network": "tcp",
                "security": "reality",
                "realitySettings": {{
                    "dest": "$XRAY_SITE_NAME:443",
                    "serverNames": [ "$XRAY_SITE_NAME" ],
                    "privateKey": "$PRIV",
                    "shortIds": [ "$SID" ]
                }}
            }}
        }}
    ],
    "outbounds": [ {{ "protocol": "freedom" }} ]
}}
EOF
  sudo test -f "$D/clientsTable" || echo "[]" | sudo tee "$D/clientsTable" >/dev/null
else
  log "конфиг уже есть — сохранён, клиенты не тронуты"
fi

log "фаервол: открываю $XRAY_SERVER_PORT/tcp наружу (Docker публикует, но ufw/firewalld могут блочить)"
if command -v ufw >/dev/null 2>&1; then sudo ufw allow $XRAY_SERVER_PORT/tcp >/dev/null 2>&1 || true; sudo ufw route allow proto tcp from any to any port $XRAY_SERVER_PORT >/dev/null 2>&1 || true; fi
if command -v firewall-cmd >/dev/null 2>&1; then sudo firewall-cmd --permanent --add-port=$XRAY_SERVER_PORT/tcp >/dev/null 2>&1 && sudo firewall-cmd --reload >/dev/null 2>&1 || true; fi

log "[5/5] контейнер"
sudo docker rm -f "$C" >/dev/null 2>&1 || true
sudo docker run -d --name "$C" --restart always --privileged --cap-add=NET_ADMIN \\
  -p ${{XRAY_SERVER_PORT}}:${{XRAY_SERVER_PORT}}/tcp \\
  -v "$D":/opt/amnezia/xray \\
  --entrypoint sh "$IMG" -c "xray -config /opt/amnezia/xray/server.json" >/dev/null || fail run
sleep 4
sudo docker ps --format '{{{{.Names}}}}' | grep -Fx "$C" >/dev/null || {{ sudo docker logs "$C" 2>&1 | tail; fail notrunning; }}
log "xray запущен на порту $XRAY_SERVER_PORT"
echo "DEPLOY_DONE"
"""


async def build_client_link(
    conn: asyncssh.SSHClientConnection,
    container: str,
    client_id: str,
    host: str,
    description: str,
    dns1: str,
    dns2: str,
) -> str:
    """Пересобирает vpn:// существующего клиента (UUID живёт в server.json)."""
    server = await _read_server(conn, container)
    ids = [c.get("id") for c in _client_list(server) if isinstance(c, dict)]
    if client_id not in ids:
        raise XrayError("Клиент не найден")
    bits = await read_server_bits(conn, container)
    return assemble_xray_link(
        host=host, description=description, dns1=dns1, dns2=dns2, client_id=client_id,
        port=bits["port"], pub=bits["pub"], short=bits["short"], site=bits["site"],
        flow=bits["flow"],
    )
