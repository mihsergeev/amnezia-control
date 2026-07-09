"""Разворачивание и обновление AmneziaWG на ноде (build-on-target).

Стратегия: собираем образ прямо на сервере из официального базового образа
Amnezia `amneziavpn/amneziawg-go:latest` (Docker Hub) + наш start.sh. По SSH
уходит только маленький скрипт; тяжёлый базовый образ сервер тянет сам.

Версии сравниваются по digest базового образа: локальный (на ноде) против
текущего `:latest` на Docker Hub.
"""

import base64
import random
import re
import secrets

import asyncssh
import httpx

from app import awg

BASE_IMAGE = "amneziavpn/amneziawg-go:latest"
BASE_REPO = "amneziavpn/amneziawg-go"
IMAGE = "acontrol-awg"
CONTAINER = "amnezia-awg2"
SUBNET = "10.8.1.0/24"
# Каталог рабочих файлов деплоя — в $HOME текущего ssh-пользователя (всегда наш,
# без коллизий владельца в общем /tmp) и СВОЙ у каждого протокола (tag), чтобы
# лог одного деплоя не подменял другой на сервере с несколькими протоколами.
WORK_ROOT = "$HOME/.acontrol"
HUB_TAGS_URL = "https://hub.docker.com/v2/repositories/amneziavpn/amneziawg-go/tags?page_size=50"

START_SH = """#!/bin/sh
# Amnezia Control: точка входа контейнера AmneziaWG
awg-quick down /opt/amnezia/awg/awg0.conf >/dev/null 2>&1
awg-quick up /opt/amnezia/awg/awg0.conf 2>/dev/null || true
iptables -t nat -C POSTROUTING -s 10.8.1.0/24 -o eth0 -j MASQUERADE 2>/dev/null \\
  || iptables -t nat -A POSTROUTING -s 10.8.1.0/24 -o eth0 -j MASQUERADE
iptables -C FORWARD -i awg0 -j ACCEPT 2>/dev/null || iptables -A FORWARD -i awg0 -j ACCEPT
iptables -C FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null \\
  || iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
exec tail -f /dev/null
"""

DOCKERFILE = """FROM amneziavpn/amneziawg-go:latest
RUN apk add --no-cache bash iptables iproute2 2>/dev/null \\
  || (apt-get update && apt-get install -y --no-install-recommends bash iptables iproute2) \\
  || true
COPY start.sh /opt/amnezia/start.sh
RUN chmod +x /opt/amnezia/start.sh
ENTRYPOINT ["/opt/amnezia/start.sh"]
"""

# идемпотентный подъём интерфейса + NAT внутри контейнера
_BRINGUP = (
    "awg-quick down /opt/amnezia/awg/awg0.conf >/dev/null 2>&1; "
    "awg-quick up /opt/amnezia/awg/awg0.conf; "
    "iptables -t nat -C POSTROUTING -s 10.8.1.0/24 -o eth0 -j MASQUERADE 2>/dev/null "
    "|| iptables -t nat -A POSTROUTING -s 10.8.1.0/24 -o eth0 -j MASQUERADE; "
    "iptables -C FORWARD -i awg0 -j ACCEPT 2>/dev/null "
    "|| iptables -A FORWARD -i awg0 -j ACCEPT; "
    "iptables -C FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null "
    "|| iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT"
)


def _b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def generate_awg_params() -> dict[str, int]:
    jc = random.randint(3, 10)
    jmin = random.randint(4, 12)
    jmax = random.randint(jmin + 50, jmin + 900)
    while True:
        s1 = random.randint(15, 150)
        s2 = random.randint(15, 150)
        if s1 != s2 and s1 + 56 != s2 and s2 + 56 != s1:
            break
    hs: set[int] = set()
    while len(hs) < 4:
        hs.add(random.randint(5, 2**31 - 1))
    h1, h2, h3, h4 = sorted(hs)
    return {
        "Jc": jc, "Jmin": jmin, "Jmax": jmax, "S1": s1, "S2": s2,
        "H1": h1, "H2": h2, "H3": h3, "H4": h4,
    }


def generate_server_config(port: int) -> dict[str, str]:
    priv, pub = awg.generate_keypair()
    psk = base64.b64encode(secrets.token_bytes(32)).decode()
    p = generate_awg_params()
    conf = (
        "[Interface]\n"
        f"PrivateKey = {priv}\n"
        f"Address = {SUBNET}\n"
        f"ListenPort = {port}\n"
        + "".join(f"{k} = {p[k]}\n" for k in
                  ["Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4"])
    )
    return {"priv": priv, "pub": pub, "psk": psk, "conf": conf}


def build_script(mode: str, port: int, cfg: dict[str, str]) -> str:
    """mode: 'deploy' или 'update' — оба тянут свежий базовый образ.

    Явный `docker pull` обязателен: без него buildkit не оставляет базовый
    образ тегированным, и версию (digest) потом не прочитать.
    """
    parts = [
        "#!/bin/bash",
        "set -e",
        "trap 'echo DEPLOY_ERROR' ERR",
        f"D=/opt/amnezia/awg; BUILD=/opt/acontrol/build; IMG={IMAGE}; CONT={CONTAINER}; PORT={port}",
        'log(){ echo "[$(date +%H:%M:%S)] $*"; }',
        "",
        'log "[1/6] docker"',
        "command -v docker >/dev/null || { curl -fsSL https://get.docker.com | sudo sh >/dev/null; }",
        "",
        'log "[2/6] tun + ip_forward + фаервол"',
        "sudo modprobe tun || true",
        "echo tun | sudo tee /etc/modules-load.d/tun.conf >/dev/null",
        'echo "net.ipv4.ip_forward=1" | sudo tee /etc/sysctl.d/99-acontrol.conf >/dev/null',
        "sudo sysctl -p /etc/sysctl.d/99-acontrol.conf >/dev/null",
        # VPN-порт наружу: Docker публикует, но ufw (особенно ufw-docker) / firewalld
        # по умолчанию блокируют — открываем best-effort (клиентам порт нужен снаружи)
        'if command -v ufw >/dev/null 2>&1; then sudo ufw allow $PORT/udp >/dev/null 2>&1 || true; '
        'sudo ufw route allow proto udp from any to any port $PORT >/dev/null 2>&1 || true; fi',
        'if command -v firewall-cmd >/dev/null 2>&1; then '
        'sudo firewall-cmd --permanent --add-port=$PORT/udp >/dev/null 2>&1 && '
        'sudo firewall-cmd --reload >/dev/null 2>&1 || true; fi',
        "",
        'log "[3/6] Dockerfile + start.sh"',
        'sudo mkdir -p "$BUILD" "$D"',
        f'echo {_b64(DOCKERFILE)} | base64 -d | sudo tee "$BUILD/Dockerfile" >/dev/null',
        f'echo {_b64(START_SH)} | base64 -d | sudo tee "$BUILD/start.sh" >/dev/null',
        "",
        f'log "[4/6] базовый образ {BASE_IMAGE} + сборка"',
        f'sudo docker pull {BASE_IMAGE} 2>&1 | tail -1',
        'sudo docker build -t $IMG "$BUILD" 2>&1 | tail -3',
        "",
        'log "[5/6] конфиг + контейнер"',
        # КРИТИЧНО: перед пересборкой вытаскиваем текущий конфиг из ЖИВОГО
        # контейнера на хост-маунт. Конфиг мог лежать ВНУТРИ контейнера (не на
        # хосте) — тогда guard ниже решил бы, что конфига нет, сгенерил пустой и
        # затёр клиентов (инцидент de-hz 10.07). Читаем через docker exec, что
        # покрывает оба случая (внутри контейнера / на маунте). base64 —
        # побайтовое сохранение (важен завершающий \n у clientsTable).
        'if sudo docker ps --format "{{.Names}}" | grep -qx "$CONT"; then',
        '  for f in awg0.conf clientsTable wireguard_server_private_key.key '
        'wireguard_server_public_key.key wireguard_psk.key; do',
        '    B=$(sudo docker exec "$CONT" cat "/opt/amnezia/awg/$f" 2>/dev/null '
        '| base64 -w0 2>/dev/null || true);',
        '    [ -n "$B" ] && echo "$B" | base64 -d | sudo tee "$D/$f" >/dev/null || true;',
        '  done',
        'fi',
        'if [ ! -f "$D/awg0.conf" ]; then',
        f'  echo {_b64(cfg["conf"])} | base64 -d | sudo tee "$D/awg0.conf" >/dev/null',
        f'  echo {_b64(cfg["pub"])} | base64 -d | sudo tee "$D/wireguard_server_public_key.key" >/dev/null',
        f'  echo {_b64(cfg["priv"])} | base64 -d | sudo tee "$D/wireguard_server_private_key.key" >/dev/null',
        f'  echo {_b64(cfg["psk"])} | base64 -d | sudo tee "$D/wireguard_psk.key" >/dev/null',
        '  printf "[]\\n" | sudo tee "$D/clientsTable" >/dev/null',
        '  log "конфиг создан (новый сервер)"',
        "else",
        '  log "конфиг уже есть — сохранён, клиенты не тронуты"',
        "fi",
        "sudo docker rm -f $CONT >/dev/null 2>&1 || true",
        "sudo docker run -d --name $CONT --restart always --privileged \\",
        "  --cap-add NET_ADMIN --cap-add SYS_MODULE \\",
        "  --sysctl net.ipv4.conf.all.src_valid_mark=1 \\",
        '  -v "$D":/opt/amnezia/awg -p $PORT:$PORT/udp $IMG >/dev/null',
        "sleep 5",
        "",
        'log "[6/6] подъём awg0 + NAT + systemd"',
        f'sudo docker exec $CONT sh -c {_shell_quote(_BRINGUP)}',
        f'echo {_b64(_systemd_unit())} | base64 -d | sudo tee /etc/systemd/system/awg-up.service >/dev/null',
        "sudo systemctl daemon-reload && sudo systemctl enable awg-up.service >/dev/null 2>&1",
        'sudo docker exec $CONT wg show awg0 | grep -E "interface|listening" || true',
        "echo DEPLOY_DONE",
    ]
    return "\n".join(parts) + "\n"


def _shell_quote(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"


def _systemd_unit() -> str:
    return (
        "[Unit]\n"
        "Description=Bring up AmneziaWG interface + NAT inside container\n"
        "After=docker.service\nRequires=docker.service\n\n"
        "[Service]\nType=oneshot\nExecStartPre=/bin/sleep 8\n"
        f"ExecStart=/usr/bin/docker exec {CONTAINER} sh -c '{_BRINGUP}'\n"
        "RemainAfterExit=yes\n\n"
        "[Install]\nWantedBy=multi-user.target\n"
    )


def _paths(tag: str) -> tuple[str, str, str]:
    d = f"{WORK_ROOT}/{tag}"
    return d, f"{d}/run.sh", f"{d}/deploy.log"


async def launch(
    conn: asyncssh.SSHClientConnection, script: str, *, tag: str = "awg"
) -> None:
    """Кладёт скрипт в $HOME/.acontrol/<tag> (свой каталог протокола) и запускает
    детачед. Отдельный каталог на протокол не даёт логам деплоя перемешиваться."""
    d, run, log = _paths(tag)
    await conn.run(f'mkdir -p "{d}"', check=False)
    await conn.run(
        f'cat > "{run}" && rm -f "{log}"',
        input=script, check=False,
    )
    await conn.run(
        f'nohup setsid bash "{run}" > "{log}" 2>&1 </dev/null & disown',
        check=False,
    )


async def foreign_awg_container(conn: asyncssh.SSHClientConnection) -> str | None:
    """Имя AWG-контейнера, собранного НЕ панелью (не {CONTAINER}), если есть.

    На таком сервере пересборка панелью создала бы ПАРАЛЛЕЛЬНЫЙ пустой контейнер
    (конфиг оригинала живёт внутри его контейнера, панель его не переносит), а
    клиенты остались бы на старом — поэтому deploy/update надо запрещать.
    """
    cmd = (
        'D=$(docker info >/dev/null 2>&1 && echo docker || echo "sudo -n docker"); '
        '$D ps --format "{{.Names}}" | grep -i "amnezia-awg" || true'
    )
    result = await conn.run(cmd, check=False)
    for name in (result.stdout or "").split():
        name = name.strip()
        if name and name != CONTAINER:
            return name
    return None


async def read_status(
    conn: asyncssh.SSHClientConnection, *, tag: str = "awg"
) -> dict:
    _d, _run, log = _paths(tag)
    result = await conn.run(f'cat "{log}" 2>/dev/null', check=False)
    log = result.stdout if isinstance(result.stdout, str) else ""
    if "DEPLOY_DONE" in log:
        state = "done"
    elif "DEPLOY_ERROR" in log:
        state = "error"
    elif log.strip():
        state = "running"
    else:
        state = "unknown"
    tail = "\n".join(log.strip().splitlines()[-15:])
    return {"state": state, "log": tail}


async def node_base_digest(conn: asyncssh.SSHClientConnection) -> str | None:
    cmd = (
        f"docker inspect --format '{{{{index .RepoDigests 0}}}}' {BASE_IMAGE} 2>/dev/null "
        f"|| sudo docker inspect --format '{{{{index .RepoDigests 0}}}}' {BASE_IMAGE} 2>/dev/null"
    )
    result = await conn.run(cmd, check=False)
    out = (result.stdout or "").strip()
    if "@sha256:" in out:
        return out.split("@", 1)[1]
    return None


async def node_awg_go_version(conn: asyncssh.SSHClientConnection) -> str | None:
    """Версия бинаря amneziawg-go из работающего контейнера (напр. 0.0.20250522)."""
    cmd = (
        'D=$(docker info >/dev/null 2>&1 && echo docker || echo "sudo -n docker"); '
        'C=$($D ps --format "{{.Names}}" | grep -m1 amnezia-awg); '
        '[ -n "$C" ] && $D exec "$C" amneziawg-go --version 2>/dev/null'
    )
    result = await conn.run(cmd, check=False)
    out = (result.stdout or "").strip()
    # "amneziawg-go 0.0.20250522 - https://amnezia.org" → 0.0.20250522
    match = re.search(r"\d+\.\d+[\d.]*", out)
    return match.group(0) if match else None


def _is_version_tag(name: str) -> bool:
    return bool(re.match(r"^\d+\.\d+", name))


async def hub_info() -> dict:
    """Тянет теги с Docker Hub, строит digest→версия и находит latest."""
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(HUB_TAGS_URL)
        resp.raise_for_status()
        data = resp.json()
    latest_digest = ""
    latest_updated = ""
    digest_to_version: dict[str, str] = {}
    for tag in data.get("results", []):
        name = tag.get("name", "")
        digest = tag.get("digest", "")
        if name == "latest":
            latest_digest = digest
            latest_updated = tag.get("last_updated", "")
        elif digest and _is_version_tag(name):
            digest_to_version.setdefault(digest, name)
    return {
        "latest_digest": latest_digest,
        "latest_version": digest_to_version.get(latest_digest),
        "latest_updated": latest_updated,
        "digest_to_version": digest_to_version,
    }
