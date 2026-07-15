"""Экспорт «полного доступа» — full-access vpn:// для десктоп-клиента AmneziaVPN.

Клиент распознаёт админский конфиг по hostName+userName+password (SSH-доступ) и
до-сканирует контейнеры сам. Панель генерит ВЫДЕЛЕННЫЙ SSH-ключ (тег
acontrol-desktop), кладёт его публичную часть в authorized_keys ssh_user
(заменяя прошлый desktop-ключ), приватную вкладывает в конфиг как password.
Если ключ утечёт — отзывается только он, ключ панели не затрагивается.
"""

import base64
import json
import shlex
import struct
import zlib

import asyncssh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

DESKTOP_KEY_TAG = "acontrol-desktop"
_DOCKER = 'DOCKER=$(docker info >/dev/null 2>&1 && echo docker || echo "sudo -n docker"); '


class FullAccessError(Exception):
    pass


def generate_keypair() -> tuple[str, str]:
    """RSA-2048 (максимальная совместимость с SSH-клиентом Amnezia).

    Возвращает (приватный PEM 'BEGIN RSA PRIVATE KEY', публичный 'ssh-rsa ... tag').
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()
    pub = key.public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    ).decode()
    return priv, f"{pub} {DESKTOP_KEY_TAG}"


async def install_desktop_key(
    conn: asyncssh.SSHClientConnection, pubkey: str
) -> None:
    """Кладёт desktop-ключ в authorized_keys ssh_user, заменяя прошлый."""
    inner = (
        "mkdir -p ~/.ssh && chmod 700 ~/.ssh && touch ~/.ssh/authorized_keys && "
        f"(grep -v {DESKTOP_KEY_TAG} ~/.ssh/authorized_keys > ~/.ssh/ak.tmp 2>/dev/null || true) && "
        "mv ~/.ssh/ak.tmp ~/.ssh/authorized_keys 2>/dev/null; "
        f"printf '%s\\n' {shlex.quote(pubkey)} >> ~/.ssh/authorized_keys && "
        "chmod 600 ~/.ssh/authorized_keys && echo KEY_OK"
    )
    result = await conn.run(inner, check=False)
    if "KEY_OK" not in (result.stdout or ""):
        err = (result.stderr or "").strip() or "не удалось установить ключ"
        raise FullAccessError(err)


async def detect_containers(conn: asyncssh.SSHClientConnection) -> list[str]:
    cmd = _DOCKER + "$DOCKER ps --format '{{.Names}}' | grep -i amnezia"
    result = await conn.run(cmd, check=False)
    return [
        line.strip()
        for line in (result.stdout or "").splitlines()
        if line.strip()
    ]


def _canonical(name: str) -> str | None:
    # ВАЖНО: amnezia-awg2 (новый AmneziaWG 2.0) проверяем ДО amnezia-awg —
    # иначе startswith("amnezia-awg") схлопнул бы новый контейнер в legacy, и
    # приложение AmneziaVPN пометило бы протокол «AmneziaWG Legacy» и полезло
    # искать несуществующий контейнер amnezia-awg (ErrorCode 202).
    if name.startswith("amnezia-awg2"):
        return "amnezia-awg2"
    if name.startswith("amnezia-awg"):
        return "amnezia-awg"
    if name.startswith("amnezia-openvpn"):
        return "amnezia-openvpn-cloak"
    if name.startswith("amnezia-xray"):
        return "amnezia-xray"
    if name.startswith("amnezia-wireguard"):
        return "amnezia-wireguard"
    return None


def build_full_access_link(
    *,
    host: str,
    ssh_user: str,
    ssh_port: int,
    private_key: str,
    description: str,
    dns1: str,
    dns2: str,
    container_names: list[str],
    awg2_config: dict | None = None,
) -> str:
    types: list[str] = []
    for name in container_names:
        canon = _canonical(name)
        if canon and canon not in types:
            types.append(canon)
    if not types:
        types = ["amnezia-awg"]
    containers: list[dict] = []
    for t in types:
        entry: dict = {"container": t}
        # Для нового AmneziaWG 2.0 вкладываем полный конфиг протокола: без него
        # приложение не видит protocol_version="2" и лечит сервер как legacy.
        if t == "amnezia-awg2" and awg2_config:
            entry["awg"] = awg2_config
        containers.append(entry)
    top = {
        "containers": containers,
        "defaultContainer": types[0],
        "description": description,
        "dns1": dns1,
        "dns2": dns2,
        "hostName": host,
        "userName": ssh_user,
        "password": private_key,
        "port": ssh_port,
    }
    payload = json.dumps(top, ensure_ascii=False, sort_keys=True).encode()
    compressed = struct.pack(">I", len(payload)) + zlib.compress(payload)
    return "vpn://" + base64.urlsafe_b64encode(compressed).decode().rstrip("=")
