"""Разбор источников для импорта серверов.

1. Amnezia «Полный доступ» (vpn://…): base64url(qCompress(json)) с host/SSH/протоколами.
2. Массовый список: строки `host[:port] user [password]`.
"""

import base64
import binascii
import json
import zlib
from dataclasses import dataclass, field


class ImportParseError(Exception):
    pass


@dataclass
class ServerSpec:
    host: str
    name: str = ""
    ssh_port: int = 22
    ssh_user: str = "root"
    password: str | None = None  # None => bootstrap невозможен (ключ/нет пароля)
    protocols: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.name:
            self.name = self.host


def _b64_decode(text: str) -> bytes:
    text = text.strip().replace("\n", "").replace("\r", "").replace(" ", "")
    padded = text + "=" * (-len(text) % 4)
    # Amnezia использует url-safe base64, но подстрахуемся и стандартным алфавитом
    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            return decoder(padded)
        except (ValueError, binascii.Error):
            continue
    raise ImportParseError("не удалось декодировать base64")


def _maybe_uncompress(raw: bytes) -> bytes:
    # qCompress: 4 байта BE (размер) + zlib
    try:
        return zlib.decompress(raw[4:])
    except zlib.error:
        pass
    try:
        return zlib.decompress(raw)
    except zlib.error:
        pass
    return raw


def _find_creds(node: object) -> dict | None:
    """Рекурсивно ищет объект с host/hostName."""
    if isinstance(node, dict):
        if any(k in node for k in ("hostName", "host")):
            return node
        for value in node.values():
            found = _find_creds(value)
            if found is not None:
                return found
    elif isinstance(node, list):
        for item in node:
            found = _find_creds(item)
            if found is not None:
                return found
    return None


def _extract_protocols(data: object) -> list[str]:
    protocols: list[str] = []

    def walk(node: object) -> None:
        if isinstance(node, dict):
            container = node.get("container")
            if isinstance(container, str) and container:
                name = container.removeprefix("amnezia-")
                if name not in protocols:
                    protocols.append(name)
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(data)
    return protocols


def _looks_like_private_key(value: str) -> bool:
    return "-----BEGIN" in value


def parse_amnezia_link(text: str) -> ServerSpec:
    raw = text.strip()
    for prefix in ("vpn://", "amnezia://"):
        if raw.lower().startswith(prefix):
            raw = raw[len(prefix):]
            break
    payload = _maybe_uncompress(_b64_decode(raw))
    try:
        data = json.loads(payload)
    except (json.JSONDecodeError, ValueError, UnicodeDecodeError) as exc:
        raise ImportParseError(
            "содержимое не похоже на конфиг Amnezia (не удалось разобрать JSON)"
        ) from exc

    creds = _find_creds(data)
    if creds is None:
        raise ImportParseError(
            "в конфиге нет адреса сервера — нужен экспорт с ПОЛНЫМ доступом"
        )

    host = creds.get("hostName") or creds.get("host")
    if not host:
        raise ImportParseError("в конфиге пустой адрес сервера")

    user = (
        creds.get("userName")
        or creds.get("username")
        or creds.get("login")
        or "root"
    )
    port = int(creds.get("port") or 22)
    secret = (
        creds.get("password")
        or creds.get("secretData")
        or creds.get("secret_data")
    )
    password = None
    if isinstance(secret, str) and secret and not _looks_like_private_key(secret):
        password = secret

    name = ""
    if isinstance(data, dict):
        name = data.get("description") or ""
    name = name or (creds.get("description") if isinstance(creds, dict) else "") or host

    return ServerSpec(
        host=str(host),
        name=str(name),
        ssh_port=port,
        ssh_user=str(user),
        password=password,
        protocols=_extract_protocols(data),
    )


def parse_bulk(text: str, default_user: str = "root") -> list[ServerSpec]:
    specs: list[ServerSpec] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        host_port = parts[0]
        host, _, port_str = host_port.partition(":")
        if not host:
            continue
        try:
            port = int(port_str) if port_str else 22
        except ValueError:
            raise ImportParseError(f"некорректный порт в строке: {line}")
        user = parts[1] if len(parts) > 1 else default_user
        password = parts[2] if len(parts) > 2 else None
        specs.append(
            ServerSpec(
                host=host,
                name=host,
                ssh_port=port,
                ssh_user=user,
                password=password,
            )
        )
    if not specs:
        raise ImportParseError("не найдено ни одной строки с сервером")
    return specs
