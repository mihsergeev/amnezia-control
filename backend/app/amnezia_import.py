"""Разбор источников для импорта серверов.

1. Amnezia «Полный доступ» (vpn://…): base64url(qCompress(json)) с host/SSH/протоколами.
2. Массовый список: строки `host[:port] user [password]`.
"""

import base64
import binascii
import json
import zlib
from collections.abc import Iterator
from dataclasses import dataclass, field

from app import sshops


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


# лимит на распакованный размер — защита от zlib-бомбы в присланной ссылке
_MAX_UNCOMPRESSED = 8 * 1024 * 1024
_MAX_JSON_DEPTH = 128


def _decompress_limited(data: bytes) -> bytes:
    obj = zlib.decompressobj()
    out = obj.decompress(data, _MAX_UNCOMPRESSED + 1)
    if len(out) > _MAX_UNCOMPRESSED:
        raise ImportParseError("конфиг Amnezia слишком большой")
    if not obj.eof:
        raise zlib.error("неполный сжатый конфиг")
    return out


def _maybe_uncompress(raw: bytes) -> bytes:
    # qCompress: 4 байта BE (размер) + zlib
    try:
        return _decompress_limited(raw[4:])
    except zlib.error:
        pass
    try:
        return _decompress_limited(raw)
    except zlib.error:
        pass
    if len(raw) > _MAX_UNCOMPRESSED:
        raise ImportParseError("конфиг Amnezia слишком большой")
    return raw


def _walk_objects(node: object, depth: int = 0) -> Iterator[dict]:
    if depth > _MAX_JSON_DEPTH:
        raise ImportParseError("слишком глубокая вложенность конфига Amnezia")
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from _walk_objects(value, depth + 1)
    elif isinstance(node, list):
        for item in node:
            yield from _walk_objects(item, depth + 1)


def _ssh_port(value: object, error: str) -> int:
    if value is None or value == "":
        return 22
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise ImportParseError(error)
    try:
        port = int(value)
    except ValueError as exc:
        raise ImportParseError(error) from exc
    if not 1 <= port <= 65535:
        raise ImportParseError(error)
    return port


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
    except RecursionError as exc:
        raise ImportParseError("слишком глубокая вложенность конфига Amnezia") from exc
    except ValueError as exc:
        raise ImportParseError(
            "содержимое не похоже на конфиг Amnezia (не удалось разобрать JSON)"
        ) from exc

    creds = None
    protocols: dict[str, None] = {}
    for node in _walk_objects(data):
        if creds is None and ("hostName" in node or "host" in node):
            creds = node
        container = node.get("container")
        if isinstance(container, str) and container:
            protocols[container.removeprefix("amnezia-")] = None
    if creds is None:
        raise ImportParseError(
            "в конфиге нет адреса сервера — нужен экспорт с ПОЛНЫМ доступом"
        )

    host = creds.get("hostName") or creds.get("host")
    if not isinstance(host, str) or not host:
        raise ImportParseError("в конфиге неверный адрес сервера")

    user = (
        creds.get("userName")
        or creds.get("username")
        or creds.get("login")
        or "root"
    )
    if not sshops.valid_ssh_user(user):
        raise ImportParseError("недопустимое имя SSH-пользователя в конфиге")
    port = _ssh_port(creds.get("port"), "некорректный порт SSH в конфиге")
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
    name = name or creds.get("description") or host
    if not isinstance(name, str):
        raise ImportParseError("в конфиге неверное название сервера")

    return ServerSpec(
        host=host,
        name=name,
        ssh_port=port,
        ssh_user=str(user),
        password=password,
        protocols=list(protocols),
    )


def parse_bulk(text: str, default_user: str = "root") -> list[ServerSpec]:
    specs: list[ServerSpec] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        host_port = parts[0]
        host, _, port_str = host_port.partition(":")
        if not host:
            continue
        port = _ssh_port(port_str, f"некорректный порт SSH в строке {line_no}")
        user = parts[1] if len(parts) > 1 else default_user
        if not sshops.valid_ssh_user(user):
            raise ImportParseError(f"недопустимое имя SSH-пользователя в строке {line_no}")
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
