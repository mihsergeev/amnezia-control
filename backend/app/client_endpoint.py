import asyncio
import ipaddress
import re
import socket

import idna
from fastapi import HTTPException


INVALID = "Укажите домен или IP VPN-сервера без порта."
UNRESOLVED = "Домен Client Endpoint не разрешается в IP. Проверьте DNS и повторите попытку."
_SECTION = re.compile(r"^[ \t]*\[([^\]\r\n]+)\]", re.MULTILINE)
_PEER_ENDPOINT = re.compile(
    r"^([ \t]*Endpoint[ \t]*=[ \t]*)[^ \t\r\n#;]+([ \t]*:[ \t]*[0-9]+)(?=[ \t\r\n#;]|$)",
    re.MULTILINE | re.IGNORECASE,
)


def normalize(value: str) -> str:
    host = value.strip()
    if not host:
        return ""
    ip = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    if "%" not in ip:
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            pass
        else:
            if host == ip or address.version == 6:
                return str(address)
    try:
        domain = idna.encode(host, uts46=True).decode("ascii")
    except idna.IDNAError:
        raise ValueError(INVALID) from None
    if "." not in domain.rstrip(".") or re.fullmatch(r"[0-9.]+", domain):
        raise ValueError(INVALID)
    return domain


async def require_resolvable(host: str) -> None:
    if not host:
        return
    try:
        ipaddress.ip_address(host)
        return
    except ValueError:
        pass
    try:
        await asyncio.wait_for(
            asyncio.get_running_loop().getaddrinfo(host, None, type=socket.SOCK_DGRAM),
            timeout=3,
        )
    except (OSError, TimeoutError):
        raise HTTPException(422, UNRESOLVED) from None


def peer_config(config: str, host: str) -> str:
    if not host:
        return config
    sections = list(_SECTION.finditer(config))
    for index, section in enumerate(sections):
        if section[1].lower() != "peer":
            continue
        end = sections[index + 1].start() if index + 1 < len(sections) else len(config)
        peer = config[section.end():end]
        address = f"[{host}]" if ":" in host else host
        rendered = _PEER_ENDPOINT.sub(lambda match: f"{match[1]}{address}{match[2]}", peer)
        return config[:section.end()] + rendered + config[end:]
    return config
