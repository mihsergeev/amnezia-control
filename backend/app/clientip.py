"""Настоящий IP клиента за обратным прокси.

Панель работает за цепочкой caddy → nginx → backend, поэтому у бэкенда
``request.client.host`` — это адрес соседнего контейнера в Docker-сети
(172.20.0.x), а не адрес пользователя. Из-за этого в журнал/алерты/rate-limit
попадал внутренний IP прокси, а не реального клиента.

Реальный адрес берем из ``X-Forwarded-For``: идем справа налево и пропускаем
только адреса своих прокси (``trusted_proxies``: docker-сети и loopback).
Первый адрес не из этого списка и есть клиент: его дописал наш прокси, правее
всего, что клиент мог подсунуть в заголовке. Раньше пропускались все частные
сети, и клиент из LAN или меша (10.x, 192.168.x) с поддельным публичным адресом
в заголовке выдавал себя за кого угодно и обходил блокировку входа.

Шлюз docker-сети (172.x.0.1) - особый случай: через него приходит и прокси на
хосте (к опубликованному порту на 127.0.0.1), и, при открытом наружу порте,
любой IPv6-клиент через L4 docker-proxy, который заголовков не меняет. Во
втором случае верить шлюзу нельзя: исключение `!gateway` (или `!<адрес>`) в
trusted_proxies, а при panel_bind не на loopback шлюз исключается сам.
"""

import functools
import ipaddress
import socket
import struct

from fastapi import Request

from app.config import DEFAULT_TRUSTED_PROXIES, get_settings


@functools.lru_cache(maxsize=1)
def _default_gateway() -> str | None:
    """IPv4-шлюз по умолчанию из /proc/net/route (в контейнере - шлюз docker-сети)."""
    try:
        with open("/proc/net/route", encoding="ascii") as fh:
            for line in fh.readlines()[1:]:
                f = line.split()
                if len(f) > 2 and f[1] == "00000000" and f[2] != "00000000":
                    return socket.inet_ntoa(struct.pack("<L", int(f[2], 16)))
    except (OSError, ValueError):
        pass
    return None


def _public_bind(bind: str) -> bool:
    """panel_bind (ACONTROL_BIND) открыт не только на loopback."""
    host = bind.strip().rsplit(":", 1)[0].strip("[]") if ":" in bind else ""
    if not bind.strip():
        return False
    if host in ("", "0.0.0.0", "::"):
        return True
    try:
        return not ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host != "localhost"


@functools.lru_cache(maxsize=8)
def _networks(spec: str, bind: str = "") -> tuple:
    """(доверенные сети, исключенные сети)."""
    nets, excluded = [], []
    parts = spec.replace(",", " ").split()
    if _public_bind(bind):
        parts.append("!gateway")
    for part in parts:
        target = nets
        if part.startswith("!"):
            target, part = excluded, part[1:]
            if part == "gateway":
                part = _default_gateway() or ""
        try:
            target.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            continue
    return tuple(nets), tuple(excluded)


def _trusted(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.version == 6 and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    settings = get_settings()
    nets, excluded = _networks(
        settings.trusted_proxies or DEFAULT_TRUSTED_PROXIES, settings.panel_bind
    )
    if any(addr in net for net in excluded):
        return False
    return any(addr in net for net in nets)


def client_ip(request: Request) -> str:
    """IP реального клиента с учетом обратного прокси."""
    peer = request.client.host if request.client else "unknown"
    # заголовок принимаем только от своего прокси: напрямую к бэкенду ходят
    # только тесты и локальный запуск, им верим как есть
    if not _trusted(peer):
        return peer
    headers = getattr(request, "headers", None)
    raw = headers.get("x-forwarded-for", "") if headers is not None else ""
    for part in reversed(raw.split(",")):
        ip = part.strip()
        if not ip:
            continue
        if _trusted(ip):
            continue
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            # мусор на месте, который пишет наш прокси, быть не может, а все,
            # что левее, клиент мог подставить сам
            return peer
        return ip
    # заголовка нет или вся цепочка из своих прокси - берем прямого соседа
    return peer
