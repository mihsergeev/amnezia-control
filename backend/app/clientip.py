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
"""

import functools
import ipaddress

from fastapi import Request

from app.config import DEFAULT_TRUSTED_PROXIES, get_settings


@functools.lru_cache(maxsize=8)
def _networks(spec: str) -> tuple:
    nets = []
    for part in spec.replace(",", " ").split():
        try:
            nets.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            continue
    return tuple(nets)


def _trusted(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.version == 6 and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    spec = get_settings().trusted_proxies or DEFAULT_TRUSTED_PROXIES
    return any(addr in net for net in _networks(spec))


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
