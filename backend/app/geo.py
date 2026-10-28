"""Определение страны сервера по его адресу — для флажка на карточке
(и страны с провайдером для адреса выхода клиентов, если нода - вход каскада).

Разовый лукап на сервер через публичный ipwho.is (без ключа). Приватные/loopback
адреса пропускаем; домены отдаём как есть (ipwho.is сам резолвит). Best-effort:
любая ошибка → пустая строка, флажок просто не покажется."""

import ipaddress
import logging

import httpx

log = logging.getLogger("acontrol.geo")


async def ip_info(ip: str) -> tuple[str, str]:
    """(страна, провайдер) для адреса выхода клиентов, ('', '') если не определить."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "", ""
    if addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_link_local:
        return "", ""
    try:
        async with httpx.AsyncClient(timeout=8) as http:
            r = await http.get(
                f"https://ipwho.is/{ip}",
                params={"fields": "success,country_code,connection"},
            )
            data = r.json()
    except Exception:  # noqa: BLE001 — геолукап не критичен
        return "", ""
    if not data.get("success"):
        return "", ""
    code = data.get("country_code")
    code = code.upper() if isinstance(code, str) and len(code) == 2 else ""
    conn = data.get("connection")
    org = (conn.get("org") or conn.get("isp") or "") if isinstance(conn, dict) else ""
    return code, str(org)[:128]


async def country_code(host: str) -> str:
    """ISO 3166-1 alpha-2 (напр. 'KZ') или '' если не определить."""
    try:
        addr = ipaddress.ip_address(host)
        if (
            addr.is_private
            or addr.is_loopback
            or addr.is_reserved
            or addr.is_link_local
        ):
            return ""
    except ValueError:
        pass  # не IP (домен) — пусть API резолвит сам
    try:
        async with httpx.AsyncClient(timeout=8) as http:
            r = await http.get(
                f"https://ipwho.is/{host}",
                params={"fields": "success,country_code"},
            )
            data = r.json()
            code = data.get("country_code")
            if data.get("success") and isinstance(code, str) and len(code) == 2:
                return code.upper()
    except Exception:  # noqa: BLE001 — геолукап не критичен
        pass
    return ""
