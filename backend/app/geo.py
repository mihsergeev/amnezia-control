"""Определение страны сервера по его адресу — для флажка на карточке.

Разовый лукап на сервер через публичный ipwho.is (без ключа). Приватные/loopback
адреса пропускаем; домены отдаём как есть (ipwho.is сам резолвит). Best-effort:
любая ошибка → пустая строка, флажок просто не покажется."""

import ipaddress
import logging

import httpx

log = logging.getLogger("acontrol.geo")


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
