"""Определение страны сервера по его адресу — для флажка на карточке
(и страны с провайдером для адреса выхода клиентов, если нода - вход каскада).

Разовый лукап на сервер через публичный ipwho.is (без ключа). Приватные/loopback
адреса пропускаем; домены отдаём как есть (ipwho.is сам резолвит). Best-effort:
любая ошибка → пустая строка, флажок просто не покажется."""

import ipaddress
import logging

import httpx

log = logging.getLogger("acontrol.geo")

# ISO 3166-1 alpha-2 codes and XK, also provided by the cascade GeoIP data.
_COUNTRY_CODES = frozenset("""
AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ
BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR
CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR
GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU
ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ
LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ
MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF
PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI
SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR
TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS XK YE YT ZA ZM ZW
""".split())


def normalize_country_code(value: object) -> str:
    """Return a supported uppercase country code or an empty string."""
    if not isinstance(value, str) or len(value) != 2 or not value.isascii():
        return ""
    code = value.upper()
    return code if code in _COUNTRY_CODES else ""


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
