"""Простой in-memory лимитер попыток входа (защита от брутфорса).

Панель работает одним процессом uvicorn, поэтому общего хранилища не нужно.
Ключ - обычно IP клиента (IPv6 - сеть /64, см. ip_key). Окно и лимит подобраны
консервативно; при превышении - блокировка на LOCKOUT. Сбрасывается при
рестарте (приемлемо).
"""

import ipaddress
import time

WINDOW = 300  # сек: окно подсчёта неудачных попыток
MAX_FAILURES = 10  # неудач в окне до блокировки
LOCKOUT = 900  # сек: длительность блокировки после превышения

_failures: dict[str, list[float]] = {}
# до какого момента ключ заблокирован. Раньше блокировки как таковой не было:
# считались только попытки в окне WINDOW, и через 5 минут после десятой ключ
# снова получал 10 попыток - LOCKOUT ни на что не влиял
_locked_until: dict[str, float] = {}


def _now(now: float | None) -> float:
    return time.time() if now is None else now


def ip_key(ip: str) -> str:
    """Ключ лимитера по адресу. IPv6 считаем по /64: провайдер обычно выдает
    клиенту целую /64, и счетчик на каждый адрес из нее не ограничивал бы ничего."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if addr.version == 6:
        if addr.ipv4_mapped:
            return str(addr.ipv4_mapped)
        return str(ipaddress.ip_network(f"{addr}/64", strict=False))
    return str(addr)


def is_locked(key: str, *, now: float | None = None) -> bool:
    t = _now(now)
    until = _locked_until.get(key)
    if until is not None:
        if t < until:
            return True
        _locked_until.pop(key, None)
        _failures.pop(key, None)
    times = [ts for ts in _failures.get(key, []) if t - ts < WINDOW]
    if times:
        _failures[key] = times
    else:
        _failures.pop(key, None)
    return False


def record_failure(
    key: str, *, now: float | None = None, max_failures: int = MAX_FAILURES
) -> bool:
    """Регистрирует неудачную попытку. Возвращает True, если ИМЕННО эта попытка
    перевела ключ в состояние блокировки (для однократного алерта)."""
    t = _now(now)
    times = [ts for ts in _failures.get(key, []) if t - ts < WINDOW]
    times.append(t)
    _failures[key] = times
    if len(times) >= max_failures and key not in _locked_until:
        _locked_until[key] = t + LOCKOUT
        return True
    return False


def clear(key: str) -> None:
    _failures.pop(key, None)
    _locked_until.pop(key, None)
