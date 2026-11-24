"""Простой in-memory лимитер попыток входа (защита от брутфорса).

Панель работает одним процессом uvicorn, поэтому общего хранилища не нужно.
Ключ - обычно IP клиента (IPv6 - сеть /64, см. ip_key). Окно и лимит подобраны
консервативно; при превышении - блокировка на LOCKOUT. Сбрасывается при
рестарте (приемлемо).

Проверка блокировки и запись неудачи разделены проверкой пароля (bcrypt в
потоке). Без очереди параллельные попытки все проходили проверку до того, как
первая успевала записать неудачу, и лимит не держал пачку запросов. Поэтому
попытки по одному ключу идут через serialized() по очереди.
"""

import asyncio
import contextlib
import ipaddress
import time

WINDOW = 300  # сек: окно подсчёта неудачных попыток
MAX_FAILURES = 10  # неудач в окне до блокировки
LOCKOUT = 900  # сек: длительность блокировки после превышения
# Потолок числа ключей: ключ берется из запроса (адрес, логин), и без потолка
# поток неудач с разными логинами раздувал бы словари без предела
MAX_KEYS = 10000
PRUNE_EVERY = 60  # сек: как часто вычищать протухшие записи

_failures: dict[str, list[float]] = {}
# до какого момента ключ заблокирован. Раньше блокировки как таковой не было:
# считались только попытки в окне WINDOW, и через 5 минут после десятой ключ
# снова получал 10 попыток - LOCKOUT ни на что не влиял
_locked_until: dict[str, float] = {}
_last_prune = 0.0
# очереди попыток по ключу: [замок, сколько запросов его держат или ждут]
_queues: dict[str, list] = {}


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


def _prune(t: float) -> None:
    """Убирает протухшие записи, а при переполнении - самые старые."""
    global _last_prune
    _last_prune = t
    for key in [k for k, until in _locked_until.items() if t >= until]:
        _locked_until.pop(key, None)
        _failures.pop(key, None)
    for key in [k for k, ts in _failures.items() if not ts or t - ts[-1] >= WINDOW]:
        if key not in _locked_until:
            _failures.pop(key, None)
    if len(_failures) > MAX_KEYS:
        # первыми уходят незаблокированные ключи с самой давней неудачей
        free = sorted(
            (k for k in _failures if k not in _locked_until),
            key=lambda k: _failures[k][-1],
        )
        for key in free[: len(_failures) - MAX_KEYS]:
            _failures.pop(key, None)
    if len(_locked_until) > MAX_KEYS:
        for key in sorted(_locked_until, key=_locked_until.get)[: len(_locked_until) - MAX_KEYS]:
            _locked_until.pop(key, None)
            _failures.pop(key, None)


def record_failure(
    key: str, *, now: float | None = None, max_failures: int = MAX_FAILURES
) -> bool:
    """Регистрирует неудачную попытку. Возвращает True, если ИМЕННО эта попытка
    перевела ключ в состояние блокировки (для однократного алерта)."""
    t = _now(now)
    if t - _last_prune >= PRUNE_EVERY or len(_failures) >= MAX_KEYS:
        _prune(t)
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


@contextlib.asynccontextmanager
async def serialized(*keys: str):
    """Выполняет попытки с общим ключом по одной: проверка is_locked внутри
    видит неудачи всех предыдущих. Замки берутся в одном порядке, чтобы два
    запроса с пересекающимися ключами не ждали друг друга по кругу. Запись
    убирается, когда очередь пуста, так что ключи из запроса не копятся."""
    ordered = sorted(set(keys))
    entries = []
    for key in ordered:
        entry = _queues.setdefault(key, [asyncio.Lock(), 0])
        entry[1] += 1
        entries.append((key, entry))
    held = []
    try:
        for _key, entry in entries:
            await entry[0].acquire()
            held.append(entry[0])
        yield
    finally:
        for lock in reversed(held):
            lock.release()
        for key, entry in entries:
            entry[1] -= 1
            if entry[1] == 0 and _queues.get(key) is entry:
                _queues.pop(key, None)
