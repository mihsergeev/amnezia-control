"""Простой in-memory лимитер попыток входа (защита от брутфорса).

Панель работает одним процессом uvicorn, поэтому общего хранилища не нужно.
Ключ — обычно IP клиента. Окно и лимит подобраны консервативно; при
превышении — временная блокировка. Сбрасывается при рестарте (приемлемо).
"""

import time

WINDOW = 300  # сек: окно подсчёта неудачных попыток
MAX_FAILURES = 10  # неудач в окне до блокировки
LOCKOUT = 900  # сек: длительность блокировки после превышения

_failures: dict[str, list[float]] = {}


def _now(now: float | None) -> float:
    return time.time() if now is None else now


def is_locked(key: str, *, now: float | None = None) -> bool:
    t = _now(now)
    times = [ts for ts in _failures.get(key, []) if t - ts < LOCKOUT]
    if times:
        _failures[key] = times
    else:
        _failures.pop(key, None)
    recent = [ts for ts in times if t - ts < WINDOW]
    # блокируем, если за окно набралось >= MAX_FAILURES и последняя ещё «свежая»
    return len(recent) >= MAX_FAILURES


def record_failure(key: str, *, now: float | None = None) -> None:
    t = _now(now)
    times = [ts for ts in _failures.get(key, []) if t - ts < LOCKOUT]
    times.append(t)
    _failures[key] = times


def clear(key: str) -> None:
    _failures.pop(key, None)
