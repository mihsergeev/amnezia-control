"""Блокировка операций панели на ноде.

Выдача, отзыв, пауза и прочие изменения устроены как "прочитал состояние с
ноды, изменил, записал". Без блокировки два одновременных запроса (двойной
Enter, два админа, API и отзыв по сроку) читали одно состояние: оба клиента
получали один IP, запись clientsTable или server.json одного из них терялась,
отзыв перезаписывал конфиг копией без только что выданного пира.

Ключ - (семейство протокола, id сервера): все AWG (2.0, 3.1, Legacy) правят
одну ноду через один набор утилит и сериализуются вместе, XRay и OpenVPN -
отдельно. Блокировка повторно входимая в пределах одной задачи, чтобы вложенное
подключение в той же операции не ждало само себя.
"""

import asyncio
from contextlib import asynccontextmanager

from fastapi import HTTPException, status

# сколько ждать занятую ноду, прежде чем ответить "занята"
WAIT_SECONDS = 120


class _Lock:
    def __init__(self) -> None:
        self.lock = asyncio.Lock()
        self.owner: asyncio.Task | None = None
        self.depth = 0


_locks: dict[tuple[str, int], _Lock] = {}


def family(protocol: str) -> str:
    return "awg" if protocol.startswith("awg") else protocol


@asynccontextmanager
async def hold(kind: str, server_id: int, *, wait: float = WAIT_SECONDS):
    key = (family(kind), int(server_id))
    lk = _locks.setdefault(key, _Lock())
    task = asyncio.current_task()
    if lk.owner is task and task is not None:
        lk.depth += 1
        try:
            yield
        finally:
            lk.depth -= 1
        return
    try:
        async with asyncio.timeout(wait):
            await lk.lock.acquire()
    except TimeoutError as exc:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "Нода занята другой операцией панели, повторите через минуту.",
        ) from exc
    lk.owner, lk.depth = task, 1
    try:
        yield
    finally:
        lk.owner, lk.depth = None, 0
        lk.lock.release()


@asynccontextmanager
async def connect(kind: str, server_id: int, conn_cm):
    """Блокировка ноды на все время SSH-сессии conn_cm (async context manager)."""
    async with hold(kind, server_id):
        async with conn_cm as conn:
            yield conn
