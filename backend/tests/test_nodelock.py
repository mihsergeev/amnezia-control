"""Блокировка операций на ноде и предел на SSH-сессию."""

import asyncio
from contextlib import asynccontextmanager

import pytest
from fastapi import HTTPException

from app import nodelock


@asynccontextmanager
async def _conn():
    yield object()


async def test_parallel_operations_serialize():
    order: list[str] = []

    async def op(tag):
        async with nodelock.connect("awg3", 1, _conn()):
            order.append(f"{tag}+")
            await asyncio.sleep(0.01)
            order.append(f"{tag}-")

    await asyncio.gather(op("a"), op("b"))
    # вторая операция начинается только после конца первой
    assert order in (["a+", "a-", "b+", "b-"], ["b+", "b-", "a+", "a-"])


async def test_reentrant_in_one_task():
    async with nodelock.hold("awg", 2):
        async with nodelock.hold("awg3", 2):  # одно семейство, та же задача
            pass


async def test_hung_operation_times_out(monkeypatch):
    monkeypatch.setattr(nodelock, "OP_TIMEOUT", 0.05)
    with pytest.raises(HTTPException) as exc:
        async with nodelock.connect("xray", 3, _conn()):
            await asyncio.sleep(1)
    assert exc.value.status_code == 504
    # блокировка отпущена: следующая операция идет сразу
    async with nodelock.hold("xray", 3, wait=0.1):
        pass


async def test_own_timeout_passes_through(monkeypatch):
    with pytest.raises(TimeoutError):
        async with nodelock.connect("openvpn", 4, _conn()):
            raise TimeoutError("connect timeout")
