"""Пульс для хостового watchdog (см. /lib65/acontrol/panel-watchdog.sh).

Панель раз в минуту пишет data/heartbeat: время, здоровье канала алертов и креды
(Telegram/webhook). Сторож на ХОСТЕ (вне docker) читает этот файл и независимо
сообщает, если пульс протух (контейнер/БД мертвы или зависли) или self-тест
канала алертов не прошёл. Креды кладём в файл специально — чтобы сторож мог
достучаться в Telegram даже когда панель и БД уже не отвечают."""

import asyncio
import logging
import os
import time

import httpx

from app import settings_store

log = logging.getLogger("acontrol.heartbeat")

HEARTBEAT_INTERVAL = 60


async def _alert_channel_ok(cfg: dict) -> bool:
    """Лёгкий self-тест канала алертов. Telegram → getMe по НАСТРОЕННОМУ базовому
    адресу (проверяет и валидность токена, и доступность API/зеркала — тем же
    путём, что реальные алерты). Только вебхук или пусто — тестировать нечем,
    считаем ок."""
    token, chat = cfg.get("telegram_token"), cfg.get("telegram_chat")
    if token and chat:
        base = (cfg.get("telegram_api") or "https://api.telegram.org").rstrip("/")
        try:
            async with httpx.AsyncClient(timeout=8) as http:
                r = await http.get(f"{base}/bot{token}/getMe")
                return r.status_code == 200 and r.json().get("ok") is True
        except Exception:  # noqa: BLE001
            return False
    return True


def _write(path: str, cfg: dict, alerts_ok: bool) -> None:
    lines = [
        f"ts={int(time.time())}",
        f"alerts_ok={1 if alerts_ok else 0}",
        f"tg_api={cfg.get('telegram_api') or 'https://api.telegram.org'}",
        f"tg_token={cfg.get('telegram_token') or ''}",
        f"tg_chat={cfg.get('telegram_chat') or ''}",
        f"webhook={cfg.get('webhook') or ''}",
    ]
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    os.chmod(tmp, 0o600)  # содержит токен бота
    os.replace(tmp, path)  # атомарная замена — сторож не поймает полу-запись


async def heartbeat_loop(session_factory, settings) -> None:
    path = os.path.join(settings.data_dir, "heartbeat")
    while True:
        try:
            async with session_factory() as session:
                cfg = await settings_store.get_alert_config(session, settings)
            ok = await _alert_channel_ok(cfg)
            _write(path, cfg, ok)
        except Exception:  # noqa: BLE001 — цикл не должен ронять приложение
            log.exception("не удалось записать пульс")
        await asyncio.sleep(HEARTBEAT_INTERVAL)
