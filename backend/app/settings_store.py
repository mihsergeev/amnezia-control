"""Хранилище редактируемых настроек панели (в БД, поверх env-дефолтов)."""

import json

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.models import AppSetting

ALERTS_KEY = "alerts"


async def _get_raw(session: AsyncSession, key: str) -> str | None:
    return await session.scalar(
        select(AppSetting.value).where(AppSetting.key == key)
    )


async def _set_raw(session: AsyncSession, key: str, value: str) -> None:
    row = await session.get(AppSetting, key)
    if row is None:
        session.add(AppSetting(key=key, value=value))
    else:
        row.value = value
    await session.commit()


async def get_alert_config(session: AsyncSession, settings: Settings) -> dict:
    """Эффективная конфигурация алертов: значение из БД, иначе — из env."""
    raw = await _get_raw(session, ALERTS_KEY)
    data = json.loads(raw) if raw else {}
    return {
        "telegram_token": data.get("telegram_token") or settings.alert_telegram_token,
        "telegram_chat": data.get("telegram_chat") or settings.alert_telegram_chat,
        # адрес Telegram Bot API: пусто = дефолт api.telegram.org (см. alerts.py).
        # Можно указать зеркало/прокси для регионов, где телега заблокирована.
        "telegram_api": data.get("telegram_api") or "",
        "webhook": data.get("webhook") or settings.alert_webhook,
    }


async def set_alert_config(
    session: AsyncSession,
    telegram_token: str,
    telegram_chat: str,
    webhook: str,
    telegram_api: str = "",
) -> None:
    await _set_raw(
        session,
        ALERTS_KEY,
        json.dumps(
            {
                "telegram_token": telegram_token.strip(),
                "telegram_chat": telegram_chat.strip(),
                "telegram_api": telegram_api.strip().rstrip("/"),
                "webhook": webhook.strip(),
            }
        ),
    )
