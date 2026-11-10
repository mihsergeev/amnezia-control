"""Хранилище редактируемых настроек панели (в БД, поверх env-дефолтов)."""

import json

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app import nodelock
from app.config import Settings
from app.models import AppSetting

ALERTS_KEY = "alerts"
# сервисы одноразовых ссылок: [{"id", "name", "url", "engine"}] (см. app/share.py)
SHARE_KEY = "share_services"


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
    return alert_config_from_raw(raw, settings)


def alert_config_from_raw(raw: str | None, settings: Settings) -> dict:
    """Resolve one settings snapshot, including an absent database row."""
    data = json.loads(raw) if raw else {}
    empty_overrides = set(data.get("empty_overrides") or [])
    channels = {
        key: data.get(key, "") if key in empty_overrides else (
            data.get(key) or getattr(settings, f"alert_{key}")
        )
        for key in ("telegram_token", "telegram_chat", "webhook")
    }
    return {
        **channels,
        # адрес Telegram Bot API: пусто = дефолт api.telegram.org (см. alerts.py).
        # Можно указать зеркало/прокси для регионов, где телега заблокирована.
        "telegram_api": data.get("telegram_api") or "",
        # язык алертов; пусто - не выбирали, шлем по-русски, как раньше
        "lang": data.get("lang") or "",
    }


async def set_alert_config(
    session: AsyncSession,
    telegram_token: str | None,
    telegram_chat: str,
    webhook: str | None,
    telegram_api: str = "",
    lang: str = "",
) -> None:
    # The panel runs one uvicorn process, as do the existing node operations.
    # Hold through commit so another PUT merges the newly committed overrides.
    async with nodelock.hold("alert-settings", 0):
        raw = await _get_raw(session, ALERTS_KEY)
        data = json.loads(raw) if raw else {}
        empty_overrides = set(data.get("empty_overrides") or [])
        # Omitted masked secrets preserve the database override or its absence.
        # Copying an effective env default here would pin it across env rotations.
        for key, value in (
            ("telegram_token", telegram_token),
            ("webhook", webhook),
            ("telegram_chat", telegram_chat),
        ):
            if value is not None:
                data[key] = value.strip()
                # Legacy blanks used env defaults. Only an explicitly cleared
                # field gets the marker that suppresses that fallback.
                if data[key]:
                    empty_overrides.discard(key)
                else:
                    empty_overrides.add(key)
        if empty_overrides:
            data["empty_overrides"] = sorted(empty_overrides)
        else:
            data.pop("empty_overrides", None)
        data.update(
            telegram_api=telegram_api.strip().rstrip("/"),
            lang=lang,
        )
        await _set_raw(
            session,
            ALERTS_KEY,
            json.dumps(data),
        )


async def get_share_services(session: AsyncSession) -> list[dict]:
    raw = await _get_raw(session, SHARE_KEY)
    try:
        data = json.loads(raw) if raw else []
    except ValueError:
        return []
    return [s for s in data if isinstance(s, dict) and s.get("id")]


async def set_share_services(session: AsyncSession, services: list[dict]) -> None:
    await _set_raw(session, SHARE_KEY, json.dumps(services, ensure_ascii=False))
