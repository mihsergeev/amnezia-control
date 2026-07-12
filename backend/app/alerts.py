"""Алерты о падении/восстановлении серверов (Telegram / вебхук)."""

import logging
from datetime import datetime, timezone

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app import settings_store
from app.config import Settings
from app.models import ServerStatus

log = logging.getLogger("acontrol.alerts")

# антидребезг падений: сколько подряд циклов нода наблюдалась офлайн, пока её
# статус ещё подтверждён как онлайн. Сбрасывается при онлайне/подтверждении.
_down_streak: dict[int, int] = {}


def alerts_enabled(cfg: dict) -> bool:
    return bool(
        (cfg.get("telegram_token") and cfg.get("telegram_chat"))
        or cfg.get("webhook")
    )


async def send_alert(cfg: dict, text: str) -> list[str]:
    """Шлёт текст во все настроенные каналы. Возвращает список ошибок (пустой = ок)."""
    errors: list[str] = []
    token, chat = cfg.get("telegram_token"), cfg.get("telegram_chat")
    if token and chat:
        # базовый адрес Bot API настраиваемый: для регионов, где api.telegram.org
        # заблокирован, можно указать зеркало/прокси (напр. https://api-tg.example.com)
        base = (cfg.get("telegram_api") or "https://api.telegram.org").rstrip("/")
        url = f"{base}/bot{token}/sendMessage"
        try:
            async with httpx.AsyncClient(timeout=10) as http:
                r = await http.post(
                    url,
                    json={
                        "chat_id": chat,
                        "text": text,
                        "disable_web_page_preview": True,
                    },
                )
                r.raise_for_status()
        except Exception as exc:  # noqa: BLE001 — алерт не должен ронять цикл
            errors.append(f"Telegram: {exc}")
            log.warning("Telegram-алерт не отправлен: %s", exc)

    if cfg.get("webhook"):
        try:
            async with httpx.AsyncClient(timeout=10) as http:
                r = await http.post(cfg["webhook"], json={"text": text})
                r.raise_for_status()
        except Exception as exc:  # noqa: BLE001
            errors.append(f"Webhook: {exc}")
            log.warning("Вебхук-алерт не отправлен: %s", exc)
    return errors


async def maybe_alert(session_factory, settings: Settings, text: str) -> None:
    """Разовый алерт (бэкап упал, отзыв отложен, клиент скоро истекает и т.п.):
    открывает свою сессию, шлёт если каналы настроены. Best-effort."""
    try:
        async with session_factory() as session:
            cfg = await settings_store.get_alert_config(session, settings)
        if alerts_enabled(cfg):
            await send_alert(cfg, text)
    except Exception:  # noqa: BLE001 — алерт не должен ронять вызывающий цикл
        log.warning("разовый алерт не отправлен", exc_info=True)


async def security_alert(session: AsyncSession, settings: Settings, text: str) -> None:
    """Шлёт security-событие (брутфорс, смена host-ключа, смена пароля и т.п.)
    во все настроенные каналы. Best-effort — не роняет вызывающую операцию."""
    try:
        cfg = await settings_store.get_alert_config(session, settings)
        if alerts_enabled(cfg):
            await send_alert(cfg, text)
    except Exception:  # noqa: BLE001
        log.warning("security-алерт не отправлен", exc_info=True)


async def reconcile(
    session: AsyncSession,
    settings: Settings,
    online_map: dict[int, bool],
    names: dict[int, str],
) -> list[tuple[int, bool]]:
    """Сверяет текущий статус с сохранённым, шлёт алерты на переходах.

    Возвращает список переходов (server_id, online_now).
    Первое наблюдение сервера статус фиксирует, но алерт не шлёт.
    """
    now = datetime.now(timezone.utc)
    misses = max(1, settings.server_down_misses)
    known = {s.server_id: s for s in await session.scalars(select(ServerStatus))}
    transitions: list[tuple[int, bool]] = []
    for sid, online in online_map.items():
        prev = known.get(sid)
        if prev is None:
            session.add(ServerStatus(server_id=sid, online=online, changed_at=now))
            _down_streak.pop(sid, None)
            continue
        if online:
            # онлайн подтверждает состояние сразу (быстрое восстановление)
            _down_streak.pop(sid, None)
            if not prev.online:
                prev.online = True
                prev.changed_at = now
                transitions.append((sid, True))
        elif prev.online:
            # наблюдаем офлайн, но пока подтверждён онлайн — копим стрик,
            # «падение» объявляем только после N подряд пропусков (антидребезг)
            _down_streak[sid] = _down_streak.get(sid, 0) + 1
            if _down_streak[sid] >= misses:
                prev.online = False
                prev.changed_at = now
                transitions.append((sid, False))
                _down_streak.pop(sid, None)
    # чистим статусы удалённых серверов
    for sid in list(known):
        if sid not in online_map:
            await session.delete(known[sid])
            _down_streak.pop(sid, None)
    await session.commit()

    if not transitions:
        return transitions
    cfg = await settings_store.get_alert_config(session, settings)
    if not alerts_enabled(cfg):
        return transitions
    for sid, online in transitions:
        name = names.get(sid, str(sid))
        text = (
            f"✅ Сервер «{name}» снова онлайн"
            if online
            else f"🔴 Сервер «{name}» недоступен"
        )
        await send_alert(cfg, text)
    return transitions
