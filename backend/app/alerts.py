"""Алерты о падении/восстановлении серверов (Telegram / вебхук)."""

import logging
from datetime import datetime, timedelta, timezone
from html import escape

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app import settings_store
from app.config import Settings
from app.models import ServerStatus

log = logging.getLogger("acontrol.alerts")


def _aware(dt: datetime) -> datetime:
    """SQLite отдаёт наивные datetime — считаем их UTC, чтобы вычитание не падало."""
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def alerts_enabled(cfg: dict) -> bool:
    return bool(
        (cfg.get("telegram_token") and cfg.get("telegram_chat"))
        or cfg.get("webhook")
    )


async def send_alert(cfg: dict, text: str, *, html_text: str | None = None) -> list[str]:
    """Шлёт текст во все настроенные каналы. Возвращает список ошибок (пустой = ок).

    html_text — необязательный HTML-вариант для Telegram (кликабельная ссылка на
    панель). Вебхуку всегда уходит чистый text: тегов он не рендерит. Динамику
    (имена серверов) в html_text обязательно экранировать — иначе имя с «<» или
    «&» сломает разбор у Telegram.
    """
    errors: list[str] = []
    token, chat = cfg.get("telegram_token"), cfg.get("telegram_chat")
    if token and chat:
        # базовый адрес Bot API настраиваемый: для регионов, где api.telegram.org
        # заблокирован, можно указать зеркало/прокси (напр. https://api-tg.example.com)
        base = (cfg.get("telegram_api") or "https://api.telegram.org").rstrip("/")
        url = f"{base}/bot{token}/sendMessage"
        try:
            async with httpx.AsyncClient(timeout=10) as http:
                payload = {
                    "chat_id": chat,
                    "text": html_text or text,
                    "disable_web_page_preview": True,
                }
                if html_text:
                    payload["parse_mode"] = "HTML"
                r = await http.post(url, json=payload)
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
    *,
    now: datetime | None = None,
) -> list[tuple[int, bool]]:
    """Сверяет текущий статус с сохранённым, шлёт алерты на переходах.

    Возвращает список переходов (server_id, online_now).
    Первое наблюдение сервера статус фиксирует, но алерт не шлёт.
    Падением считаем только НЕПРЕРЫВНУЮ недоступность дольше
    settings.server_down_minutes — иначе алерты спамят на сетевых блипах.
    now — для тестов (подменить «сейчас» и проверить срабатывание по времени).
    """
    now = now or datetime.now(timezone.utc)
    grace = timedelta(minutes=max(0, settings.server_down_minutes))
    known = {s.server_id: s for s in await session.scalars(select(ServerStatus))}
    transitions: list[tuple[int, bool]] = []
    for sid, online in online_map.items():
        prev = known.get(sid)
        if prev is None:
            session.add(ServerStatus(server_id=sid, online=online, changed_at=now))
            continue
        if online:
            # онлайн подтверждает состояние сразу (быстрое восстановление) и
            # обнуляет таймер недоступности — серия прервалась
            prev.down_since = None
            if not prev.online:
                prev.online = True
                prev.changed_at = now
                transitions.append((sid, True))
        elif prev.online:
            # Нода молчит, но статус ещё «онлайн». Засекаем начало серии и
            # объявляем падение, только если молчит НЕПРЕРЫВНО дольше grace:
            # короткий сетевой блип не должен будить дежурного.
            if prev.down_since is None:
                prev.down_since = now
            if now - _aware(prev.down_since) >= grace:
                prev.online = False
                prev.changed_at = now
                prev.down_since = None
                transitions.append((sid, False))
    # чистим статусы удалённых серверов
    for sid in list(known):
        if sid not in online_map:
            await session.delete(known[sid])
    await session.commit()

    if not transitions:
        return transitions
    cfg = await settings_store.get_alert_config(session, settings)
    if not alerts_enabled(cfg):
        return transitions
    panel = (getattr(settings, "panel_url", "") or "").rstrip("/")
    mins = max(0, settings.server_down_minutes)
    for sid, online in transitions:
        name = names.get(sid, str(sid))
        if online:
            text = f"✅ Сервер «{name}» снова онлайн"
        else:
            # длительность в тексте — сразу видно, что это не блип, а реальная
            # авария, на которую дежурному надо реагировать
            text = f"🔴 Сервер «{name}» недоступен больше {mins} мин"
        html_text = None
        if panel:
            # имя сервера — кликабельная ссылка на панель (в чат могут писать
            # несколько панелей; экранируем имя, чтобы «<»/«&» не сломали разбор)
            link = f'<a href="{escape(panel)}">{escape(name)}</a>'
            html_text = (
                f"✅ Сервер «{link}» снова онлайн"
                if online
                else f"🔴 Сервер «{link}» недоступен больше {mins} мин"
            )
            text = f"{text}\n{panel}"  # вебхуку/фолбэку — ссылка отдельной строкой
        await send_alert(cfg, text, html_text=html_text)
    return transitions
