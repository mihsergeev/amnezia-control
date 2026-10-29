"""Алерты о падении/восстановлении серверов (Telegram / вебхук)."""

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from html import escape
from urllib.parse import urlsplit

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


LEVEL = {"crit": "🔴", "warn": "⚠️", "ok": "✅", "info": "🔔"}

# Английские тексты алертов по русскому шаблону (язык - в настройках алертов).
# Причины отказа каскада совпадают с cascade.health() и подсказками во фронте.
EN = {
    "Сервер снова онлайн": "Server is back online",
    "Сервер недоступен больше {mins} мин": "Server unreachable for over {mins} min",
    "Каскад не работает больше {mins} мин": "Cascade down for over {mins} min",
    "Каскад снова работает": "Cascade works again",
    "Каскад не собрался": "Cascade install failed",
    "{reason}, выход {exit}": "{reason}, exit {exit}",
    "выход {exit}": "exit {exit}",
    "шлюз на входе не запущен": "the gateway on the entry is not running",
    "нет GRE-туннеля": "no GRE tunnel",
    "GRE-туннель выключен": "GRE tunnel is down",
    "клиенты идут мимо шлюза (tproxy выключен)": "clients bypass the gateway (tproxy is off)",
    "через выход интернет не открывается": "no internet through the exit",
    "Сменился SSH-ключ сервера": "Server SSH host key changed",
    "возможна подмена. Если сервер пересоздавали, удалите его строку из data/ssh/known_hosts":
        "possible spoofing. If the server was rebuilt, remove its line from data/ssh/known_hosts",
    "Мало места: диск занят на {pct}%": "Low disk space: {pct}% used",
    "Место на диске снова есть": "Disk space is fine again",
    "занято {pct}%": "{pct}% used",
    "Пропали клиенты": "Clients are gone",
    "Клиент качает торренты": "A client is downloading torrents",
    "{name}, {proto}: {hits} попыток за {mins} мин, торренты на сервере блокируются":
        "{name}, {proto}: {hits} attempts in {mins} min, torrents are blocked on the server",
    "{detail}. Клиент поставлен на паузу": "{detail}. The client is paused",
    "{detail}. Паузу поставить не вышло: {err}": "{detail}. Could not pause: {err}",
    "активных за 2 часа {cur}, вчера {yday}, неделю назад {week}. Сервер отвечает, "
    "похоже, адрес режут провайдеры":
        "active in 2 hours: {cur}, yesterday {yday}, a week ago {week}. The server answers, "
        "ISPs are probably blocking its address",
    "Подбор пароля к панели": "Panel password guessing",
    "{n} неудачных входов подряд с {ip}, адрес временно заблокирован":
        "{n} failed logins in a row from {ip}, the address is blocked for a while",
    "Подбор пароля к «{user}»": "Password guessing for \"{user}\"",
    "{n} неудачных входов с разных адресов, логин временно заблокирован":
        "{n} failed logins from different addresses, the login is blocked for a while",
    "Сменен пароль «{user}»": "Password changed for \"{user}\"",
    "Включена 2FA у «{user}»": "2FA enabled for \"{user}\"",
    "Отключена 2FA у «{user}»": "2FA disabled for \"{user}\"",
    "с {ip}": "from {ip}",
    "{user} с {ip}": "{user} from {ip}",
    "Скачан бэкап панели": "Panel backup downloaded",
    "Скачан бэкап панели {name}": "Panel backup {name} downloaded",
    "Панель восстановлена из бэкапа": "Panel restored from a backup",
    "Авто-бэкап снова проходит": "Auto-backup works again",
    "самопроверка ок": "self-test passed",
    "Авто-бэкап не создан": "Auto-backup failed",
    "{err}. Проверьте место на диске и логи backend": "{err}. Check disk space and the backend logs",
    "Бэкап не прошел самопроверку": "Backup failed its self-test",
    "{problems}. Восстановиться из него может не выйти": "{problems}. Restoring from it may fail",
    "Пароль «{user}» сброшен из .env": "Password for \"{user}\" reset from .env",
    "2FA отключена. Уберите флаг сброса из .env, иначе это повторится при каждом перезапуске":
        "2FA is off. Remove the reset flag from .env, or this repeats on every restart",
    "Развертывание {proto} не удалось": "{proto} deployment failed",
    "лог в карточке сервера": "the log is in the server card",
    "Клиент истек, но не отозван": "Client expired but not revoked",
    "{client}: сервер недоступен, повторю позже": "{client}: the server is unreachable, will retry",
    "Клиент истекает через {days} дн.": "Client expires in {days} d",
    "{client}, {at} UTC. Не продлить - отключится сам":
        "{client}, {at} UTC. Extend it or it is revoked automatically",
    "Тестовый алерт": "Test alert",
    "канал работает": "the channel works",
}


@dataclass
class T:
    """Текст алерта: русский шаблон и параметры, переводится при отправке.
    Обычная строка (текст ошибки, имя) идет как есть, без подстановки."""

    text: str
    kw: dict


def t(text: str, **kw) -> T:
    return T(text, kw)


def _text(value, lang: str) -> str:
    if not isinstance(value, T):
        return str(value)
    template = EN.get(value.text, value.text) if lang == "en" else value.text
    return template.format(**{k: _text(v, lang) for k, v in value.kw.items()})


@dataclass
class Card:
    """Алерт карточкой: строка 1 - уровень, тема и о чем (сервер или панель),
    строка 2 - что случилось, строка 3 - подробность. subject пусто - сама панель."""

    level: str  # crit | warn | ok | info
    icon: str  # тема: 🖥 сервер, 💾 диск, 🔑 доступ и т.п.; у каскада без иконки
    title: "T | str"
    detail: "T | str" = ""
    subject: str = ""

    def render(self, panel_url: str = "", lang: str = "ru") -> tuple[str, str]:
        """(текст для вебхука, HTML для Telegram)."""
        panel = (panel_url or "").rstrip("/")
        subject = self.subject or urlsplit(panel).hostname or "Amnezia Control"
        head = f"{LEVEL.get(self.level, '')}{self.icon}"
        title, detail = _text(self.title, lang), _text(self.detail, lang)
        plain = [f"{head} {subject}", title]
        link = (
            f'<a href="{escape(panel)}">{escape(subject)}</a>' if panel else escape(subject)
        )
        html = [f"{head} {link}", f"<b>{escape(title)}</b>"]
        if detail:
            plain.append(detail)
            html.append(escape(detail))
        if panel:
            plain.append(panel)  # вебхуку ссылка отдельной строкой
        return "\n".join(plain), "\n".join(html)


async def send_card(cfg: dict, settings: Settings, card: Card) -> list[str]:
    text, html_text = card.render(getattr(settings, "panel_url", ""), cfg.get("lang") or "ru")
    return await send_alert(cfg, text, html_text=html_text)


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
            # текст ошибки httpx содержит URL запроса, а в нем токен бота -
            # в журнал и лог он попадать не должен
            msg = str(exc).replace(token, "***") if token else str(exc)
            errors.append(f"Telegram: {msg}")
            log.warning("Telegram-алерт не отправлен: %s", msg)

    if cfg.get("webhook"):
        try:
            async with httpx.AsyncClient(timeout=10) as http:
                r = await http.post(cfg["webhook"], json={"text": text})
                r.raise_for_status()
        except Exception as exc:  # noqa: BLE001
            errors.append(f"Webhook: {exc}")
            log.warning("Вебхук-алерт не отправлен: %s", exc)
    return errors


async def maybe_alert(session_factory, settings: Settings, card: Card) -> None:
    """Разовый алерт (бэкап упал, отзыв отложен, клиент скоро истекает и т.п.):
    открывает свою сессию, шлёт если каналы настроены. Best-effort."""
    try:
        async with session_factory() as session:
            cfg = await settings_store.get_alert_config(session, settings)
        if alerts_enabled(cfg):
            await send_card(cfg, settings, card)
    except Exception:  # noqa: BLE001 — алерт не должен ронять вызывающий цикл
        log.warning("разовый алерт не отправлен", exc_info=True)


async def security_alert(session: AsyncSession, settings: Settings, card: Card) -> None:
    """Шлёт security-событие (брутфорс, смена host-ключа, смена пароля и т.п.)
    во все настроенные каналы. Best-effort — не роняет вызывающую операцию."""
    try:
        cfg = await settings_store.get_alert_config(session, settings)
        if alerts_enabled(cfg):
            await send_card(cfg, settings, card)
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
    mins = max(0, settings.server_down_minutes)
    for sid, online in transitions:
        name = names.get(sid, str(sid))
        # длительность в тексте — сразу видно, что это не блип, а реальная авария
        card = (
            Card("ok", "🖥", t("Сервер снова онлайн"), subject=name)
            if online
            else Card("crit", "🖥", t("Сервер недоступен больше {mins} мин", mins=mins), subject=name)
        )
        await send_card(cfg, settings, card)
    return transitions
