"""Одноразовые ссылки на конфиг клиента через self-hosted сервисы секретов.

Вместо того чтобы слать конфиг файлом в мессенджер (где он останется
навсегда), панель кладет его в сервис секретов и отдает ссылку: открыть ее
можно один раз, через неделю она сгорит сама.

Поддерживаются два движка, оба без ключа API:
  sup3rs3cret - sup3rS3cretMes5age (POST /secret, ссылка /getmsg?token=...)
  pwpush      - Password Pusher (POST /api/v2/pushes, ссылка /p/<token>/r)
Движок определяется по самому сервису при добавлении (detect_engine)."""

import asyncio
import json
from urllib.parse import quote, urlsplit, urlunsplit

import httpx

ENGINES = ("sup3rs3cret", "pwpush")
TTL_DAYS = 7  # сколько живет ссылка, если ее никто не открыл
TIMEOUT = 15
# Таймаут httpx действует на каждую фазу отдельно: сервис, отдающий ответ по
# байту, держал бы запрос бесконечно. Общий срок и потолок размера ответа -
# сверху (ответы обоих движков - короткий JSON или страница).
TOTAL_TIMEOUT = 25
MAX_RESPONSE = 256 * 1024


class ShareError(Exception):
    """Сервис не ответил или ответил не тем (текст - для пользователя)."""


def public_url(url: str) -> str:
    """URL без старых Basic Auth credentials, для ссылок, UI и журнала."""
    try:
        parts = urlsplit(url)
    except ValueError as exc:
        raise ShareError("неверный адрес сервиса") from exc
    return urlunsplit(parts._replace(netloc=parts.netloc.rsplit("@", 1)[-1]))


def insecure(url: str) -> bool:
    """Сервис без TLS: конфиг с ключом идет к нему и к получателю открытым текстом."""
    return urlsplit(url).scheme == "http"


class _Reply:
    """Прочитанный с потолком ответ сервиса."""

    def __init__(self, status_code: int, body: bytes, encoding: str | None) -> None:
        self.status_code = status_code
        self.body = body
        self.encoding = encoding or "utf-8"

    @property
    def text(self) -> str:
        return self.body.decode(self.encoding, errors="replace")

    def json(self):
        return json.loads(self.body)


async def _send(http: httpx.AsyncClient, method: str, url: str, **kwargs) -> _Reply:
    try:
        async with asyncio.timeout(TOTAL_TIMEOUT):
            async with http.stream(method, url, follow_redirects=False, **kwargs) as r:
                body = bytearray()
                async for chunk in r.aiter_bytes():
                    body += chunk
                    if len(body) > MAX_RESPONSE:
                        raise ShareError("сервис ответил слишком большим ответом")
                return _Reply(r.status_code, bytes(body), r.encoding)
    except TimeoutError as exc:
        raise ShareError("сервис не отвечает") from exc


def _check_status(r: _Reply) -> None:
    if not 200 <= r.status_code < 300:
        raise ShareError(f"сервис ответил {r.status_code}")


def normalize_url(url: str) -> str:
    """Адрес сервиса -> его origin (https://host[:port]): путь вроде /msg не нужен."""
    try:
        parts = urlsplit(url.strip())
        port = parts.port
        parsed = httpx.URL(url.strip())
    except (ValueError, httpx.InvalidURL) as exc:
        raise ShareError("нужен адрес вида https://secret.example.com") from exc
    if (parts.scheme not in ("http", "https") or not parts.hostname
            or any(ch.isspace() for ch in parts.netloc) or "\\" in parts.netloc
            or not parsed.host or port == 0):
        raise ShareError("нужен адрес вида https://secret.example.com")
    if parts.username is not None or parts.password is not None:
        # Origin хранится в настройках и журнале. Не принимаем URL, который
        # превратит пароль Basic Auth в обычный текст журнала и списка сервисов.
        raise ShareError("логин и пароль в адресе сервиса не поддерживаются")
    return str(parsed.copy_with(path="", query=None, fragment=None))


async def detect_engine(base: str, client: httpx.AsyncClient | None = None) -> str:
    async with _client(client) as http:
        try:
            r = await _send(http, "GET", f"{base}/api/v2/version")
            if r.status_code == 200 and isinstance(r.json(), dict) and "application_version" in r.json():
                return "pwpush"
        except (httpx.HTTPError, ValueError, ShareError):
            pass
        try:
            r = await _send(http, "GET", f"{base}/msg")
            if r.status_code == 200 and "sup3rS3cretMes5age" in r.text:
                return "sup3rs3cret"
        except httpx.HTTPError as exc:
            raise ShareError("сервис не отвечает") from exc
    raise ShareError("не похоже ни на sup3rS3cretMes5age, ни на Password Pusher")


async def create_link(
    engine: str, base: str, text: str, client: httpx.AsyncClient | None = None
) -> str:
    """Кладет text в сервис как одноразовый секрет, возвращает ссылку на него."""
    async with _client(client) as http:
        try:
            if engine == "sup3rs3cret":
                r = await _send(
                    http, "POST", f"{base}/secret",
                    files={"msg": (None, text), "ttl": (None, f"{TTL_DAYS * 24}h")},
                )
                _check_status(r)
                data = r.json()
                token = data.get("token") if isinstance(data, dict) else None
                if not isinstance(token, str) or not token:
                    raise ShareError("сервис не вернул токен")
                return f"{public_url(base)}/getmsg?token={quote(token, safe='')}"
            if engine == "pwpush":
                r = await _send(
                    http, "POST", f"{base}/api/v2/pushes",
                    json={"push": {
                        "payload": text,
                        "expire_after_days": TTL_DAYS,
                        "expire_after_views": 1,
                    }},
                )
                _check_status(r)
                data = r.json()
                if not isinstance(data, dict):
                    raise ShareError("сервис не вернул ссылку")
                if isinstance(data.get("url_token"), str) and data["url_token"]:
                    return f"{public_url(base)}/p/{quote(data['url_token'], safe='')}/r"
                if isinstance(data.get("html_url"), str) and data["html_url"]:
                    url = public_url(data["html_url"])
                    if normalize_url(url) != normalize_url(public_url(base)):
                        raise ShareError("ссылка ведет на другой сервис")
                    return url
                raise ShareError("сервис не вернул ссылку")
        except httpx.HTTPError as exc:
            # Исключение может содержать полный URL со старыми credentials.
            raise ShareError("сервис не отвечает") from exc
        except ValueError as exc:
            raise ShareError("сервис ответил не JSON") from exc
    raise ShareError(f"неизвестный движок {engine}")


def _client(client: httpx.AsyncClient | None):
    if client is not None:
        return _Borrowed(client)
    return httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=False)


class _Borrowed:
    """Чужой клиент (тесты): не закрываем его на выходе."""

    def __init__(self, client: httpx.AsyncClient) -> None:
        self.client = client

    async def __aenter__(self) -> httpx.AsyncClient:
        return self.client

    async def __aexit__(self, *args) -> bool:
        return False
