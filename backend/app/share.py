"""Одноразовые ссылки на конфиг клиента через self-hosted сервисы секретов.

Вместо того чтобы слать конфиг файлом в мессенджер (где он останется
навсегда), панель кладет его в сервис секретов и отдает ссылку: открыть ее
можно один раз, через неделю она сгорит сама.

Поддерживаются два движка, оба без ключа API:
  sup3rs3cret - sup3rS3cretMes5age (POST /secret, ссылка /getmsg?token=...)
  pwpush      - Password Pusher (POST /api/v2/pushes, ссылка /p/<token>/r)
Движок определяется по самому сервису при добавлении (detect_engine)."""

from urllib.parse import quote, urlsplit

import httpx

ENGINES = ("sup3rs3cret", "pwpush")
TTL_DAYS = 7  # сколько живет ссылка, если ее никто не открыл
TIMEOUT = 15
MAX_TEXT = 100_000


class ShareError(Exception):
    """Сервис не ответил или ответил не тем (текст - для пользователя)."""


def normalize_url(url: str) -> str:
    """Адрес сервиса -> его origin (https://host[:port]): путь вроде /msg не нужен."""
    parts = urlsplit(url.strip())
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ShareError("нужен адрес вида https://secret.example.com")
    return f"{parts.scheme}://{parts.netloc}"


async def detect_engine(base: str, client: httpx.AsyncClient | None = None) -> str:
    async with _client(client) as http:
        try:
            r = await http.get(f"{base}/api/v2/version")
            if r.status_code == 200 and "application_version" in r.json():
                return "pwpush"
        except (httpx.HTTPError, ValueError):
            pass
        try:
            r = await http.get(f"{base}/msg")
            if r.status_code == 200 and "sup3rS3cretMes5age" in r.text:
                return "sup3rs3cret"
        except httpx.HTTPError as exc:
            raise ShareError(f"сервис не отвечает: {exc}") from exc
    raise ShareError("не похоже ни на sup3rS3cretMes5age, ни на Password Pusher")


async def create_link(
    engine: str, base: str, text: str, client: httpx.AsyncClient | None = None
) -> str:
    """Кладет text в сервис как одноразовый секрет, возвращает ссылку на него."""
    async with _client(client) as http:
        try:
            if engine == "sup3rs3cret":
                r = await http.post(
                    f"{base}/secret",
                    files={"msg": (None, text), "ttl": (None, f"{TTL_DAYS * 24}h")},
                )
                r.raise_for_status()
                token = r.json().get("token")
                if not token:
                    raise ShareError("сервис не вернул токен")
                return f"{base}/getmsg?token={quote(token, safe='')}"
            if engine == "pwpush":
                r = await http.post(
                    f"{base}/api/v2/pushes",
                    json={"push": {
                        "payload": text,
                        "expire_after_days": TTL_DAYS,
                        "expire_after_views": 1,
                    }},
                )
                r.raise_for_status()
                data = r.json()
                if data.get("html_url"):
                    return data["html_url"]
                if data.get("url_token"):
                    return f"{base}/p/{quote(data['url_token'], safe='')}/r"
                raise ShareError("сервис не вернул ссылку")
        except httpx.HTTPStatusError as exc:
            raise ShareError(f"сервис ответил {exc.response.status_code}") from exc
        except httpx.HTTPError as exc:
            raise ShareError(f"сервис не отвечает: {exc}") from exc
        except ValueError as exc:
            raise ShareError("сервис ответил не JSON") from exc
    raise ShareError(f"неизвестный движок {engine}")


def _client(client: httpx.AsyncClient | None):
    if client is not None:
        return _Borrowed(client)
    return httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True)


class _Borrowed:
    """Чужой клиент (тесты): не закрываем его на выходе."""

    def __init__(self, client: httpx.AsyncClient) -> None:
        self.client = client

    async def __aenter__(self) -> httpx.AsyncClient:
        return self.client

    async def __aexit__(self, *args) -> bool:
        return False
