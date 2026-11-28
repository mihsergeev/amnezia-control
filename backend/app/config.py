import re
from functools import lru_cache
from ipaddress import IPv6Address
from urllib.parse import urlsplit

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


DEFAULT_TRUSTED_PROXIES = "127.0.0.0/8 ::1/128 172.16.0.0/12 fd00::/8"
_REGISTRY_HOST = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_REPOSITORY_COMPONENT = re.compile(r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="VPNPANEL_", env_file=".env", hide_input_in_errors=True)

    app_name: str = "Amnezia Control"
    version: str = "0.84.91"
    debug: bool = False

    # Swagger/OpenAPI на /api/docs. Включено: интеграции нужен читаемый контракт
    # /api/v1. Ручки всё равно закрыты (JWT или X-API-Key) — доки раскрывают лишь
    # форму запросов. Выключить: VPNPANEL_API_DOCS=0.
    api_docs: bool = True

    # Проверка стабильных релизов GitHub с экрана «Обзор».
    # Выключить: VPNPANEL_RELEASE_CHECK_ENABLED=false.
    release_check_enabled: bool = True

    db_url: str = "sqlite+aiosqlite:///./data/panel.db"
    data_dir: str = "./data"

    # Внешний IP панели — подставляется в скрипт настройки нод (ufw/hosts.allow)
    panel_ip: str = ""
    ssh_connect_timeout: int = 10

    # Optional registry repository with a verbatim copy of the pinned cascade Xray image.
    xray_registry_mirror: str = ""

    @field_validator("xray_registry_mirror")
    @classmethod
    def validate_xray_registry_mirror(cls, value: str) -> str:
        value = value.strip()
        if not value:
            return ""
        error = ValueError("expected a registry and repository without a scheme, tag, digest or credentials")
        authority, _, repository = value.partition("/")
        if len(value) > 255 or not all(_REPOSITORY_COMPONENT.fullmatch(part) for part in repository.split("/")):
            raise error
        if not re.fullmatch(r"(?:[a-z0-9.-]+|\[[a-f0-9:]+\])(?::[0-9]+)?", authority):
            raise error
        if authority != "localhost" and "." not in authority and ":" not in authority:
            raise error
        try:
            parsed = urlsplit("https://" + authority)
            host, port = parsed.hostname, parsed.port
            if port == 0 or not host:
                raise error
            if authority.startswith("["):
                IPv6Address(host)
            elif not all(_REGISTRY_HOST.fullmatch(label) for label in host.split(".")):
                raise error
        except ValueError:
            raise error from None
        return value

    # Дефолтный SSH-пользователь для новых серверов (предзаполняет форму)
    default_ssh_user: str = "acontrol"

    # DNS в выдаваемых клиентских конфигах AmneziaWG
    awg_client_dns: str = "1.1.1.1, 1.0.0.1"

    # Сбор метрик: интервал в секундах (0 = выключить), хранение снимков в днях.
    # Держим 90 дней: столько же — максимальный диапазон графиков на «Обзоре»
    # (общих снимков ~1 строка/сервер/интервал — сотни тысяч строк, копейки).
    stats_interval: int = 300
    stats_retention_days: int = 90
    # Хранение пер-клиентских снимков трафика (их много) — короче общего
    client_stats_retention_days: int = 14
    # Хранение журнала действий в днях (0 = вечно)
    audit_retention_days: int = 365
    # Адреса своих обратных прокси, которым верим в X-Forwarded-For: loopback
    # и docker-сети (caddy, nginx фронтенда). Клиентские сети сюда не входят.
    # Пусто - тот же список по умолчанию (compose передает пустую строку).
    # `!<адрес>` исключает адрес, `!gateway` - шлюз docker-сети (см. clientip).
    trusted_proxies: str = ""
    # Адрес публикации панели (ACONTROL_BIND). Не loopback - шлюзу docker-сети
    # не верим: через него идут IPv6-клиенты L4 docker-proxy с любым XFF.
    panel_bind: str = ""

    # Авто-бэкап БД: интервал в часах (0 = выключить), сколько копий хранить
    backup_interval_hours: int = 24
    backup_keep: int = 14
    # история трафика (client_traffic_samples/traffic_samples) — сотни МБ и
    # некритична (регенерируется). По умолчанию НЕ кладём в бэкап: тогда архив
    # весит килобайты и его удобно скачивать/хранить офсайт. Включить = полный дамп.
    backup_include_traffic: bool = False

    # Авто-отзыв истёкших клиентов: интервал в секундах (0 = выключить)
    expiry_interval: int = 300
    # За сколько дней до истечения слать предупреждающий алерт (0 = выключить)
    expiry_warn_days: int = 3

    # Сколько минут нода должна быть НЕПРЕРЫВНО недоступна, прежде чем поднять
    # алерт. Порог во ВРЕМЕНИ, а не в циклах сбора — не «поедет» при смене
    # stats_interval. Короткие сетевые блипы (нода вернулась через 2-3 минуты)
    # дежурного будить не должны: алерт шлём только когда реально нужно
    # вмешательство. 0 = алертить с первого же пропуска (без антидребезга).
    server_down_minutes: int = 30
    # Каскад: сколько минут трафик через выход должен не идти НЕПРЕРЫВНО, прежде
    # чем поднять алерт (проверка раз в 2 минуты). Меньше, чем у серверов:
    # клиенты в это время без зарубежных сайтов. -1 = не проверять.
    cascade_down_minutes: int = 10

    # Алерты о падении серверов (Telegram / вебхук)
    alert_telegram_token: str = ""
    alert_telegram_chat: str = ""
    alert_webhook: str = ""

    # Публичный URL панели — пишется в пульс, чтобы хостовый watchdog называл
    # КОНКРЕТНУЮ панель со ссылкой (когда в один чат шлют 2-3 панели — видно, чья).
    panel_url: str = ""

    # Алерт «мало места на диске ноды»: порог в % (0 = выключить)
    disk_alert_percent: int = 90

    # Алерт «на ноде пропали клиенты» (адрес режут у провайдеров, а сервер
    # отвечает): активных за 2 часа не больше этого % от того же окна неделю
    # назад и вчера (0 = выключить). Ноды, где тогда было меньше min_clients
    # активных, не проверяем: на паре клиентов любая тишина выглядит провалом.
    online_drop_percent: int = 35
    online_drop_min_clients: int = 8

    jwt_secret: str = "dev-insecure-change-me"
    jwt_ttl_minutes: int = 12 * 60

    # Начальная учётка админа (сидируется при первом старте; далее пароль
    # меняется в UI и из .env НЕ пересинхронизируется)
    admin_user: str = "admin"
    admin_password: str = "admin"

    # Аварийный сброс (break-glass): при VPNPANEL_ADMIN_PASSWORD_RESET=1 старт
    # сбрасывает пароль админа на admin_password и отключает 2FA. Убрать флаг
    # из .env после входа. Нужно, если потерян пароль И 2FA.
    admin_password_reset: bool = False


@lru_cache
def get_settings() -> Settings:
    return Settings()
