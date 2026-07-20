from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="VPNPANEL_", env_file=".env")

    app_name: str = "Amnezia Control"
    version: str = "0.45.0"
    debug: bool = False

    db_url: str = "sqlite+aiosqlite:///./data/panel.db"
    data_dir: str = "./data"

    # Внешний IP панели — подставляется в скрипт настройки нод (ufw/hosts.allow)
    panel_ip: str = ""
    ssh_connect_timeout: int = 10

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

    # Алерты о падении серверов (Telegram / вебхук)
    alert_telegram_token: str = ""
    alert_telegram_chat: str = ""
    alert_webhook: str = ""

    # Публичный URL панели — пишется в пульс, чтобы хостовый watchdog называл
    # КОНКРЕТНУЮ панель со ссылкой (когда в один чат шлют 2-3 панели — видно, чья).
    panel_url: str = ""

    # Алерт «мало места на диске ноды»: порог в % (0 = выключить)
    disk_alert_percent: int = 90

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
