from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Float,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    password_hash: Mapped[str] = mapped_column(String(128))
    totp_secret: Mapped[str] = mapped_column(String(64), default="")
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    # последний использованный TOTP-счётчик (защита от повторного использования кода)
    totp_last_counter: Mapped[int] = mapped_column(BigInteger, default=0)
    # версия токена: смена пароля инкрементит её и инвалидирует старые JWT
    token_version: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class Server(Base):
    __tablename__ = "servers"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    host: Mapped[str] = mapped_column(String(255))
    ssh_port: Mapped[int] = mapped_column(Integer, default=22)
    ssh_user: Mapped[str] = mapped_column(String(64), default="root")
    note: Mapped[str] = mapped_column(Text, default="")
    group_name: Mapped[str] = mapped_column(String(64), default="")
    # ручной порядок карточек (drag-and-drop); в пределах группы и порядок групп
    # выводятся из позиции: группы сортируются по минимальной позиции участника
    position: Mapped[int] = mapped_column(Integer, default=0)
    # ISO 3166-1 alpha-2 (для флажка на карточке); заполняется коллектором по IP
    country: Mapped[str] = mapped_column(String(2), default="")
    # адрес, с которого клиенты VPN выходят в интернет, если он НЕ совпадает с
    # адресом сервера (нода - вход каскада/туннеля). Пусто - выход напрямую или
    # еще не проверяли. Снимается изнутри amnezia-контейнера (sshops.EGRESS_COMMAND)
    egress_ip: Mapped[str] = mapped_column(String(45), default="")
    egress_country: Mapped[str] = mapped_column(String(2), default="")
    egress_org: Mapped[str] = mapped_column(String(128), default="")
    egress_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_check_ok: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    last_check_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_check_info: Mapped[str] = mapped_column(Text, default="")
    # блокировка торрентов в контейнерах AWG/OpenVPN (app/torrent.py) и пауза
    # клиента, который их качает
    torrent_block: Mapped[bool] = mapped_column(Boolean, default=False)
    torrent_autopause: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class AwgConfig(Base):
    """Сохранённый выданный клиентский конфиг — чтобы показать QR/скачать заново."""

    __tablename__ = "awg_configs"
    __table_args__ = (UniqueConstraint("server_id", "public_key"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    server_id: Mapped[int] = mapped_column(Integer, index=True)
    public_key: Mapped[str] = mapped_column(String(64))
    name: Mapped[str] = mapped_column(String(128))
    config: Mapped[str] = mapped_column(Text)
    # awg | awg3 | awglegacy: таблица общая для всех AWG, и без протокола поиск
    # и массовый отзыв считали клиента 3.1/Legacy клиентом 2.0
    protocol: Mapped[str] = mapped_column(String(16), default="awg", server_default="awg")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class OvpnConfig(Base):
    """Сохранённый vpn:// OpenVPN-клиента (приватный ключ живёт только тут)."""

    __tablename__ = "ovpn_configs"
    __table_args__ = (UniqueConstraint("server_id", "client_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    server_id: Mapped[int] = mapped_column(Integer, index=True)
    client_id: Mapped[str] = mapped_column(String(64))
    name: Mapped[str] = mapped_column(String(128))
    config_amnezia: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class TrafficSample(Base):
    """Снимок статистики сервера (снимается фоновым сборщиком) для графиков."""

    __tablename__ = "traffic_samples"

    id: Mapped[int] = mapped_column(primary_key=True)
    server_id: Mapped[int] = mapped_column(Integer, index=True)
    ts: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    rx_total: Mapped[int] = mapped_column(BigInteger, default=0)
    tx_total: Mapped[int] = mapped_column(BigInteger, default=0)
    clients_total: Mapped[int] = mapped_column(Integer, default=0)
    clients_online: Mapped[int] = mapped_column(Integer, default=0)


class ClientLimit(Base):
    """Ограничение клиента: срок действия (по истечении — авто-отзыв)."""

    __tablename__ = "client_limits"
    __table_args__ = (UniqueConstraint("server_id", "protocol", "client_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    server_id: Mapped[int] = mapped_column(Integer, index=True)
    protocol: Mapped[str] = mapped_column(String(16))  # awg | openvpn | xray
    client_id: Mapped[str] = mapped_column(String(64))
    name: Mapped[str] = mapped_column(String(128), default="")
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class AuditLog(Base):
    """Журнал действий: кто/когда/что сделал (выдача, отзыв, деплой, и т.п.)."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    username: Mapped[str] = mapped_column(String(64), default="")
    action: Mapped[str] = mapped_column(String(48))
    target: Mapped[str] = mapped_column(String(255), default="")
    detail: Mapped[str] = mapped_column(Text, default="")


class AwgNote(Base):
    """Панельная заметка к клиенту любого протокола (работает и для клиентов,
    созданных вне панели). Имя таблицы историческое (awg_notes), но protocol
    делает её общей для awg/openvpn/xray. public_key = client_id клиента."""

    __tablename__ = "awg_notes"
    __table_args__ = (UniqueConstraint("server_id", "protocol", "public_key"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    server_id: Mapped[int] = mapped_column(Integer, index=True)
    protocol: Mapped[str] = mapped_column(String(16), default="awg")
    public_key: Mapped[str] = mapped_column(String(64))
    note: Mapped[str] = mapped_column(Text, default="")
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class ServerStatus(Base):
    """Последний известный online/offline статус сервера — для алертов о падении."""

    __tablename__ = "server_status"

    server_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    online: Mapped[bool] = mapped_column(Boolean)
    changed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    # Момент ПЕРВОГО наблюдения офлайна в текущей серии (сбрасывается, как только
    # нода ответила). Пока статус ещё «online», это таймер антидребезга: падением
    # считаем лишь непрерывную недоступность дольше server_down_minutes. В БД, а не
    # в памяти — чтобы рестарт панели не обнулял отсчёт посреди реальной аварии.
    down_since: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )
    # Алерт «пропали клиенты» (onlinedrop): когда отправлен последний и идет ли
    # еще эта просадка. В БД, а не в памяти - иначе каждый рестарт панели
    # (релиз) заново слал алерт про ту же самую просадку.
    drop_alerted: Mapped[bool] = mapped_column(Boolean, default=False)
    drop_alerted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )


class AppSetting(Base):
    """Настройки панели (key-value), редактируемые из UI. Значение — строка/JSON."""

    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text, default="")


class ClientTrafficSample(Base):
    """Снимок кумулятивного трафика клиента (для графика по клиенту)."""

    __tablename__ = "client_traffic_samples"
    __table_args__ = (
        Index("ix_cts_lookup", "server_id", "protocol", "client_id", "ts"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    server_id: Mapped[int] = mapped_column(Integer, index=True)
    protocol: Mapped[str] = mapped_column(String(16))
    client_id: Mapped[str] = mapped_column(String(64))
    rx: Mapped[int] = mapped_column(BigInteger, default=0)
    tx: Mapped[int] = mapped_column(BigInteger, default=0)
    ts: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )


class ClientName(Base):
    """Кэш имён клиентов, снятых с ноды (clientsTable) — чтобы в статистике
    показывать имена даже для клиентов, созданных не через панель (bulk / на ноде).
    Наполняется сборщиком; одна строка на клиента (не тайм-серия)."""

    __tablename__ = "client_names"
    __table_args__ = (UniqueConstraint("server_id", "protocol", "client_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    server_id: Mapped[int] = mapped_column(Integer, index=True)
    protocol: Mapped[str] = mapped_column(String(16))
    client_id: Mapped[str] = mapped_column(String(64))
    name: Mapped[str] = mapped_column(String(128), default="")
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class PausedClient(Base):
    """Клиент «на паузе»: снят с сервера (не может подключиться), но его данные
    сохранены, чтобы возобновить без пересоздания. data — JSON с протокол-
    специфичной нагрузкой для восстановления (IP у awg, dict клиента у xray)."""

    __tablename__ = "paused_clients"
    __table_args__ = (UniqueConstraint("server_id", "protocol", "client_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    server_id: Mapped[int] = mapped_column(Integer, index=True)
    protocol: Mapped[str] = mapped_column(String(16))
    client_id: Mapped[str] = mapped_column(String(64))
    name: Mapped[str] = mapped_column(String(128), default="")
    data: Mapped[str] = mapped_column(Text, default="")  # JSON restore payload
    paused_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class TorrentHit(Base):
    """Клиент, у которого правила app/torrent.py ловили торрент-трафик: сколько
    раз всего, когда впервые и в последний раз, когда о нем был алерт."""

    __tablename__ = "torrent_hits"
    __table_args__ = (UniqueConstraint("server_id", "protocol", "client_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    server_id: Mapped[int] = mapped_column(Integer, index=True)
    protocol: Mapped[str] = mapped_column(String(16))
    client_id: Mapped[str] = mapped_column(String(64))
    name: Mapped[str] = mapped_column(String(128), default="")
    hits: Mapped[int] = mapped_column(Integer, default=0)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    alerted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class NodeMetric(Base):
    """Последний снимок ресурсов ноды (CPU/RAM/диск/аптайм) — для карточек и алертов."""

    __tablename__ = "node_metrics"

    server_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cpu_count: Mapped[int] = mapped_column(Integer, default=0)
    load1: Mapped[float] = mapped_column(Float, default=0.0)
    mem_total: Mapped[int] = mapped_column(BigInteger, default=0)
    mem_used: Mapped[int] = mapped_column(BigInteger, default=0)
    disk_total: Mapped[int] = mapped_column(BigInteger, default=0)
    disk_used: Mapped[int] = mapped_column(BigInteger, default=0)
    uptime_seconds: Mapped[int] = mapped_column(BigInteger, default=0)
    # счетчики /proc/stat прошлого снимка и загрузка CPU между снимками, %
    # (None - первый снимок или нода перезагрузилась); psi_cpu - PSI some avg60
    cpu_busy: Mapped[int] = mapped_column(BigInteger, default=0)
    cpu_total: Mapped[int] = mapped_column(BigInteger, default=0)
    cpu_pct: Mapped[float | None] = mapped_column(Float, nullable=True)
    psi_cpu: Mapped[float | None] = mapped_column(Float, nullable=True)
    disk_alerted: Mapped[bool] = mapped_column(Boolean, default=False)
    ts: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class ApiKey(Base):
    """Ключ интеграционного API (/api/v1) — для машин, не для людей.

    Хранится ТОЛЬКО хэш секрета (bcrypt), как пароль: утечка БД не даёт рабочих
    ключей. Полный ключ показывается один раз при создании. `prefix` — открытая
    часть для быстрого поиска строки без перебора хэшей всей таблицы и для
    опознания ключа в UI/логах. Права ключа фиксированы и узки: клиентские
    операции AmneziaWG + чтение списка серверов (ни деплоя, ни full-access).
    """

    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(120))
    prefix: Mapped[str] = mapped_column(String(16), unique=True, index=True)
    key_hash: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    last_used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    # Ограничения ключа: срок действия (None = бессрочно) и серверы, с которыми
    # он работает (id через запятую, пусто = все). Без них ключ интеграции
    # видел все серверы и все приватные конфиги и жил вечно.
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )
    servers: Mapped[str] = mapped_column(Text, default="", server_default="")

    @property
    def server_ids(self) -> list[int]:
        return [int(x) for x in (self.servers or "").split(",") if x.strip().isdigit()]

    def allows(self, server_id: int) -> bool:
        ids = self.server_ids
        return not ids or int(server_id) in ids


class Cascade(Base):
    """Каскад: клиенты подключаются ко входу, в интернет выходят с адреса выхода
    (см. app/cascade.py). Сервер бывает только в одном каскаде."""

    __tablename__ = "cascades"

    id: Mapped[int] = mapped_column(primary_key=True)
    entry_server_id: Mapped[int] = mapped_column(Integer, unique=True)
    exit_server_id: Mapped[int] = mapped_column(Integer, unique=True)
    # vless | gre
    transport: Mapped[str] = mapped_column(String(16))
    # installing | ready | error
    status: Mapped[str] = mapped_column(String(16), default="installing")
    error: Mapped[str] = mapped_column(Text, default="")
    # ключи VLESS, порт, адреса сторон на момент установки (JSON)
    params: Mapped[str] = mapped_column(Text, default="{}")
    # последняя проверка канала до установки и проверка через шлюз после (JSON)
    probe: Mapped[str] = mapped_column(Text, default="{}")
    result: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
