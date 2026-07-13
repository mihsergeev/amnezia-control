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
    # ISO 3166-1 alpha-2 (для флажка на карточке); заполняется коллектором по IP
    country: Mapped[str] = mapped_column(String(2), default="")
    last_check_ok: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    last_check_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_check_info: Mapped[str] = mapped_column(Text, default="")
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
    disk_alerted: Mapped[bool] = mapped_column(Boolean, default=False)
    ts: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
