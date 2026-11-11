import re
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Annotated, Literal
from uuid import UUID

import idna
from pydantic import AfterValidator, BaseModel, ConfigDict, Field, computed_field, field_validator, model_validator


from app.cascade_routes import Route, RouteUpdate
from app.client_endpoint import normalize as normalize_client_endpoint
from app.geo import normalize_country_code
from app.metadata_schemas import ClientLabels
from app.xray import STATS_API_PORT


class LoginRequest(BaseModel):
    # длина ограничена: логин уходит в ключ лимитера, и мегабайтные логины
    # раздували бы его память
    username: str = Field(max_length=128)
    password: str = Field(max_length=128)
    otp: str | None = Field(default=None, max_length=16)


class TwoFAStatusOut(BaseModel):
    enabled: bool


class TwoFASetupOut(BaseModel):
    secret: str
    otpauth_uri: str


class TwoFAVerifyRequest(BaseModel):
    otp: str = Field(min_length=1, max_length=16)
    # включение и выключение 2FA - с повторным вводом пароля: иначе укравший
    # токен включил бы 2FA со своим секретом и запер настоящего админа
    password: str = Field(min_length=1, max_length=128)


class PasswordChangeRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=8, max_length=128)


class StepUpRequest(BaseModel):
    """Повторный ввод пароля для опасного действия (степ-ап аутентификация)."""
    password: str = Field(min_length=1, max_length=128)
    # код 2FA, если она включена (можно и заголовком X-Confirm-OTP)
    otp: str | None = Field(default=None, max_length=16)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str


ClientEndpoint = Annotated[str, Field(max_length=255), AfterValidator(normalize_client_endpoint)]


class ServerCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    host: str = Field(min_length=1, max_length=255)
    client_endpoint: ClientEndpoint = ""
    ssh_port: int = Field(default=22, ge=1, le=65535)
    # только безопасный набор символов для имени пользователя (без shell-метасимволов)
    ssh_user: str = Field(
        default="root", min_length=1, max_length=64,
        pattern=r"^[A-Za-z_][A-Za-z0-9_-]*$",
    )
    note: str = ""
    group_name: str = Field(default="", max_length=64)


class ServerUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    host: str | None = Field(default=None, min_length=1, max_length=255)
    client_endpoint: ClientEndpoint = ""
    ssh_port: int | None = Field(default=None, ge=1, le=65535)
    ssh_user: str | None = Field(
        default=None, min_length=1, max_length=64,
        pattern=r"^[A-Za-z_][A-Za-z0-9_-]*$",
    )
    note: str | None = None
    group_name: str | None = Field(default=None, max_length=64)
    torrent_block: bool | None = None
    torrent_autopause: bool | None = None
    alerts_enabled: bool | None = None
    manual_exit_name: str | None = Field(default=None, max_length=128)


class OrderItem(BaseModel):
    id: int
    group_name: str = Field(default="", max_length=64)


class ReorderRequest(BaseModel):
    # плоский список карточек в желаемом порядке отображения; позиция = индекс,
    # порядок групп выводится из непрерывных блоков (drag-and-drop)
    order: list[OrderItem]


class ServerOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    host: str
    client_endpoint: str = ""
    ssh_port: int
    ssh_user: str
    note: str
    group_name: str
    position: int = 0
    country: str = ""
    egress_ip: str = ""
    egress_country: str = ""
    egress_org: str = ""
    egress_at: datetime | None = None
    last_check_ok: bool | None
    last_check_at: datetime | None
    last_check_info: str
    torrent_block: bool = False
    torrent_autopause: bool = False
    alerts_enabled: bool = False
    created_at: datetime
    updated_at: datetime


class TorrentClientOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    protocol: str
    client_id: str
    name: str
    hits: int
    first_seen: datetime
    last_seen: datetime


class TorrentOut(BaseModel):
    # правила на ноде: None - еще не проверяли (блокировка выключена или
    # коллектор не дошел), error - в каких контейнерах не встали
    active: bool | None = None
    checked_at: str | None = None
    error: str = ""
    clients: list[TorrentClientOut] = []


class SetupScriptOut(BaseModel):
    script: str
    panel_public_key: str


class DeleteServerResult(BaseModel):
    key_removed: bool | None = None  # None = не запрашивали снятие ключа
    message: str = ""


class BootstrapRequest(BaseModel):
    password: str = Field(min_length=1)
    become_password: str | None = None


class ConfigOut(BaseModel):
    default_ssh_user: str
    panel_ip: str
    version: str = ""


class AwgClientOut(ClientLabels):
    name: str
    public_key: str
    address: str
    latest_handshake: int | None = None
    rx_bytes: int = 0
    tx_bytes: int = 0
    endpoint: str = ""
    has_config: bool = False
    note: str = ""
    expires_at: datetime | None = None
    paused: bool = False


class AwgStateOut(BaseModel):
    container: str
    interface: str
    listen_port: int
    server_public_key: str
    endpoint: str
    address: str
    clients: list[AwgClientOut]
    # имя отдельного legacy-контейнера (старый AmneziaWG на wg0), если он есть
    # РЯДОМ с новым — тогда фронт покажет вторую секцию «AmneziaWG Legacy»
    legacy_container: str | None = None
    # вкладка 3.x: есть ли на ноде ключи 3.1 (RandomTrailers/DisableCookies).
    # None — вопрос неприменим (2.0/legacy); False — на ноде ещё 3.0
    params_v31: bool | None = None


# DNS уходит строкой "DNS = ..." в конфиг клиента: перевод строки дописал бы
# туда любые директивы (PostUp = ... выполнит awg-quick от root). Только адреса
# IPv4/IPv6 через запятую.
_DNS_PATTERN = r"^[0-9A-Fa-f:.]+(\s*,\s*[0-9A-Fa-f:.]+){0,3}$"


class CreateClientRequest(ClientLabels):
    name: str = Field(min_length=1, max_length=128)
    dns: str | None = Field(default=None, max_length=200, pattern=_DNS_PATTERN)
    note: str = Field(default="", max_length=512)
    expires_at: datetime | None = None


class NoteRequest(BaseModel):
    public_key: str = Field(min_length=1)
    note: str = Field(default="", max_length=512)


class CreateClientResponse(BaseModel):
    client: AwgClientOut
    config: str
    config_amnezia: str


class RevokeClientRequest(BaseModel):
    public_key: str = Field(min_length=1)


class PublicKeyRequest(BaseModel):
    public_key: str = Field(min_length=1)


class ConfigTextResponse(BaseModel):
    config: str
    config_amnezia: str
    name: str


class ServerImportResult(BaseModel):
    """Итог загрузки сервера из файла переноса."""

    server_id: int
    name: str
    host: str
    # сколько строк принято по таблицам — оператор видит, что доехало
    imported: dict[str, int] = {}
    # таблицы из более новой панели, которых тут нет: называем вслух
    skipped_tables: list[str] = []


class ImportLinkRequest(BaseModel):
    link: str = Field(min_length=1)


class ImportPreview(BaseModel):
    name: str
    host: str
    ssh_port: int
    ssh_user: str
    protocols: list[str]
    has_password: bool


class ImportAmneziaRequest(BaseModel):
    links: list[str] = Field(min_length=1)


class ImportBulkRequest(BaseModel):
    text: str = Field(min_length=1)


class ImportResult(BaseModel):
    name: str
    host: str
    ok: bool
    server_id: int | None = None
    bootstrapped: bool = False
    message: str = ""


class ImportResponse(BaseModel):
    results: list[ImportResult]


class DeployRequest(BaseModel):
    port: int = Field(default=47180, ge=1, le=65535)


class DeployStatusOut(BaseModel):
    state: str  # running | done | error | unknown
    log: str


class SnapshotOut(BaseModel):
    id: str  # метка времени снимка (ГГГГММДД-ЧЧММСС)
    clients: int


class SnapshotRestoreRequest(BaseModel):
    id: str = Field(min_length=1, max_length=32)


class VersionOut(BaseModel):
    deployed: bool
    current_version: str | None  # тег образа, напр. "0.2.19"
    current_awg_go: str | None  # версия бинаря amneziawg-go, напр. "0.0.20250522"
    latest_version: str | None
    latest_updated: str
    update_available: bool
    # имя AWG-контейнера, собранного НЕ панелью (amnezia-awg), если такой есть
    foreign_container: str | None = None
    # можно ли его безопасно взять под управление (это настоящий AmneziaWG с
    # awg0.conf). Если False (напр. plain-WireGuard на wg0.conf) — перенос
    # запрещён, иначе затёрли бы конфиг и потеряли клиентов
    adoptable: bool = False


class ServerStat(BaseModel):
    id: int
    name: str
    online: bool
    clients_total: int
    clients_online: int
    rx_total: int
    tx_total: int


class OverviewOut(BaseModel):
    servers_total: int
    servers_online: int
    clients_total: int
    clients_online: int
    rx_total: int
    tx_total: int
    per_server: list[ServerStat]


class HistoryPoint(BaseModel):
    ts: str
    clients_online: int
    throughput: int  # байт за интервал (дельта суммарного трафика)
    rx_total: int
    tx_total: int
    # скорость по направлениям, байт в секунду: сумма посерверных скоростей
    rx_rate: float = 0
    tx_rate: float = 0


class HistoryServerOut(BaseModel):
    """Клиенты онлайн одного сервера, по тем же точкам, что и points."""

    server_id: int
    name: str
    clients_online: list[int | None]


class HistoryOut(BaseModel):
    interval_seconds: int
    points: list[HistoryPoint]
    # только при by_server=true: разбивка для стека "клиенты по серверам"
    servers: list[HistoryServerOut] = []


class ClientHistoryPoint(BaseModel):
    ts: str
    rx_total: int
    tx_total: int
    throughput: int  # байт за интервал (дельта суммарного трафика)


class ClientHistoryOut(BaseModel):
    interval_seconds: int
    current_rx: int
    current_tx: int
    points: list[ClientHistoryPoint]


class TopClientOut(BaseModel):
    server_id: int
    server_name: str
    protocol: str
    # протокол с версией, как на карточке сервера: "AmneziaWG 2.0", "Legacy"...
    protocol_label: str = ""
    client_id: str
    name: str
    rx: int
    tx: int
    total: int


class NodeMetricOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    server_id: int
    cpu_count: int
    load1: float
    cpu_pct: float | None = None
    psi_cpu: float | None = None
    mem_total: int
    mem_used: int
    disk_total: int
    disk_used: int
    uptime_seconds: int
    ts: datetime


class ClientNoteRequest(BaseModel):
    client_id: str = Field(min_length=1)
    note: str = Field(default="", max_length=512)


class OvpnClientOut(ClientLabels):
    client_id: str
    name: str
    creation_date: str
    has_config: bool = False
    expires_at: datetime | None = None
    note: str = ""
    # трафик/онлайн из openvpn-status.log (заполняется в get_openvpn)
    rx_bytes: int = 0
    tx_bytes: int = 0
    connected: bool = False
    since: str = ""  # когда подключился (строка из status-лога)
    paused: bool = False


class OvpnStateOut(BaseModel):
    container: str
    clients: list[OvpnClientOut]


class OvpnCreateRequest(ClientLabels):
    name: str = Field(min_length=1, max_length=128)
    expires_at: datetime | None = None


class OvpnCreateResponse(BaseModel):
    client: OvpnClientOut
    config_amnezia: str


class OvpnConfigRequest(BaseModel):
    client_id: str = Field(min_length=1)


class OvpnConfigResponse(BaseModel):
    config_amnezia: str
    name: str


class OvpnReissueRequest(BaseModel):
    client_id: str = Field(min_length=1)


class OvpnRevokeRequest(BaseModel):
    client_id: str = Field(min_length=1)


class OvpnDeployRequest(BaseModel):
    port: int = Field(default=8443, ge=1, le=65535)
    site: str = Field(default="tile.openstreetmap.org", max_length=253)


class XrayClientOut(ClientLabels):
    client_id: str
    name: str
    creation_date: str
    expires_at: datetime | None = None
    note: str = ""
    # трафик из xray StatsService (0, если статистика не включена на сервере)
    rx_bytes: int = 0  # upload (uplink)
    tx_bytes: int = 0  # download (downlink)
    paused: bool = False


class XrayStateOut(BaseModel):
    container: str
    clients: list[XrayClientOut]


class XrayCreateRequest(ClientLabels):
    name: str = Field(min_length=1, max_length=128)
    expires_at: datetime | None = None


class XrayVariantOut(BaseModel):
    """Вариант подключения: vision (TCP) или xhttp, если он есть на сервере."""

    key: str
    label: str
    amnezia: str  # vpn:// для приложения AmneziaVPN
    uri: str  # vless:// для Happ, v2rayN, INCY и других клиентов на Xray


class XrayCreateResponse(BaseModel):
    client: XrayClientOut
    config_amnezia: str  # = configs[0].amnezia (Vision), для старых клиентов API
    configs: list[XrayVariantOut] = []


class XrayConfigRequest(BaseModel):
    client_id: str = Field(min_length=1)


class XrayConfigResponse(BaseModel):
    config_amnezia: str
    name: str
    configs: list[XrayVariantOut] = []


class XrayRevokeRequest(BaseModel):
    client_id: str = Field(min_length=1)


def _reality_domain(value: str) -> str:
    error = "Enter a DNS name without a scheme, wildcard or port for SNI"
    try:
        domain = idna.encode(value, uts46=True).decode("ascii").removesuffix(".")
    except idna.IDNAError as exc:
        raise ValueError(error) from exc
    if "." in domain and not domain.rsplit(".", 1)[-1].isdigit():
        return domain
    raise ValueError(error)


class XrayDeployRequest(BaseModel):
    port: int = Field(default=443, ge=1, le=65535)
    site: str = Field(default="", max_length=254)
    dest: str = Field(default="", max_length=260)

    @field_validator("site")
    @classmethod
    def normalize_site(cls, value: str) -> str:
        value = value.strip()
        return _reality_domain(value) if value else ""

    @field_validator("dest")
    @classmethod
    def normalize_dest(cls, value: str) -> str:
        value = value.strip()
        if not value:
            return ""
        match = re.fullmatch(r"(\[[0-9a-fA-F:.]+\]|[^:\[\]]+)(?::([0-9]{1,5}))?", value)
        error = "Enter a domain, IPv4 address or [IPv6 address], with an optional port from 1 to 65535"
        if match is None:
            raise ValueError(error)
        host, port = match.groups()
        port = int(port) if port else 443
        if not 1 <= port <= 65535:
            raise ValueError(error)
        if port == STATS_API_PORT:
            raise ValueError("Dest cannot use the port reserved for Xray statistics")
        try:
            if host.startswith("["):
                host = f"[{IPv6Address(host[1:-1])}]"
            else:
                try:
                    host = str(IPv4Address(host))
                except ValueError:
                    host = _reality_domain(host)
        except ValueError as exc:
            raise ValueError(error) from exc
        return f"{host}:{port}"

    @model_validator(mode="after")
    def infer_site(self) -> "XrayDeployRequest":
        if self.dest and not self.site:
            host = self.dest.rsplit(":", 1)[0]
            try:
                self.site = _reality_domain(host)
            except ValueError as exc:
                raise ValueError("Enter an SNI domain when Dest is an IP address") from exc
        return self


class XrayVersionOut(BaseModel):
    deployed: bool
    current_version: str | None  # версия xray-core в контейнере, напр. "25.8.3"
    latest_version: str | None  # версия, которую ставит панель (xray.XRAY_RELEASE)
    latest_updated: str
    update_available: bool


class FullAccessOut(BaseModel):
    config: str  # full-access vpn:// (содержит приватный SSH-ключ!)
    ssh_user: str


class AlertConfigOut(BaseModel):
    telegram_token_set: bool
    telegram_chat: str
    telegram_api: str = ""
    webhook_set: bool
    lang: Literal["", "ru", "en"] = ""  # пусто - не выбирали (алерты по-русски)
    enabled: bool


class AlertConfigIn(BaseModel):
    telegram_token: str | None = Field(default=None, max_length=256)
    telegram_chat: str = Field(default="", max_length=64)
    telegram_api: str = Field(default="", max_length=256)
    webhook: str | None = Field(default=None, max_length=512)
    lang: Literal["", "ru", "en"] = ""
    # смена каналов - со степ-апом: подменой адреса Telegram API или вебхука
    # укравший сессию увел бы токен бота и security-алерты
    password: str = Field(default="", max_length=128)
    otp: str | None = Field(default=None, max_length=16)


class AlertTestResult(BaseModel):
    sent: bool
    errors: list[str] = []


class SetLimitRequest(BaseModel):
    protocol: str = Field(pattern="^(awg|awg3|awglegacy|openvpn|xray|wireguard|openvpn-native)$")
    client_id: str = Field(min_length=1)
    name: str = Field(default="", max_length=128)
    expires_at: datetime | None = None


class AuditEntryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ts: datetime
    username: str
    action: str
    target: str
    detail: str


# --- Интеграционный API (/api/v1) и ключи к нему ----------------------------


class ApiKeyOut(BaseModel):
    """Ключ без секрета — то, что можно показывать в списке."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    prefix: str
    created_at: datetime
    last_used_at: datetime | None = None
    revoked: bool = False
    expires_at: datetime | None = None
    server_ids: list[int] = Field(
        default_factory=list, description="Серверы, с которыми работает ключ (пусто = все)"
    )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def all_servers(self) -> bool:
        return not self.server_ids


class ApiKeyCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120, description="Кому выдан ключ")
    # ключ бессрочный и переживает выход и смену пароля - выпуск со степ-апом
    password: str = Field(min_length=1, max_length=128)
    otp: str | None = Field(default=None, max_length=16)


class ApiKeyUpdateRequest(BaseModel):
    """Ограничения ключа целиком: срок (null = бессрочно) и серверы (пусто = все)."""

    expires_at: datetime | None = None
    server_ids: list[int] = Field(default_factory=list, max_length=500)
    # явное "все серверы": пустой список без него раньше молча давал доступ ко
    # всем. None - старое поведение (пусто = все), False с пустым списком - 400
    all_servers: bool | None = None
    password: str = Field(min_length=1, max_length=128)
    otp: str | None = Field(default=None, max_length=16)


class ApiKeyCreated(ApiKeyOut):
    key: str = Field(
        description="Полный ключ. Показывается ОДИН раз — сохраните его сразу, "
        "восстановить нельзя (в БД только хэш)."
    )


class V1ServerOut(BaseModel):
    """Сервер в интеграционном API: только то, что нужно для выбора ноды."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    host: str
    country: str = ""
    last_check_ok: bool | None = None


# --- Глобальный поиск клиентов и массовый отзыв -----------------------------


class ClientSearchHit(BaseModel):
    """Найденный клиент: на каком сервере, каким протоколом, как зовут."""

    server_id: int
    server_name: str
    protocol: str  # awg | awg3 | awglegacy | openvpn | xray
    # Готовая подпись для интерфейса: «AmneziaWG 2.0», «AmneziaWG 3.0» и т.п.
    # Ключ протокола версию не несёт (у 1.0 и 2.0 он одинаковый — «awg»),
    # поэтому версию берём из проверки ноды, где она определена по конфигу.
    protocol_label: str = ""
    client_id: str
    name: str = ""
    note: str = ""
    has_config: bool = False
    # клиент на паузе: снят с ноды, данные для возобновления в панели
    paused: bool = False
    paused_at: datetime | None = None


class ClientRenameRequest(BaseModel):
    client_id: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=128)


class ProtocolRemoveOut(BaseModel):
    container: str
    snapshot: str  # id снимка конфига на ноде (для ручного восстановления)
    moved: list[str] = []  # каталоги конфига на хосте, переименованные в *.removed-*
    image: str = ""  # удаленный образ, если им больше никто не пользовался


class RevokeBulkItem(BaseModel):
    server_id: int
    protocol: str = Field(min_length=1, max_length=16)
    client_id: str = Field(min_length=1)


class RevokeBulkRequest(BaseModel):
    items: list[RevokeBulkItem] = Field(min_length=1, max_length=500)
    # что искали — попадёт в журнал действий, чтобы потом было понятно, за что
    # отзывали пачку доступов
    query: str = Field(default="", max_length=128)


class RevokeBulkResultItem(BaseModel):
    server_id: int
    server_name: str
    protocol: str
    client_id: str
    ok: bool
    error: str = ""


class RevokeBulkResult(BaseModel):
    revoked: int
    failed: int
    items: list[RevokeBulkResultItem]


class ShareServiceIn(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    url: str = Field(min_length=1, max_length=255)
    password: str = Field(default="", max_length=1024)
    otp: str | None = None


class ShareServiceOut(BaseModel):
    id: str
    name: str
    url: str
    engine: str


class ShareRequest(BaseModel):
    service_id: str = Field(min_length=1, max_length=32)
    text: str = Field(min_length=1, max_length=100_000)
    # что отправляем (имя клиента) - только для журнала, сам текст туда не пишем
    target: str = Field(default="", max_length=255)


class ShareLinkOut(BaseModel):
    url: str
    ttl_days: int


class CascadePair(BaseModel):
    entry_id: int
    exit_id: int


class CascadeInstall(BaseModel):
    entry_country: str | None = Field(default=None, pattern=r"^[A-Za-z]{2}$")

    @field_validator("entry_country")
    @classmethod
    def validate_entry_country(cls, value: str | None) -> str | None:
        if value is None:
            return None
        country = normalize_country_code(value)
        if not country:
            raise ValueError("Expected a supported two-letter country code")
        return country


class CascadeCreate(CascadePair, CascadeInstall, RouteUpdate):
    transport: Literal["vless", "gre", "awg"]
    routes: list[Route] = Field(default_factory=list, max_length=100)
    entry_port: int | None = Field(default=None, ge=1, le=65535)
    exit_port: int | None = Field(default=None, ge=1, le=65535)
    request_id: UUID | None = None

    @model_validator(mode="after")
    def awg_ports_only(self):
        if self.transport != "awg" and (self.entry_port is not None or self.exit_port is not None):
            raise ValueError("UDP ports are only supported for AWG cascades")
        return self


class ProbeSide(BaseModel):
    ok: bool
    bytes: int
    secs: float
    mbps: int
    error: str = ""


class CascadeProbeOut(BaseModel):
    entry_ip: str
    exit_ip: str
    exit_country: str = ""
    exit_org: str = ""
    tcp: ProbeSide
    gre: ProbeSide
    recommend: str  # vless | gre | "" (не проходит ничего)
    # сервер за NAT хостера: GRE через такой NAT обычно не проходит
    entry_nat: bool = False
    exit_nat: bool = False


class CascadeTransportProbe(CascadeCreate):
    """One independent temporary transport measurement."""

    prepare_missing_image: bool = False
    run_id: UUID | None = None

    @model_validator(mode="after")
    def docker_transport_only(self):
        if self.prepare_missing_image and self.transport == "gre":
            raise ValueError("Image preparation is only supported for AWG and VLESS")
        return self


class CascadeSideProgress(BaseModel):
    status: Literal["pending", "running", "done", "error"]
    stage: str
    started_at: datetime | None = None
    updated_at: datetime | None = None


class CascadeTransportProgressOut(BaseModel):
    run_id: str
    entry_server_id: int
    exit_server_id: int
    transport: Literal["awg", "vless", "gre"]
    status: Literal["running", "done", "error", "cancelled"]
    started_at: datetime
    updated_at: datetime
    sides: dict[Literal["entry", "exit"], CascadeSideProgress]


class CascadeTransportProbeOut(BaseModel):
    transport: Literal["awg", "vless", "gre"]
    measurement: Literal["awg", "vless", "gre"]
    run_id: str
    requested_bytes: int
    status: Literal["ok", "failed", "unavailable"]
    ok: bool | None
    bytes: int = 0
    secs: float | None = None
    mbps: float | None = None
    error: str = ""
    reason: Literal["local_image_missing"] | None = None
    entry_ip: str
    exit_ip: str
    exit_country: str = ""
    exit_org: str = ""
    entry_nat: bool = False
    exit_nat: bool = False
    checked_at: datetime
    entry_port: int | None = None
    exit_port: int | None = None
    prerequisite_tcp: dict | None = None
    transfer_ok: bool | None = None
    cleanup_failed: list[Literal["entry", "exit"]] = Field(default_factory=list)
    failed_side: Literal["entry", "exit"] | None = None


class CascadeOut(BaseModel):
    id: int
    entry_server_id: int
    exit_server_id: int
    transport: str
    status: str  # installing | ready | error
    error: str
    phase: str = ""  # exit | entry, пока идет установка
    log: str = ""
    progress: dict[Literal["entry", "exit"], CascadeSideProgress] = Field(default_factory=dict)
    entry_ip: str = ""
    entry_country: str = ""
    exit_ip: str = ""
    entry_port: int | None = None
    exit_port: int | None = None
    encryption: Literal["awg", "reality", "none", "unknown"] = "unknown"
    encrypted: bool | None = None
    probe: dict = {}
    result: dict = {}
    created_at: datetime
    routes: list[Route] = Field(default_factory=list)


class EgressSiteOut(BaseModel):
    name: str
    ok: bool
    code: int
    ms: int


class EgressCheckOut(BaseModel):
    error: str  # проверить не вышло (нет контейнера, нет curl); пусто - проверили
    container: str
    egress: str  # адрес, с которого клиенты выходят в интернет; пусто - не вышли
    egress_country: str
    egress_org: str
    local: str  # адрес для сайтов страны сервера (есть не для всех стран)
    sites: list[EgressSiteOut]
    checked_at: datetime


class CascadeCheckOut(BaseModel):
    ok: bool
    gateway: bool
    tproxy: bool
    rule: bool = True  # ip rule в шлюз на месте
    tunnel: str  # состояние acgre (UP/DOWN) или "" без GRE
    egress: str
    egress_confirmed: bool | None = None
    reason: str = ""
    ru: str
    client: str = ""  # адрес изнутри VPN-контейнера, "" - спросить не вышло
    direct: str = ""  # свой адрес входа: если клиенты выходят с него, каскад они обходят
    leak: bool = False
    encryption: Literal["awg", "reality", "none", "unknown"] = "unknown"
    encrypted: bool | None = None
    handshake_age: int | None = None
    checked_at: datetime
