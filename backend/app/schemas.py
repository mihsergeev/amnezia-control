from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class LoginRequest(BaseModel):
    username: str
    password: str
    otp: str | None = None


class TwoFAStatusOut(BaseModel):
    enabled: bool


class TwoFASetupOut(BaseModel):
    secret: str
    otpauth_uri: str


class TwoFAVerifyRequest(BaseModel):
    otp: str = Field(min_length=1, max_length=16)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str


class ServerCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    host: str = Field(min_length=1, max_length=255)
    ssh_port: int = Field(default=22, ge=1, le=65535)
    ssh_user: str = Field(default="root", min_length=1, max_length=64)
    note: str = ""


class ServerUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    host: str | None = Field(default=None, min_length=1, max_length=255)
    ssh_port: int | None = Field(default=None, ge=1, le=65535)
    ssh_user: str | None = Field(default=None, min_length=1, max_length=64)
    note: str | None = None


class ServerOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    host: str
    ssh_port: int
    ssh_user: str
    note: str
    last_check_ok: bool | None
    last_check_at: datetime | None
    last_check_info: str
    created_at: datetime
    updated_at: datetime


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


class AwgClientOut(BaseModel):
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


class AwgStateOut(BaseModel):
    container: str
    interface: str
    listen_port: int
    server_public_key: str
    endpoint: str
    address: str
    clients: list[AwgClientOut]


class CreateClientRequest(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    dns: str | None = None
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


class VersionOut(BaseModel):
    deployed: bool
    current_version: str | None  # тег образа, напр. "0.2.19"
    current_awg_go: str | None  # версия бинаря amneziawg-go, напр. "0.0.20250522"
    latest_version: str | None
    latest_updated: str
    update_available: bool


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


class HistoryOut(BaseModel):
    interval_seconds: int
    points: list[HistoryPoint]


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
    mem_total: int
    mem_used: int
    disk_total: int
    disk_used: int
    uptime_seconds: int
    ts: datetime


class OvpnClientOut(BaseModel):
    client_id: str
    name: str
    creation_date: str
    has_config: bool = False
    expires_at: datetime | None = None


class OvpnStateOut(BaseModel):
    container: str
    clients: list[OvpnClientOut]


class OvpnCreateRequest(BaseModel):
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


class XrayClientOut(BaseModel):
    client_id: str
    name: str
    creation_date: str
    expires_at: datetime | None = None


class XrayStateOut(BaseModel):
    container: str
    clients: list[XrayClientOut]


class XrayCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    expires_at: datetime | None = None


class XrayCreateResponse(BaseModel):
    client: XrayClientOut
    config_amnezia: str


class XrayConfigRequest(BaseModel):
    client_id: str = Field(min_length=1)


class XrayConfigResponse(BaseModel):
    config_amnezia: str
    name: str


class XrayRevokeRequest(BaseModel):
    client_id: str = Field(min_length=1)


class XrayDeployRequest(BaseModel):
    port: int = Field(default=443, ge=1, le=65535)
    site: str = Field(default="www.googletagmanager.com", max_length=253)


class XrayVersionOut(BaseModel):
    deployed: bool
    current_version: str | None  # версия xray-core в контейнере, напр. "25.8.3"
    latest_version: str | None  # последний релиз XTLS/Xray-core
    latest_updated: str
    update_available: bool


class FullAccessOut(BaseModel):
    config: str  # full-access vpn:// (содержит приватный SSH-ключ!)
    ssh_user: str


class AlertConfigOut(BaseModel):
    telegram_token: str
    telegram_chat: str
    webhook: str
    enabled: bool


class AlertConfigIn(BaseModel):
    telegram_token: str = Field(default="", max_length=256)
    telegram_chat: str = Field(default="", max_length=64)
    webhook: str = Field(default="", max_length=512)


class AlertTestResult(BaseModel):
    sent: bool
    errors: list[str] = []


class SetLimitRequest(BaseModel):
    protocol: str = Field(pattern="^(awg|openvpn|xray)$")
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
