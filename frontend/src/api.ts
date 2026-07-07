const TOKEN_KEY = 'acontrol_token'

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY)
}

export function setToken(token: string | null) {
  if (token) {
    localStorage.setItem(TOKEN_KEY, token)
  } else {
    localStorage.removeItem(TOKEN_KEY)
  }
}

export class ApiError extends Error {
  status: number

  constructor(message: string, status: number) {
    super(message)
    this.status = status
  }
}

export async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string> | undefined),
  }
  const token = getToken()
  if (token) headers['Authorization'] = `Bearer ${token}`

  const res = await fetch(path, { ...options, headers })
  if (res.status === 204) return undefined as T

  const body = await res.json().catch(() => null)
  if (!res.ok) {
    const detail =
      typeof body?.detail === 'string' ? body.detail : `Ошибка HTTP ${res.status}`
    throw new ApiError(detail, res.status)
  }
  return body as T
}

// Скачивание бэкапа: fetch с токеном → blob → триггерим загрузку файла.
export async function downloadBackup(): Promise<void> {
  const token = getToken()
  const res = await fetch('/api/backup', {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  })
  if (!res.ok) {
    throw new ApiError(`Ошибка бэкапа HTTP ${res.status}`, res.status)
  }
  const cd = res.headers.get('Content-Disposition') || ''
  const m = cd.match(/filename="?([^"]+)"?/)
  const name = m ? m[1] : 'acontrol-backup.tar.gz'
  const blob = await res.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = name
  a.click()
  URL.revokeObjectURL(url)
}

// Восстановление: заливаем архив в тело POST (без multipart).
export async function restoreBackup(
  file: File | Blob,
): Promise<{ restored: Record<string, number> }> {
  const token = getToken()
  const res = await fetch('/api/backup/restore', {
    method: 'POST',
    headers: token ? { Authorization: `Bearer ${token}` } : {},
    body: file,
  })
  const body = await res.json().catch(() => null)
  if (!res.ok) {
    const detail =
      typeof body?.detail === 'string' ? body.detail : `Ошибка HTTP ${res.status}`
    throw new ApiError(detail, res.status)
  }
  return body
}

export type BackupItem = { filename: string; size: number; created: string }

export async function downloadSavedBackup(filename: string): Promise<void> {
  const token = getToken()
  const res = await fetch(`/api/backup/file/${encodeURIComponent(filename)}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  })
  if (!res.ok) throw new ApiError(`Ошибка HTTP ${res.status}`, res.status)
  const blob = await res.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}

export type Server = {
  id: number
  name: string
  host: string
  ssh_port: number
  ssh_user: string
  note: string
  last_check_ok: boolean | null
  last_check_at: string | null
  last_check_info: string
  created_at: string
  updated_at: string
}

export type CheckInfo = {
  error?: string
  hostname?: string
  docker?: boolean
  containers?: string[]
  amnezia_containers?: string[]
}

export function parseCheckInfo(server: Server): CheckInfo | null {
  if (!server.last_check_info) return null
  try {
    return JSON.parse(server.last_check_info) as CheckInfo
  } catch {
    return null
  }
}

export type ServerForm = {
  name: string
  host: string
  ssh_port: number
  ssh_user: string
  note: string
}

export type PanelConfig = {
  default_ssh_user: string
  panel_ip: string
}

export type AwgClient = {
  name: string
  public_key: string
  address: string
  latest_handshake: number | null
  rx_bytes: number
  tx_bytes: number
  endpoint: string
  has_config: boolean
  note: string
  expires_at?: string | null
}

export type AwgState = {
  container: string
  interface: string
  listen_port: number
  server_public_key: string
  endpoint: string
  address: string
  clients: AwgClient[]
}

export type CreatedClient = {
  client: AwgClient
  config: string
  config_amnezia: string
}

export type ImportPreview = {
  name: string
  host: string
  ssh_port: number
  ssh_user: string
  protocols: string[]
  has_password: boolean
}

export type ImportResult = {
  name: string
  host: string
  ok: boolean
  server_id: number | null
  bootstrapped: boolean
  message: string
}

export type DeployStatus = {
  state: 'running' | 'done' | 'error' | 'unknown'
  log: string
}

export type VersionInfo = {
  deployed: boolean
  current_version: string | null
  current_awg_go: string | null
  latest_version: string | null
  latest_updated: string
  update_available: boolean
}

export type ServerStat = {
  id: number
  name: string
  online: boolean
  clients_total: number
  clients_online: number
  rx_total: number
  tx_total: number
}

export type TopClient = {
  server_id: number
  server_name: string
  protocol: 'awg' | 'openvpn' | 'xray'
  client_id: string
  name: string
  rx: number
  tx: number
  total: number
}

export type NodeMetric = {
  server_id: number
  cpu_count: number
  load1: number
  mem_total: number
  mem_used: number
  disk_total: number
  disk_used: number
  uptime_seconds: number
  ts: string
}

export type Overview = {
  servers_total: number
  servers_online: number
  clients_total: number
  clients_online: number
  rx_total: number
  tx_total: number
  per_server: ServerStat[]
}

export type HistoryPoint = {
  ts: string
  clients_online: number
  throughput: number
  rx_total: number
  tx_total: number
}

export type History = {
  interval_seconds: number
  points: HistoryPoint[]
}

export type OvpnClient = {
  client_id: string
  name: string
  creation_date: string
  has_config: boolean
  expires_at?: string | null
}

export type OvpnState = {
  container: string
  clients: OvpnClient[]
}

export type OvpnCreated = {
  client: OvpnClient
  config_amnezia: string
}

export type OvpnConfig = {
  config_amnezia: string
  name: string
}

export type XrayClient = {
  client_id: string
  name: string
  creation_date: string
  expires_at?: string | null
}

// Установить/снять срок действия клиента (протокол-независимо).
export async function setClientLimit(
  serverId: number,
  protocol: 'awg' | 'openvpn' | 'xray',
  clientId: string,
  name: string,
  expiresAt: string | null,
): Promise<void> {
  await api<void>(`/api/servers/${serverId}/limit`, {
    method: 'POST',
    body: JSON.stringify({
      protocol,
      client_id: clientId,
      name,
      expires_at: expiresAt,
    }),
  })
}

export type XrayState = {
  container: string
  clients: XrayClient[]
}

export type XrayCreated = {
  client: XrayClient
  config_amnezia: string
}

export type XrayConfig = {
  config_amnezia: string
  name: string
}

export type XrayVersion = {
  deployed: boolean
  current_version: string | null
  latest_version: string | null
  latest_updated: string
  update_available: boolean
}

export type AlertConfig = {
  telegram_token: string
  telegram_chat: string
  webhook: string
  enabled: boolean
}

export function getAlerts(): Promise<AlertConfig> {
  return api<AlertConfig>('/api/alerts')
}

export function putAlerts(cfg: {
  telegram_token: string
  telegram_chat: string
  webhook: string
}): Promise<AlertConfig> {
  return api<AlertConfig>('/api/alerts', {
    method: 'PUT',
    body: JSON.stringify(cfg),
  })
}

export function testAlerts(): Promise<{ sent: boolean; errors: string[] }> {
  return api<{ sent: boolean; errors: string[] }>('/api/alerts/test', {
    method: 'POST',
  })
}

export type ClientHistoryPoint = {
  ts: string
  rx_total: number
  tx_total: number
  throughput: number
}

export type ClientHistory = {
  interval_seconds: number
  current_rx: number
  current_tx: number
  points: ClientHistoryPoint[]
}

export function clientHistory(
  serverId: number,
  protocol: string,
  clientId: string,
  hours = 24,
): Promise<ClientHistory> {
  const q = new URLSearchParams({
    server_id: String(serverId),
    protocol,
    client_id: clientId,
    hours: String(hours),
  })
  return api<ClientHistory>(`/api/stats/client?${q.toString()}`)
}

export type TwoFAStatus = { enabled: boolean }
export type TwoFASetup = { secret: string; otpauth_uri: string }

export function get2FA(): Promise<TwoFAStatus> {
  return api<TwoFAStatus>('/api/auth/2fa')
}

export function setup2FA(): Promise<TwoFASetup> {
  return api<TwoFASetup>('/api/auth/2fa/setup', { method: 'POST' })
}

export function enable2FA(otp: string): Promise<TwoFAStatus> {
  return api<TwoFAStatus>('/api/auth/2fa/enable', {
    method: 'POST',
    body: JSON.stringify({ otp }),
  })
}

export function disable2FA(otp: string): Promise<TwoFAStatus> {
  return api<TwoFAStatus>('/api/auth/2fa/disable', {
    method: 'POST',
    body: JSON.stringify({ otp }),
  })
}

export type Protocol = { key: 'awg' | 'openvpn' | 'xray'; label: string }

// какие протоколы есть на сервере (по именам контейнеров amnezia-*)
export function protocolsFromContainers(containers: string[]): Protocol[] {
  const found: Protocol[] = []
  const has = (re: RegExp) => containers.some((c) => re.test(c))
  if (has(/^amnezia-awg/)) found.push({ key: 'awg', label: 'AmneziaWG' })
  if (has(/^amnezia-openvpn/))
    found.push({ key: 'openvpn', label: 'OpenVPN/Cloak' })
  if (has(/^amnezia-xray/)) found.push({ key: 'xray', label: 'XRay/REALITY' })
  return found
}
