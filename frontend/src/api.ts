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
  if (!res.ok) throw new ApiError(errorDetail(body, res.status), res.status)
  return body as T
}

// Текст ошибки из ответа. У 422 FastAPI detail - массив ошибок валидации, и
// раньше вместо него показывалось "Ошибка HTTP 422".
export function errorDetail(body: unknown, status: number): string {
  const detail = (body as { detail?: unknown } | null)?.detail
  if (typeof detail === 'string') return detail
  if (Array.isArray(detail) && detail.length) {
    return detail
      .map((d: { loc?: unknown[]; msg?: string }) => {
        const field = (d.loc ?? []).filter((x) => x !== 'body').join('.')
        return field ? `${field}: ${d.msg ?? ''}` : (d.msg ?? '')
      })
      .join('; ')
  }
  return `Ошибка HTTP ${status}`
}

// Выход: токен отзывается и на сервере, иначе украденный жил бы до конца срока.
export async function logoutServer(): Promise<void> {
  try {
    await api<void>('/api/auth/logout', { method: 'POST' })
  } catch {
    // сеть или истекший токен: локальный выход все равно состоится
  }
}

// Скачивание файла с POST-запроса: fetch с токеном -> blob -> загрузка.
async function downloadPost(path: string, body: unknown, fallback: string): Promise<void> {
  const token = getToken()
  const res = await fetch(path, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(body),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => null)
    throw new ApiError(errorDetail(err, res.status), res.status)
  }
  const cd = res.headers.get('Content-Disposition') || ''
  const m = cd.match(/filename="?([^"]+)"?/)
  const blob = await res.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = m ? m[1] : fallback
  a.click()
  URL.revokeObjectURL(url)
}

// Смена пароля: возвращает новый токен (старые инвалидируются на бэкенде).
export async function changePassword(
  current_password: string,
  new_password: string,
): Promise<void> {
  const r = await api<{ access_token: string }>('/api/auth/password', {
    method: 'POST',
    body: JSON.stringify({ current_password, new_password }),
  })
  setToken(r.access_token)
}

// Скачивание бэкапа. В нем SSH-ключ ко всем нодам, поэтому нужен пароль.
export async function downloadBackup(password: string): Promise<void> {
  await downloadPost('/api/backup/download', { password }, 'acontrol-backup.tar.gz')
}

// Восстановление: архив в теле POST (без multipart), пароль заголовком.
export async function restoreBackup(
  file: File | Blob,
  password: string,
): Promise<{ restored: Record<string, number> }> {
  const token = getToken()
  const res = await fetch('/api/backup/restore', {
    method: 'POST',
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      'X-Confirm-Password': password,
    },
    body: file,
  })
  const body = await res.json().catch(() => null)
  if (!res.ok) throw new ApiError(errorDetail(body, res.status), res.status)
  return body
}

export type BackupItem = { filename: string; size: number; created: string }

export async function downloadSavedBackup(filename: string, password: string): Promise<void> {
  await downloadPost(
    `/api/backup/file/${encodeURIComponent(filename)}`, { password }, filename,
  )
}

// Перенос одного сервера между панелями (в отличие от бэкапа, который
// переносит панель целиком и затирает принимающую).
export type ServerImportResult = {
  server_id: number
  name: string
  host: string
  imported: Record<string, number>
  skipped_tables: string[]
}

export async function exportServer(id: number, history: boolean): Promise<void> {
  const token = getToken()
  const res = await fetch(`/api/servers/${id}/export?history=${history}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  })
  if (!res.ok) throw new ApiError(`Ошибка HTTP ${res.status}`, res.status)
  const cd = res.headers.get('Content-Disposition') || ''
  const m = cd.match(/filename="?([^"]+)"?/)
  const blob = await res.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = m ? m[1] : 'server.acontrol-server.json'
  a.click()
  URL.revokeObjectURL(url)
}

export async function importServerFile(file: File | Blob): Promise<ServerImportResult> {
  const token = getToken()
  const res = await fetch('/api/servers/import-file', {
    method: 'POST',
    headers: token ? { Authorization: `Bearer ${token}` } : {},
    body: file,
  })
  const body = await res.json().catch(() => null)
  if (!res.ok) throw new ApiError(errorDetail(body, res.status), res.status)
  return body
}

export type Server = {
  id: number
  name: string
  host: string
  ssh_port: number
  ssh_user: string
  note: string
  group_name: string
  position: number
  country: string
  // адрес выхода клиентов в интернет, если он не совпадает с host (вход каскада)
  egress_ip: string
  egress_country: string
  egress_org: string
  egress_at: string | null
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
  // реальный протокол каждого контейнера, определённый по его КОНФИГУ:
  // awg1 | awg2 | awg3 | openvpn | xray. Имя контейнера версию не отражает —
  // на боевой ноде встречается amnezia-awg2, внутри которого конфиг 1.0.
  protocols?: Record<string, string>
  // поднятые GRE-туннели ноды (каскад через GRE)
  tunnels?: { kind: string; name: string; remote: string }[]
}

export function parseCheckInfo(server: Server): CheckInfo | null {
  if (!server.last_check_info) return null
  try {
    return JSON.parse(server.last_check_info) as CheckInfo
  } catch {
    return null
  }
}

// Сохранить ручной порядок карточек (drag-and-drop): плоский список в порядке
// отображения, каждый с (возможно новой) группой.
export function reorderServers(
  order: { id: number; group_name: string }[],
): Promise<void> {
  return api<void>('/api/servers/order', {
    method: 'POST',
    body: JSON.stringify({ order }),
  })
}

export type ServerForm = {
  name: string
  host: string
  ssh_port: number
  ssh_user: string
  note: string
  group_name: string
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
  paused?: boolean
}

export type AwgState = {
  container: string
  // для вкладки 3.x: несёт ли конфиг ноды ключи 3.1. false = там ещё 3.0 и
  // ноду надо пересобрать, иначе выданные конфиги будут трёхнулевыми
  params_v31?: boolean
  interface: string
  listen_port: number
  server_public_key: string
  endpoint: string
  address: string
  clients: AwgClient[]
  legacy_container?: string | null
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
  foreign_container?: string | null
  adoptable?: boolean
}

// снимки конфига на ноде (для отката пересборки), для любого протокола
export type SnapProto = 'awg' | 'awg3' | 'xray' | 'openvpn'
export type Snapshot = { id: string; clients: number }

export function listConfigBackups(
  serverId: number,
  proto: SnapProto,
): Promise<Snapshot[]> {
  return api<Snapshot[]>(`/api/servers/${serverId}/${proto}/config-backups`)
}

export async function restoreConfig(
  serverId: number,
  proto: SnapProto,
  id: string,
): Promise<void> {
  await api(`/api/servers/${serverId}/${proto}/config-restore`, {
    method: 'POST',
    body: JSON.stringify({ id }),
  })
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
  // awg / awg3 / awglegacy / openvpn / xray - версию сам ключ не несет
  protocol: string
  // протокол с версией, как на карточке сервера: "AmneziaWG 2.0", "Legacy"...
  protocol_label?: string
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
  // скорость по направлениям, байт в секунду (сумма посерверных скоростей)
  rx_rate: number
  tx_rate: number
}

export type HistoryServer = {
  server_id: number
  name: string
  // по тем же точкам, что points; null - снимка сервера в этой точке нет
  clients_online: (number | null)[]
}

export type History = {
  interval_seconds: number
  points: HistoryPoint[]
  servers: HistoryServer[]
}

export type OvpnClient = {
  client_id: string
  name: string
  creation_date: string
  has_config: boolean
  expires_at?: string | null
  note?: string
  rx_bytes?: number
  tx_bytes?: number
  connected?: boolean
  since?: string
  paused?: boolean
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
  note?: string
  rx_bytes?: number
  tx_bytes?: number
  paused?: boolean
}

// Пауза/возобновление клиента (протокол-независимо).
export async function pauseClient(
  serverId: number,
  protocol: 'awg' | 'awg-legacy' | 'awg3' | 'xray' | 'openvpn',
  clientId: string,
  resume: boolean,
): Promise<void> {
  const idKey = protocol.startsWith('awg') ? 'public_key' : 'client_id'
  await api<void>(
    `/api/servers/${serverId}/${protocol}/${resume ? 'resume' : 'pause'}`,
    { method: 'POST', body: JSON.stringify({ [idKey]: clientId }) },
  )
}

// Установить/снять срок действия клиента (протокол-независимо).
export async function setClientLimit(
  serverId: number,
  protocol: 'awg' | 'awg3' | 'awglegacy' | 'openvpn' | 'xray',
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

// Вариант подключения: vision (TCP) всегда, xhttp - если он есть на сервере.
export type XrayVariant = {
  key: string
  label: string
  amnezia: string // vpn:// для AmneziaVPN
  uri: string // vless:// для Happ, v2rayN, INCY и др.
}

export type XrayCreated = {
  client: XrayClient
  config_amnezia: string
  configs?: XrayVariant[]
}

export type XrayConfig = {
  config_amnezia: string
  name: string
  configs?: XrayVariant[]
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
  telegram_api: string
  webhook: string
  // язык алертов; пусто - не выбирали (панель шлет по-русски)
  lang: '' | 'ru' | 'en'
  enabled: boolean
}

export function getAlerts(): Promise<AlertConfig> {
  return api<AlertConfig>('/api/alerts')
}

export function putAlerts(cfg: {
  telegram_token: string
  telegram_chat: string
  telegram_api: string
  webhook: string
  lang: 'ru' | 'en'
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

// включение и выключение 2FA требуют пароль: иначе укравший токен включил бы
// 2FA со своим секретом и запер настоящего админа
export function setup2FA(password: string): Promise<TwoFASetup> {
  return api<TwoFASetup>('/api/auth/2fa/setup', {
    method: 'POST',
    body: JSON.stringify({ password }),
  })
}

export function enable2FA(otp: string, password: string): Promise<TwoFAStatus> {
  return api<TwoFAStatus>('/api/auth/2fa/enable', {
    method: 'POST',
    body: JSON.stringify({ otp, password }),
  })
}

export function disable2FA(otp: string, password: string): Promise<TwoFAStatus> {
  return api<TwoFAStatus>('/api/auth/2fa/disable', {
    method: 'POST',
    body: JSON.stringify({ otp, password }),
  })
}

export type Protocol = {
  key: 'awg' | 'awglegacy' | 'awg3' | 'openvpn' | 'xray'
  label: string
}

// какие протоколы есть на сервере (по именам контейнеров amnezia-*)
// Метка реальной версии AmneziaWG по данным проверки ноды. Имя контейнера
// версию не отражает: Amnezia называет контейнер amnezia-awg2 и для старого 1.0.
const AWG_KIND_LABEL: Record<string, string> = {
  awg1: 'AmneziaWG 1.0',
  awg2: 'AmneziaWG 2.0',
  awg3: 'AmneziaWG 3.0',
  awg31: 'AmneziaWG 3.1',
}

export function protocolsFromContainers(
  containers: string[],
  kinds: Record<string, string> = {},
): Protocol[] {
  const found: Protocol[] = []
  const has = (re: RegExp) => containers.some((c) => re.test(c))
  // AmneziaWG 3.0 — отдельный контейнер amnezia-awg3. Его нужно исключать из
  // проверки на 2.0: иначе сервер, где стоит ТОЛЬКО 3.0, показывался бы как 2.0
  // (шаблон /^amnezia-awg/ совпадает и с awg3).
  const hasAwg3 = has(/^amnezia-awg3/)
  const hasAwgOther = containers.some(
    (c) => /^amnezia-awg/.test(c) && !/^amnezia-awg3/.test(c),
  )
  // Порядок вкладок — от НОВОГО к старому: 3.0, затем 2.0, затем legacy. Первая
  // вкладка открывается по умолчанию, а нужен обычно самый свежий протокол: если
  // на ноде уже есть 3.0, открывать её на 2.0 бессмысленно.
  if (hasAwg3) {
    // подпись по реальной версии из конфига: панель ставит 3.1, но на ноде
    // может стоять и раньше развёрнутая 3.0
    const c3 = containers.find((x) => /^amnezia-awg3/.test(x) && kinds[x])
    found.push({
      key: 'awg3',
      label: (c3 && AWG_KIND_LABEL[kinds[c3]]) || 'AmneziaWG 3.1',
    })
  }
  if (hasAwgOther) {
    // версию берём из конфига контейнера; пока проверка старая (без protocols)
    // — остаётся прежняя нейтральная подпись
    const c = containers.find(
      (x) => /^amnezia-awg2/.test(x) && kinds[x],
    ) ?? containers.find((x) => /^amnezia-awg/.test(x) && !/^amnezia-awg3/.test(x) && kinds[x])
    found.push({ key: 'awg', label: (c && AWG_KIND_LABEL[kinds[c]]) || 'AmneziaWG' })
  }
  // старый AmneziaWG (wg0) рядом с новым: у Amnezia legacy=amnezia-awg, new=
  // amnezia-awg2 — если есть ОБА контейнера, второй протокол это legacy
  if (containers.includes('amnezia-awg') && has(/^amnezia-awg2/)) {
    found.push({ key: 'awglegacy', label: 'AmneziaWG Legacy' })
  }
  if (has(/^amnezia-openvpn/))
    found.push({ key: 'openvpn', label: 'OpenVPN/Cloak' })
  if (has(/^amnezia-xray/)) found.push({ key: 'xray', label: 'XRay/REALITY' })
  return found
}

// --- Ключи интеграционного API (/api/v1) ------------------------------------

export type ApiKey = {
  id: number
  name: string
  prefix: string
  created_at: string
  last_used_at: string | null
  revoked: boolean
  expires_at: string | null
  server_ids: number[]
}

// Полный ключ приходит ТОЛЬКО в ответе на создание — показать и не терять.
export type ApiKeyCreated = ApiKey & { key: string }

export async function listApiKeys(): Promise<ApiKey[]> {
  return api<ApiKey[]>('/api/apikeys')
}

export async function createApiKey(name: string): Promise<ApiKeyCreated> {
  return api<ApiKeyCreated>('/api/apikeys', {
    method: 'POST',
    body: JSON.stringify({ name }),
  })
}

// срок (null = бессрочно) и серверы (пусто = все) задаются целиком
export async function updateApiKey(
  id: number,
  expires_at: string | null,
  server_ids: number[],
): Promise<ApiKey> {
  return api<ApiKey>(`/api/apikeys/${id}`, {
    method: 'PUT',
    body: JSON.stringify({ expires_at, server_ids }),
  })
}

export async function revokeApiKey(id: number): Promise<void> {
  return api<void>(`/api/apikeys/${id}`, { method: 'DELETE' })
}

// --- Глобальный поиск клиентов по всему парку -------------------------------

export type ClientHit = {
  server_id: number
  server_name: string
  protocol: string
  // подпись с версией («AmneziaWG 2.0/3.0», «AmneziaWG Legacy», …) — считается
  // на бэкенде: ключ протокола версию не несёт, её знает проверка ноды
  protocol_label?: string
  client_id: string
  name: string
  note: string
  has_config: boolean
}

export type RevokeBulkResultItem = {
  server_id: number
  server_name: string
  protocol: string
  client_id: string
  ok: boolean
  error: string
}

export type RevokeBulkResult = {
  revoked: number
  failed: number
  items: RevokeBulkResultItem[]
}

export function searchClients(q: string): Promise<ClientHit[]> {
  return api<ClientHit[]>(`/api/clients/search?q=${encodeURIComponent(q)}`)
}

export function revokeClientsBulk(
  items: { server_id: number; protocol: string; client_id: string }[],
  query: string,
): Promise<RevokeBulkResult> {
  return api<RevokeBulkResult>('/api/clients/revoke-bulk', {
    method: 'POST',
    body: JSON.stringify({ items, query }),
  })
}

export type ProtocolRemoved = {
  container: string
  snapshot: string
  moved: string[]
  image: string
}

// удаляет протокол с ноды вместе со всеми клиентами (нужен пароль)
export function removeProtocol(
  serverId: number,
  protocol: Protocol['key'],
  password: string,
): Promise<ProtocolRemoved> {
  return api<ProtocolRemoved>(`/api/servers/${serverId}/protocols/${protocol}/remove`, {
    method: 'POST',
    body: JSON.stringify({ password }),
  })
}

// новое имя клиента: в clientsTable на ноде и в панели
export function renameClient(
  serverId: number,
  protocol: Protocol['key'],
  clientId: string,
  name: string,
): Promise<void> {
  return api<void>(`/api/servers/${serverId}/protocols/${protocol}/rename`, {
    method: 'POST',
    body: JSON.stringify({ client_id: clientId, name }),
  })
}

// человекочитаемое имя протокола для списков поиска
export const PROTOCOL_LABEL: Record<string, string> = {
  awg: 'AmneziaWG',
  awg2: 'AmneziaWG 2.0',
  awg3: 'AmneziaWG 3.1',
  awglegacy: 'AmneziaWG Legacy',
  openvpn: 'OpenVPN/Cloak',
  xray: 'XRay/REALITY',
}

// --- одноразовые ссылки на конфиг через сервисы секретов ---
export type ShareService = { id: string; name: string; url: string; engine: string }

export function getShareServices(): Promise<ShareService[]> {
  return api<ShareService[]>('/api/share/services')
}

export function addShareService(name: string, url: string): Promise<ShareService[]> {
  return api<ShareService[]>('/api/share/services', {
    method: 'POST',
    body: JSON.stringify({ name, url }),
  })
}

export function deleteShareService(id: string): Promise<ShareService[]> {
  return api<ShareService[]>(`/api/share/services/${id}`, { method: 'DELETE' })
}

export function createShareLink(
  serviceId: string,
  text: string,
  target: string,
): Promise<{ url: string; ttl_days: number }> {
  return api('/api/share', {
    method: 'POST',
    body: JSON.stringify({ service_id: serviceId, text, target }),
  })
}

// --- каскады: вход и выход ---------------------------------------------------

export type CascadeTransport = 'vless' | 'gre'

export type ProbeSide = { ok: boolean; bytes: number; secs: number; mbps: number; error: string }

export type CascadeProbe = {
  entry_ip: string
  exit_ip: string
  exit_country: string
  exit_org: string
  tcp: ProbeSide
  gre: ProbeSide
  recommend: CascadeTransport | ''
}

export type Cascade = {
  id: number
  entry_server_id: number
  exit_server_id: number
  transport: CascadeTransport
  status: 'installing' | 'ready' | 'error'
  error: string
  phase: '' | 'exit' | 'entry'
  log: string
  entry_ip: string
  exit_ip: string
  probe: Partial<CascadeProbe> & { checked_at?: string }
  result: {
    egress?: string
    ru?: string
    checked_at?: string
    // фоновая проверка панели раз в пару минут
    health?: { ok: boolean; reason?: string; since?: string; checked_at?: string }
  }
  created_at: string
}

export type CascadeCheck = {
  ok: boolean
  gateway: boolean
  tproxy: boolean
  tunnel: string
  egress: string
  ru: string
  checked_at: string
}

/** Сервер уже в каскаде: собранном панелью или настроенном руками (GRE, другой выход). */
export function inCascade(s: Server, cascades: Cascade[]): boolean {
  if (cascades.some((c) => c.entry_server_id === s.id || c.exit_server_id === s.id)) return true
  const gre = (parseCheckInfo(s)?.tunnels ?? []).some((x) => x.kind === 'gre')
  // каскад, собранный руками: клиенты выходят в другой стране. Просто другой
  // адрес выхода (NAT, несколько адресов у сервера) каскадом не считаем
  const abroad =
    s.egress_ip !== '' &&
    s.egress_country !== '' &&
    s.country !== '' &&
    s.egress_country !== s.country
  return gre || abroad
}

export function listCascades(): Promise<Cascade[]> {
  return api<Cascade[]>('/api/cascades')
}

// серверы без выходов каскадов: выход - часть своего входа, клиентов у него нет
export async function listVpnServers(): Promise<Server[]> {
  const [servers, cascades] = await Promise.all([
    api<Server[]>('/api/servers'),
    listCascades().catch(() => [] as Cascade[]),
  ])
  const exits = new Set(cascades.map((c) => c.exit_server_id))
  return servers.filter((s) => !exits.has(s.id))
}

export function getCascade(id: number): Promise<Cascade> {
  return api<Cascade>(`/api/cascades/${id}`)
}

export function probeCascade(entryId: number, exitId: number): Promise<CascadeProbe> {
  return api<CascadeProbe>('/api/cascades/probe', {
    method: 'POST',
    body: JSON.stringify({ entry_id: entryId, exit_id: exitId }),
  })
}

export function createCascade(
  entryId: number,
  exitId: number,
  transport: CascadeTransport,
): Promise<Cascade> {
  return api<Cascade>('/api/cascades', {
    method: 'POST',
    body: JSON.stringify({ entry_id: entryId, exit_id: exitId, transport }),
  })
}

export function reinstallCascade(id: number): Promise<Cascade> {
  return api<Cascade>(`/api/cascades/${id}/install`, { method: 'POST' })
}

export function checkCascade(id: number): Promise<CascadeCheck> {
  return api<CascadeCheck>(`/api/cascades/${id}/check`, { method: 'POST' })
}

export function deleteCascade(id: number, force = false): Promise<void> {
  return api<void>(`/api/cascades/${id}${force ? '?force=true' : ''}`, { method: 'DELETE' })
}
