import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type FormEvent,
  type ReactNode,
} from 'react'
import {
  api,
  ApiError,
  deleteCascade,
  listCascades,
  parseCheckInfo,
  protocolsFromContainers,
  reorderServers,
  type Cascade,
  type DeployProtocol,
  type NodeMetric,
  type Overview,
  type PanelConfig,
  type Protocol,
  type Server,
  type ServerForm,
  type HostKey,
  type ServerStat,
} from './api'
import { ClientsModal } from './ClientsModal'
import { RemoveProtocolModal } from './BulkActions'
import { ImportModal } from './ImportModal'
import { DeployModal } from './DeployModal'
import { HostKeyReplacement } from './HostKeyReplacement'
import { Menu, type MenuItem } from './Menu'
import { ServerExportModal, ServerImportModal } from './ServerTransfer'
import { SshAccessEditor } from './SshAccessEditor'
import { accessChanged, accessPolicy, accessPolicyPayload, DEFAULT_ACCESS, keyFileType, type AccessPreview } from './sshAccess'
import { copyText } from './clipboard'
import { countryFlag, formatBytes, formatUptime } from './format'
import { CascadeWizard } from './CascadeWizard'
import { CascadeCheckModal } from './CascadeCheck'
import { CascadeRoutesModal } from './CascadeRoutes'
import { SiteCheckModal } from './SiteCheck'
import { cascadeEntryCountry, cascadeTransportLabel, latestCascadeHealth } from './cascadeUi'
import { EgressCheckModal } from './EgressCheck'
import { TorrentLine } from './Torrent'
import { translate, useI18n } from './i18n'
import {
  groupServerList, resolveServerSelection, serverListAnchors, serverListClients,
  serverListItems, serverListMatches, serverListProblem, serverSelectionFromHistory,
  serverSelectionParams, type ServerListItem, type ServerSelection,
  cascadeNameParts, greLinkLabel, manualExitNameChange, serverListRoute, type ServerRouteNode,
} from './serverList'

const FALLBACK_USER = 'acontrol'

function initialSelection(): ServerSelection {
  const fromUrl = serverSelectionFromHistory(new URLSearchParams(window.location.search), window.history.state)
  if (fromUrl.key || fromUrl.serverId) return fromUrl
  try {
    const serverId = Number(localStorage.getItem('acontrol_selected_server')) || null
    const key = localStorage.getItem('acontrol_selected_row')
    return { key: key && /^(server|cascade):\d+$/.test(key) ? key : null, serverId }
  } catch {
    return { key: null, serverId: null }
  }
}

function emptyForm(defaultUser: string): ServerForm {
  return {
    name: '',
    host: '',
    client_endpoint: '',
    country_override: '',
    ssh_port: 22,
    ssh_user: defaultUser,
    ...DEFAULT_ACCESS,
    note: '',
    group_name: '',
  }
}

type Props = {
  onUnauthorized: () => void
}

// Полный доступ умеет только то, что знает приложение AmneziaVPN (как
// fullaccess._canonical на бэкенде): amnezia-awg3 туда не попадает. Если на
// ноде кроме него ничего нет, пункт меню бесполезен. Пока проверки нет
// (список пуст) - показываем, решит бэкенд.
function fullAccessSupported(containers: string[]): boolean {
  if (!containers.length) return true
  return containers.some(
    (c) => /^amnezia-(awg|openvpn|xray|wireguard)/.test(c) && !/^amnezia-awg3/.test(c),
  )
}

// по последней проверке ноды: контейнер amnezia-awg3 с конфигом 3.0 (kind awg3,
// у 3.1 kind awg31)
function isAwg30Node(info: ReturnType<typeof parseCheckInfo>): boolean {
  const kinds = info?.protocols ?? {}
  return (info?.amnezia_containers ?? []).some(
    (c) => /^amnezia-awg3/.test(c) && kinds[c] === 'awg3',
  )
}

function greTunnels(server: Server) {
  return (parseCheckInfo(server)?.tunnels ?? []).filter((x) => x.kind === 'gre')
}

function GreBadge({ server, withRemote }: { server: Server; withRemote?: boolean }) {
  const { t } = useI18n()
  const gre = greTunnels(server)
  if (gre.length === 0) return null
  const remotes = gre.map((x) => x.remote).join(', ')
  const link = parseCheckInfo(server)?.cascade_link
  const degraded = link?.encrypted === true && link.healthy === false
  return (
    <span className={`tun-badge${degraded ? ' tun-badge-warn' : ''}`} title={degraded ? t('Связь требует проверки; шифрование сохраняется') : t('GRE-туннель до {ip}', { ip: remotes })}>
      {withRemote ? `${greLinkLabel(server)} → ${remotes}` : greLinkLabel(server)}
    </span>
  )
}

function CascadeNodeName({ node }: { node: ServerRouteNode }) {
  const name = cascadeNameParts(node.name)
  return <span className="srv-cascade-node" title={`${node.name}: ${node.host}`}>
    {countryFlag(node.country) && <span className="server-flag" title={node.country}>{countryFlag(node.country)}</span>}
    <span className="srv-cascade-primary">{name.primary}</span>
  </span>
}

function CascadeListName({ route }: { route: NonNullable<ReturnType<typeof serverListRoute>> }) {
  return <span className="srv-item-name srv-cascade-name">
    <CascadeNodeName node={route.entry} />
    <span className="srv-cascade-arrow" aria-hidden="true">→</span>
    <CascadeNodeName node={route.exit} />
  </span>
}

// Путь клиентов каскада, настроенного вручную: известен только адрес выхода.
function EgressRoute({ server }: { server: Server }) {
  const { t } = useI18n()
  const viaGre = greTunnels(server).length > 0
  const exitIp = server.egress_ip
  const exitCountry = server.egress_country
  const exitSub = server.egress_org
  return (
    <div className="srv-route">
      <span className="srv-route-label">{t('Клиенты')}</span>
      <span className="srv-route-arrow">→</span>
      <Hop flag={countryFlag(server.country)} title={server.host} sub={t('этот сервер')} />
      <span className="srv-route-arrow">
        {viaGre && <GreBadge server={server} />}
        →
      </span>
      <Hop
        className="srv-hop-exit"
        flag={countryFlag(exitCountry)}
        title={exitIp}
        sub={exitSub ? t('выход в интернет, {org}', { org: exitSub }) : t('выход в интернет')}
      />
    </div>
  )
}

// Одна схема сохраняет контекст каскада при открытии любого его узла.
function CascadeRoute({
  cascade,
  entry,
  exit,
  selectedId,
  onOpen,
}: {
  cascade: Cascade
  entry?: Server
  exit?: Server
  selectedId?: number
  onOpen: (s: Server) => void
}) {
  const { t } = useI18n()
  return (
    <div className="srv-route">
      <span className="srv-route-label">{t('Клиенты')}</span>
      <span className="srv-route-arrow">→</span>
      <Hop
        flag={countryFlag(cascadeEntryCountry(cascade, entry))}
        title={entry?.host || cascade.entry_ip}
        sub={entry ? t('вход каскада, {name}', { name: entry.name }) : t('Сервер входа недоступен')}
        onClick={entry ? () => onOpen(entry) : undefined}
        selected={entry?.id === selectedId}
        hint={t('Открыть сервер входа')}
      />
      <span className="srv-route-arrow">
        <span className="tun-badge">{cascade.transport === 'gre' ? greLinkLabel(entry) : cascadeTransportLabel(cascade.transport)}</span>→
      </span>
      <Hop
        className="srv-hop-exit"
        flag={countryFlag(exit?.country || '')}
        title={exit?.host || cascade.exit_ip}
        sub={exit ? t('выход каскада, {name}', { name: exit.name }) : t('Сервер выхода недоступен')}
        onClick={exit ? () => onOpen(exit) : undefined}
        selected={exit?.id === selectedId}
        hint={t('Открыть сервер выхода')}
      />
    </div>
  )
}

// узел маршрута; с onClick - открывает соседний сервер каскада
function Hop({
  className = '',
  flag,
  title,
  sub,
  onClick,
  hint,
  selected = false,
}: {
  className?: string
  flag: string
  title: string
  sub: string
  onClick?: () => void
  hint?: string
  selected?: boolean
}) {
  const content = <>
    {flag && <span className="server-flag">{flag}</span>}
    <span className="srv-hop-text">
      <span className="mono">{title}</span>
      <span className="muted small">{sub}</span>
    </span>
    {onClick && <span className="srv-hop-go" aria-hidden="true">↗</span>}
  </>
  const cls = `srv-hop ${className}${onClick ? ' srv-hop-link' : ''}${selected ? ' srv-hop-selected' : ''}`
  if (onClick) {
    return <button type="button" className={cls} title={hint} aria-pressed={selected} onClick={onClick}>{content}</button>
  }
  return (
    <div className={cls}>{content}</div>
  )
}

// exitDown: выход каскада этого сервера не отвечает - у клиентов не открывается все, что идет через выход
function StatusDot({ server, exitDown = false, cascadeUnverified = false }: {
  server: Server; exitDown?: boolean; cascadeUnverified?: boolean
}) {
  const { t } = useI18n()
  const cls =
    server.last_check_ok === null
      ? 'dot-unknown'
      : !server.last_check_ok || exitDown ? 'dot-fail'
        : cascadeUnverified ? 'dot-unknown' : 'dot-ok'
  const title =
    server.last_check_ok === null
      ? t('не проверялся')
      : !server.last_check_ok
        ? t('ошибка (см. лог)')
        : exitDown
          ? t('выход каскада не отвечает')
          : cascadeUnverified ? t('Каскад еще не проверен') : t('онлайн')
  return <span className={`dot ${cls}`} title={title} />
}

function ListStatusDot({ item }: { item: ServerListItem }) {
  const { t } = useI18n()
  if (!item.cascade) return item.anchor ? <StatusDot server={item.anchor} /> : null
  const health = latestCascadeHealth(item.cascade.result)
  const failed = item.cascade.status === 'error' || !item.entry || !item.exit
    || health?.ok === false || item.members.some((server) => server.last_check_ok === false)
  const installing = item.cascade.status === 'installing'
  const unknown = installing || !health || item.members.some((server) => server.last_check_ok === null)
  const cls = failed ? 'dot-fail' : unknown ? 'dot-unknown' : 'dot-ok'
  const title = failed ? t('ошибка (см. лог)') : installing ? t('Каскад собирается…')
    : !health ? t('Каскад еще не проверен') : unknown ? t('не проверялся') : t('онлайн')
  return <span className={`dot ${cls}`} title={title} />
}

function pct(used: number, total: number): number {
  return total > 0 ? Math.round((used / total) * 100) : 0
}

// пороги те же, что подсвечивают метрики в карточке: диск и память от 90%.
// CPU - по настоящей загрузке и PSI (задачи ждут процессор), а не по load на
// ядро: на 1 vCPU load выше 1 бывает от ожидания IO при свободном процессоре
function cpuLevel(m: NodeMetric): string {
  const cpu = m.cpu_pct ?? 0
  const psi = m.psi_cpu ?? 0
  if (cpu >= 90 || psi >= 60) return 'res-crit'
  if (cpu >= 70 || psi >= 30) return 'res-warn'
  return ''
}

function pctLevel(p: number, warn: number): string {
  return p >= 90 ? 'res-crit' : p >= warn ? 'res-warn' : ''
}

function isProblem(s: Server, m: NodeMetric | undefined): boolean {
  if (s.last_check_ok === false) return true
  if (!m) return false
  return (
    cpuLevel(m) === 'res-crit' ||
    pct(m.mem_used, m.mem_total) >= 90 ||
    pct(m.disk_used, m.disk_total) >= 90
  )
}

function Kpi({
  label,
  value,
  sub,
  bar,
  level = '',
}: {
  label: string
  value: ReactNode
  sub?: string
  bar?: number
  level?: string
}) {
  return (
    <div className={`srv-kpi ${level}`}>
      <div className="srv-kpi-label">{label}</div>
      <div className="srv-kpi-value">{value}</div>
      {sub && <div className="srv-kpi-sub">{sub}</div>}
      {bar !== undefined && (
        <div className="srv-kpi-bar">
          <i style={{ width: `${Math.min(100, bar)}%` }} />
        </div>
      )}
    </div>
  )
}

function ServerDetail({
  server,
  metric: m,
  stat,
  checking,
  menu,
  onCheck,
  onClients,
  cascade,
  peer,
  onCascade,
  onOpen,
  onCascadeCheck,
  onCascadeRoutes,
  onEgressCheck,
}: {
  server: Server
  metric: NodeMetric | undefined
  stat: ServerStat | undefined
  checking: boolean
  menu: MenuItem[]
  onCheck: () => Promise<void>
  onClients: (proto?: Protocol['key']) => void
  // каскад панели с этим сервером и второй его сервер
  cascade?: Cascade
  peer?: Server
  onCascade: (c: Cascade) => void
  onOpen: (s: Server) => void
  onCascadeCheck: (c: Cascade) => void
  onCascadeRoutes: (c: Cascade) => void
  // проверка выхода путем клиентов: для каскада, собранного руками
  onEgressCheck: () => void
}) {
  const { t, lang } = useI18n()
  const info = parseCheckInfo(server)
  const protocols = protocolsFromContainers(
    info?.amnezia_containers ?? [],
    info?.protocols ?? {},
  )
  const online = server.last_check_ok === true
  const memPct = m ? pct(m.mem_used, m.mem_total) : 0
  const diskPct = m ? pct(m.disk_used, m.disk_total) : 0
  const cpuPct = m?.cpu_pct != null ? Math.round(m.cpu_pct) : null
  const isEntry = cascade?.entry_server_id === server.id
  const health = isEntry && cascade?.status === 'ready' ? latestCascadeHealth(cascade.result) : undefined
  const exitDown = isEntry && (peer?.last_check_ok === false || health?.ok === false)
  const checkManaged = cascade?.status === 'ready' && !!peer
  const checkExternal = !cascade && !!server.egress_ip

  async function runCheck() {
    await onCheck()
    if (checkManaged && cascade) onCascadeCheck(cascade)
    else if (checkExternal) onEgressCheck()
  }

  return (
    <div className={`card srv-detail${server.last_check_ok === false ? ' server-down' : ''}`}>
      <div className="srv-detail-head">
        <StatusDot server={server} exitDown={exitDown} cascadeUnverified={isEntry && cascade?.status === 'ready' && !health} />
        <h3 className="srv-detail-name" title={server.name}>
          {server.name}
        </h3>
        {server.group_name && <span className="group-count">{server.group_name}</span>}
        <div className="srv-detail-actions">
          {online && protocols.length > 0 && (
            <button onClick={() => onClients()}>{t('Клиенты')}</button>
          )}
          <button className="ghost" onClick={() => void runCheck()} disabled={checking}>
            {checking ? t('Проверка…') : t(checkManaged || checkExternal ? 'Проверить каскад' : 'Проверить')}
          </button>
          <Menu label={t('Ещё')} items={menu} />
        </div>
      </div>

      <div className="srv-detail-meta">
        {countryFlag(server.country) && (
          <span className="server-flag" title={server.country}>
            {countryFlag(server.country)}
          </span>
        )}
        <span className="mono host">{server.host}</span>
        <span className="muted small mono">
          SSH {server.ssh_user}:{server.ssh_port}
        </span>
        {online && m && (
          <span className="muted small">
            {t('аптайм {t}', { t: formatUptime(m.uptime_seconds) })}
          </span>
        )}
      </div>

      {cascade ? (
        <>
          <CascadeRoute
            cascade={cascade}
            entry={isEntry ? server : peer}
            exit={isEntry ? peer : server}
            selectedId={server.id}
            onOpen={onOpen}
          />
          {!isEntry && <div className="muted small">
            {protocols.length > 0
              ? t('Свои клиенты этого сервера выходят в интернет с него напрямую, без каскада.')
              : t('Чтобы завести здесь своих клиентов без каскада, разверните протокол в меню «Ещё».')}
          </div>}
        </>
      ) : server.egress_ip ? (
        <EgressRoute server={server} />
      ) : (
        greTunnels(server).length > 0 && (
          <div>
            <GreBadge server={server} withRemote />
          </div>
        )
      )}

      {cascade && cascade.status !== 'ready' && (
        <div className={`small ${cascade.status === 'error' ? 'err-text' : 'muted'}`}>
          {cascade.status === 'error'
            ? t('Каскад не собрался: {err}', { err: cascade.error })
            : t('Каскад собирается…')}{' '}
          <button className="link-btn" onClick={() => onCascade(cascade)}>
            {t('Подробнее')}
          </button>
        </div>
      )}
      {cascade && cascade.status === 'ready' && cascade.entry_server_id === server.id && (
        <div className="srv-route-settings">
          <div>
            <strong>{t('Маршруты каскада')}</strong>
            <div className="muted small">
              {t('Сохраненная страна маршрутов: {country}', { country: cascade.entry_country || '—' })}
              {cascade.desired_entry_country !== cascade.entry_country && ` · ${t('Изменения страны ожидают применения')}`}
              {` · ${t('Фактические правила доступны в настройках маршрутов')}`}
            </div>
          </div>
          <button className="ghost" onClick={() => onCascadeRoutes(cascade)}>{t('Настроить маршруты')}</button>
        </div>
      )}
      {health?.ok === false && (
        <div className="small err-text cas-exit-down">
          {health.since
            ? t('Каскад не работает с {time}: {reason}', {
                time: new Date(health.since).toLocaleString(lang === 'en' ? 'en-GB' : 'ru-RU', {
                  day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit',
                }),
                reason: t(health.reason ?? ''),
              })
            : health.reason ? t('Каскад не работает: {reason}', { reason: t(health.reason) }) : t('Каскад не работает')}
        </div>
      )}
      {isEntry && peer?.last_check_ok === false && (
        <div className="small err-text cas-exit-down">
          {t('Выход {host} не отвечает: {err}', {
            host: peer.host,
            err: parseCheckInfo(peer)?.error || t('нет связи'),
          })}
        </div>
      )}

      {server.note && <div className="srv-detail-note">{server.note}</div>}

      {server.torrent_block && <TorrentLine server={server} />}

      {server.last_check_ok === false && info?.error && (
        <div className="small err-text">{info.error}</div>
      )}

      {online && (m || stat?.online) && (
        <div className="srv-kpis">
          {stat?.online && (
            <Kpi
              label={t('Клиенты онлайн')}
              value={
                <>
                  {stat.clients_online}
                  <span className="srv-kpi-of"> / {stat.clients_total}</span>
                </>
              }
            />
          )}
          {m && (
            <>
              <Kpi
                label="CPU"
                value={cpuPct != null ? `${cpuPct}%` : '…'}
                sub={t('load {l}, ядер {n}', {
                  l: m.load1.toFixed(2),
                  n: m.cpu_count,
                })}
                bar={cpuPct ?? undefined}
                level={cpuLevel(m)}
              />
              <Kpi
                label="RAM"
                value={`${memPct}%`}
                sub={`${formatBytes(m.mem_used)} / ${formatBytes(m.mem_total)}`}
                bar={memPct}
                level={pctLevel(memPct, 80)}
              />
              <Kpi
                label={t('Диск')}
                value={`${diskPct}%`}
                sub={`${formatBytes(m.disk_used)} / ${formatBytes(m.disk_total)}`}
                bar={diskPct}
                level={pctLevel(diskPct, 75)}
              />
            </>
          )}
        </div>
      )}

      {online && info?.sudo === 'no' && (
        <p className="small res-warn" role="status">
          {t('У пользователя SSH нет sudo без пароля: установка протоколов и изменения на сервере не сработают.')}
        </p>
      )}

      <div className="srv-protos">
        <div className="srv-protos-title">{t('Протоколы')}</div>
        {protocols.length === 0 ? (
          <p className="muted small">
            {!online
              ? t('Протоколы появятся после успешной проверки сервера.')
              : info?.docker === false
                ? t('Docker на сервере недоступен.')
                : t('Протоколов нет. Развернуть можно в меню «Ещё».')}
          </p>
        ) : (
          protocols.map((p) =>
            online ? (
              // вся строка открывает клиентов протокола, кнопка - подсказка глазу
              <div
                className="srv-proto-row clickable"
                key={p.key}
                role="button"
                tabIndex={0}
                onClick={() => onClients(p.key)}
                onKeyDown={(e) => {
                  if (e.target !== e.currentTarget) return
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault()
                    onClients(p.key)
                  }
                }}
              >
                <span className="proto-badge">{p.label}</span>
                <button
                  className="primary-ghost"
                  tabIndex={-1}
                  onClick={(e) => {
                    e.stopPropagation()
                    onClients(p.key)
                  }}
                >
                  {t('Клиенты')}
                </button>
              </div>
            ) : (
              <div className="srv-proto-row" key={p.key}>
                <span className="proto-badge">{p.label}</span>
              </div>
            ),
          )
        )}
      </div>
    </div>
  )
}


export function ServersPage({ onUnauthorized }: Props) {
  const { t } = useI18n()
  const [servers, setServers] = useState<Server[]>([])
  const [metrics, setMetrics] = useState<Record<number, NodeMetric>>({})
  // клиенты онлайн/всего по серверам - из последних снимков сборщика
  const [stats, setStats] = useState<Record<number, ServerStat>>({})
  const [query, setQuery] = useState('')
  const [onlyProblems, setOnlyProblems] = useState(false)
  const [selection, setSelection] = useState<ServerSelection>(initialSelection)
  const initialSelectionRef = useRef(selection)
  const detailRef = useRef<HTMLDivElement>(null)
  const [config, setConfig] = useState<PanelConfig | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)

  const [form, setForm] = useState<ServerForm>(emptyForm(FALLBACK_USER))
  const [editingId, setEditingId] = useState<number | null>(null)
  const [formOpen, setFormOpen] = useState(false)
  const [formError, setFormError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  // храним ключ, а не перевод: подпись должна меняться вместе с языком
  const [busyLabel, setBusyLabel] = useState('Сохранить')
  const [savedSsh, setSavedSsh] = useState<{ warning?: string } | null>(null)

  // автонастройка по паролю (только при создании)
  const [useBootstrap, setUseBootstrap] = useState(true)
  const [password, setPassword] = useState('')
  const [sudoPassword, setSudoPassword] = useState('')
  const [showAdvanced, setShowAdvanced] = useState(false)
  const [sshPreview, setSshPreview] = useState<AccessPreview | null>(null)
  // закрыть незавершенную настройку SSH, когда сервер недоступен навсегда
  const [abandonFor, setAbandonFor] = useState<Server | null>(null)
  const [abandonPassword, setAbandonPassword] = useState('')
  const [abandonError, setAbandonError] = useState<string | null>(null)
  // отпечаток ключа нового сервера, который надо подтвердить до отправки пароля
  const [hostKeyConfirm, setHostKeyConfirm] = useState<{ server: Server; fingerprint: string; key_type: string } | null>(null)

  const [checkingId, setCheckingId] = useState<number | null>(null)
  const [clientsFor, setClientsFor] = useState<Server | null>(null)
  // вкладка протокола, с которой открыть клиентов (кнопка в строке протокола)
  const [clientsTab, setClientsTab] = useState<Protocol['key'] | undefined>()
  const [importOpen, setImportOpen] = useState(false)
  // перенос одного сервера между панелями (не путать с бэкапом всей панели)
  const [exportFor, setExportFor] = useState<Server | null>(null)
  const [fileImportOpen, setFileImportOpen] = useState(false)
  const [deployFor, setDeployFor] = useState<{
    server: Server
    mode: 'deploy' | 'update' | 'adopt' | 'upgrade31'
    protocol: DeployProtocol
  } | null>(null)
  const [fullAccess, setFullAccess] = useState<{
    server: Server
    config: string
    user: string
  } | null>(null)
  const [faBusyId, setFaBusyId] = useState<number | null>(null)
  const [faCopied, setFaCopied] = useState(false)
  // степ-ап: сервер, для которого запрашиваем повторный пароль перед выдачей ключа
  const [faStepUp, setFaStepUp] = useState<Server | null>(null)
  const [faPassword, setFaPassword] = useState('')
  const [scriptFor, setScriptFor] = useState<{
    server: Server
    onboardingError?: string
    text?: string
    error?: string
  } | null>(null)
  const [deleteFor, setDeleteFor] = useState<Server | null>(null)
  // удаление протокола целиком: из меню «Ещё», после подтверждения и пароля
  const [removeProto, setRemoveProto] = useState<{ server: Server; protocol: Protocol } | null>(null)
  const [deleteRemoveKey, setDeleteRemoveKey] = useState(false)
  const [deleting, setDeleting] = useState(false)
  const [copied, setCopied] = useState(false)
  const [cascades, setCascades] = useState<Cascade[]>([])
  // мастер каскада: новый (resume нет) или ход установки уже созданного
  const [wizard, setWizard] = useState<{ resume?: Cascade; replacement?: Cascade } | null>(null)
  const [unbuild, setUnbuild] = useState<{ c: Cascade; error?: string; canForget?: boolean } | null>(null)
  const [unbuilding, setUnbuilding] = useState(false)
  const [casRoutes, setCasRoutes] = useState<Cascade | null>(null)
  // окно проверки канала каскада
  const [casCheck, setCasCheck] = useState<Cascade | null>(null)
  const [egressCheck, setEgressCheck] = useState<Server | null>(null)
  const [siteCheckFor, setSiteCheckFor] = useState<Server | null>(null)
  const [hostKeyReplacementFor, setHostKeyReplacementFor] = useState<Server | null>(null)
  const editingServer = servers.find(server => server.id === editingId)

  useEffect(() => {
    const state = window.history.state && typeof window.history.state === 'object' ? window.history.state : {}
    window.history.replaceState({ ...state, acontrolServerSelection: initialSelectionRef.current }, '')
    const navigate = (event: PopStateEvent) => setSelection(serverSelectionFromHistory(new URLSearchParams(window.location.search), event.state))
    window.addEventListener('popstate', navigate)
    return () => window.removeEventListener('popstate', navigate)
  }, [])

  // Escape закрывает открытую инлайновую модалку страницы (компонентные —
  // ClientsModal/DeployModal и т.п. — обрабатывают Escape сами)
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key !== 'Escape' || e.defaultPrevented) return
      if (faStepUp) setFaStepUp(null)
      else if (fullAccess) setFullAccess(null)
      else if (scriptFor) setScriptFor(null)
      else if (deleteFor) setDeleteFor(null)
      else if (unbuild) setUnbuild(null)
      else if (formOpen && !busy) closeForm()
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [faStepUp, fullAccess, scriptFor, deleteFor, unbuild, formOpen, busy])

  const handleError = useCallback(
    (err: unknown) => {
      if (err instanceof ApiError && err.status === 401) {
        onUnauthorized()
        return
      }
      setError(err instanceof Error ? err.message : translate('Неизвестная ошибка'))
    },
    [onUnauthorized],
  )

  const loadSequence = useRef(0)
  const invalidateLoads = useCallback(() => { loadSequence.current++ }, [])
  const load = useCallback(async () => {
    const sequence = ++loadSequence.current
    try {
      const loaded = await api<Server[]>('/api/servers')
      if (sequence !== loadSequence.current) return
      setServers(loaded)
      setError(null)
      // метрики нод — необязательны, грузим отдельно и молча
      api<NodeMetric[]>('/api/stats/nodes')
        .then((rows) => {
          if (sequence === loadSequence.current) setMetrics(Object.fromEntries(rows.map((r) => [r.server_id, r])))
        })
        .catch(() => {})
      listCascades()
        .then((rows) => { if (sequence === loadSequence.current) setCascades(rows) })
        .catch(() => {})
      api<Overview>('/api/stats/overview')
        .then((o) => { if (sequence === loadSequence.current) setStats(Object.fromEntries(o.per_server.map((r) => [r.id, r]))) })
        .catch(() => {})
      return loaded
    } catch (err) {
      if (sequence === loadSequence.current) handleError(err)
    } finally {
      if (sequence === loadSequence.current) setLoading(false)
    }
  }, [handleError])

  useEffect(() => {
    void load()
    api<PanelConfig>('/api/config')
      .then(setConfig)
      .catch(() => setConfig(null))
    return invalidateLoads
  }, [load, invalidateLoads])

  function resetForm(defaultUser: string) {
    setSshPreview(null)
    setForm(emptyForm(defaultUser))
    setFormError(null)
    setPassword('')
    setSudoPassword('')
    setShowAdvanced(false)
    setUseBootstrap(true)
  }

  function closeForm() {
    setPassword('')
    setSudoPassword('')
    setHostKeyConfirm(null)
    setFormOpen(false)
  }

  function openCreate() {
    if (busy) return
    resetForm(config?.default_ssh_user ?? FALLBACK_USER)
    setEditingId(null)
    setFormOpen(true)
  }

  function openEdit(server: Server) {
    if (busy) return
    setSshPreview(null)
    setSavedSsh(null)
    setFormError(null)
    setForm({
      name: server.name,
      host: server.host,
      client_endpoint: server.client_endpoint ?? '',
      country_override: server.country_override ?? '',
      ssh_port: server.ssh_port,
      ssh_user: server.ssh_user,
      ...accessPolicy(server),
      note: server.note,
      group_name: server.group_name,
      torrent_block: server.torrent_block,
      torrent_autopause: server.torrent_autopause,
      alerts_enabled: server.alerts_enabled,
      ...(parseCheckInfo(server)?.manual_cascade ? { manual_exit_name: parseCheckInfo(server)?.manual_cascade?.exit_name || '' } : {}),
    })
    setEditingId(server.id)
    setFormOpen(true)
  }

  async function openScript(server: Server, onboardingError?: string) {
    const request = { server, onboardingError }
    setScriptFor(request)
    setCopied(false)
    try {
      const { script } = await api<{ script: string }>(
        `/api/servers/${server.id}/setup-script`,
      )
      setScriptFor(current => current === request ? { ...request, text: script } : current)
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        setScriptFor(current => current === request ? null : current)
        handleError(err)
        return
      }
      const error = err instanceof Error ? err.message : t('Неизвестная ошибка')
      setScriptFor(current => current === request ? { ...request, error } : current)
    }
  }

  async function copyScript() {
    if (scriptFor?.text !== undefined) setCopied(await copyText(scriptFor.text))
  }

  async function check(server: Server) {
    setCheckingId(server.id)
    try {
      const updated = await api<Server>(`/api/servers/${server.id}/check`, {
        method: 'POST',
      })
      setServers((prev) => prev.map((s) => (s.id === updated.id ? updated : s)))
      setError(null)
    } catch (err) {
      handleError(err)
    } finally {
      setCheckingId(null)
    }
  }

  async function exportFullAccess(server: Server, password: string) {
    setFaBusyId(server.id)
    setError(null)
    try {
      const r = await api<{ config: string; ssh_user: string }>(
        `/api/servers/${server.id}/fullaccess`,
        { method: 'POST', body: JSON.stringify({ password }) },
      )
      setFaStepUp(null) // закрываем степ-ап только при успехе
      setFaPassword('')
      setFaCopied(false)
      setFullAccess({ server, config: r.config, user: r.ssh_user })
      void check(server) // карточка узнает, что ключ полного доступа выдан
    } catch (err) {
      handleError(err) // на неверный пароль (403) окно остаётся, показываем ошибку
    } finally {
      setFaBusyId(null)
    }
  }

  async function revokeFullAccess(server: Server) {
    if (!window.confirm(t('Отозвать полный доступ к серверу «{name}»? Приложение AmneziaVPN, куда добавлена ссылка, потеряет управление сервером.', { name: server.name }))) return
    setFaBusyId(server.id)
    setError(null)
    setNotice(null)
    try {
      const r = await api<{ removed: boolean }>(`/api/servers/${server.id}/fullaccess`, { method: 'DELETE' })
      setNotice(r.removed
        ? t('Полный доступ к серверу «{name}» отозван.', { name: server.name })
        : t('Ключа полного доступа на сервере «{name}» уже не было.', { name: server.name }))
      void check(server)
    } catch (err) {
      handleError(err)
    } finally {
      setFaBusyId(null)
    }
  }

  function rememberSavedSsh(server: Server) {
    const warning = parseCheckInfo(server)?.ssh_access_warning
    invalidateLoads()
    setServers(previous => previous.map(item => item.id === server.id ? server : item))
    setForm(previous => ({ ...previous, ...accessPolicy(server) }))
    setSshPreview(null)
    setSavedSsh({ warning })
    if (warning) setNotice(warning)
    return warning
  }

  // панель сама зайдёт по паролю, поставит ключ и настроит фаервол
  async function bootstrapCreated(created: Server, fingerprint: string | null) {
    setBusyLabel('Подключаюсь и настраиваю…')
    try {
      const configured = await api<Server>(`/api/servers/${created.id}/bootstrap`, {
        method: 'POST',
        body: JSON.stringify({
          password,
          become_password: sudoPassword || null,
          host_key_fingerprint: fingerprint,
        }),
      })
      setServers(previous => previous.map(server => server.id === configured.id ? configured : server))
      closeForm()
      await load()
      setNotice(t('Сервер «{name}» настроен и подключён.', { name: created.name }))
    } catch (err) {
      closeForm()
      if (err instanceof ApiError && err.status === 401) throw err
      await load()
      const msg = err instanceof Error ? err.message : t('ошибка')
      await openScript(created, t('Сервер создан. Автонастройка не удалась. {msg}', { msg: t(msg) }))
    }
  }

  async function declineHostKey() {
    const created = hostKeyConfirm?.server
    closeForm()
    if (!created) return
    await load()
    await openScript(created, t('Сервер создан. Пароль не отправлен: ключ сервера не подтвержден.'))
  }

  async function submit(e: FormEvent) {
    e.preventDefault()
    if (busy) return
    if (hostKeyConfirm) {
      setBusy(true)
      setFormError(null)
      try {
        await bootstrapCreated(hostKeyConfirm.server, hostKeyConfirm.fingerprint)
      } catch (err) {
        if (err instanceof ApiError && err.status === 401) onUnauthorized()
        else setFormError(err instanceof Error ? err.message : t('Неизвестная ошибка'))
      } finally {
        setBusy(false)
        setBusyLabel('Сохранить')
      }
      return
    }
    if (editingServer?.ssh_access_pending) {
      setSshPreview(null)
      setFormError(t('Восстановить настройку SSH'))
      return
    }
    setBusy(true)
    setFormError(null)
    setNotice(null)
    try {
      if (editingId !== null) {
        setBusyLabel('Сохранение…')
        const {
          ssh_jump_server_id: _jumpServerId,
          ssh_source_mode: _sourceMode,
          ssh_source_ips: _sourceIps,
          ssh_firewall_mode: _firewallMode,
          ...payload
        } = form
        const existing = editingServer
        let accessWarning = savedSsh?.warning
        if (existing && accessChanged(existing, form)) {
          if (existing.host !== form.host || existing.ssh_port !== form.ssh_port || existing.ssh_user !== form.ssh_user) throw new Error(t('Сначала сохраните адрес SSH отдельно, затем измените способ доступа.'))
          const proposed = accessPolicyPayload(form)
          if (!sshPreview) {
            setSshPreview(await api<AccessPreview>(`/api/servers/${editingId}/ssh-access/preview`, {
              method: 'POST', body: JSON.stringify(proposed),
            }))
            return
          }
          let applied: Server
          try {
            applied = await api<Server>(`/api/servers/${editingId}/ssh-access/apply`, {
              method: 'POST', body: JSON.stringify({ token: sshPreview.token }),
            })
            if (applied?.id !== editingId) throw new Error(t('Не удалось подтвердить результат настройки SSH.'))
          } catch (err) {
            setSshPreview(null)
            if (err instanceof ApiError && err.status === 401) throw err
            // A lost response can leave an active transaction or an already saved policy.
            setServers(previous => previous.map(server => server.id === editingId
              ? { ...server, ssh_access_pending: true } : server))
            const refreshed = (await load())?.find(server => server.id === editingId)
            const expected = proposed.ssh_source_mode === 'custom' ? { ...proposed, ssh_source_ips: sshPreview.sources } : proposed
            if (refreshed && !refreshed.ssh_access_pending && !accessChanged(refreshed, expected)) {
              rememberSavedSsh(refreshed)
            }
            throw err
          }
          accessWarning = rememberSavedSsh(applied)
        }
        if (payload.manual_exit_name !== undefined) {
          const oldName = existing ? parseCheckInfo(existing)?.manual_cascade?.exit_name || '' : ''
          payload.manual_exit_name = manualExitNameChange(payload.manual_exit_name, oldName)
          if (payload.manual_exit_name === undefined) delete payload.manual_exit_name
        }
        const updated = await api<Server>(`/api/servers/${editingId}`, {
          method: 'PATCH',
          body: JSON.stringify(payload),
        })
        setServers(previous => previous.map(server => server.id === updated.id ? updated : server))
        setFormOpen(false)
        await load()
        if (existing?.ssh_jump_server_id && (existing.host !== form.host || existing.ssh_port !== form.ssh_port)) setNotice(t('Адрес SSH сохранен. В скрипте настройки подготовьте промежуточную ноду и проверьте подключение.'))
        else if (accessWarning) setNotice(accessWarning)
        return
      }

      setBusyLabel('Создание…')
      const created = await api<Server>('/api/servers', {
        method: 'POST',
        body: JSON.stringify({ ...form, ...accessPolicyPayload(form) }),
      })
      invalidateLoads()
      setServers(previous => [...previous.filter(server => server.id !== created.id), created])

      if (useBootstrap && password) {
        // Пароль уходит только серверу, чей ключ подтвержден: сначала отпечаток.
        setBusyLabel('Получаю ключ сервера…')
        let hostKey: HostKey
        try {
          hostKey = await api<HostKey>(`/api/servers/${created.id}/host-key`, { method: 'POST' })
        } catch (err) {
          closeForm()
          if (err instanceof ApiError && err.status === 401) throw err
          await load()
          const msg = err instanceof Error ? err.message : t('ошибка')
          await openScript(created, t('Сервер создан. Автонастройка не удалась. {msg}', { msg: t(msg) }))
          return
        }
        if (hostKey.known) await bootstrapCreated(created, null)
        else setHostKeyConfirm({ server: created, fingerprint: hostKey.fingerprint, key_type: hostKey.key_type })
      } else {
        // ручной путь — показываем скрипт для запуска на сервере
        closeForm()
        await load()
        await openScript(created)
      }
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) onUnauthorized()
      else setFormError(err instanceof Error ? err.message : t('Неизвестная ошибка'))
    } finally {
      setBusy(false)
      setBusyLabel('Сохранить')
    }
  }

  async function recoverSshAccess(serverId: number, fromEditor = false) {
    if (busy || (formOpen && !fromEditor)) return
    setBusy(true)
    if (fromEditor) setFormError(null)
    try {
      const recovered = await api<Server>(`/api/servers/${serverId}/ssh-access/recover`, { method: 'POST' })
      if (fromEditor) {
        setSshPreview(null)
        setForm(previous => ({ ...previous, ...accessPolicy(recovered) }))
      }
      // A successful recovery confirms the transaction is no longer pending.
      setServers(previous => previous.map(server => server.id === serverId
        ? { ...recovered, ssh_access_pending: false } : server))
      await load()
      const warning = parseCheckInfo(recovered)?.ssh_access_warning
      if (warning) setNotice(t(warning))
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) return onUnauthorized()
      await load()
      if (fromEditor) setFormError(err instanceof Error ? err.message : t('Неизвестная ошибка'))
      else handleError(err)
    } finally {
      setBusy(false)
    }
  }

  async function abandonSshAccess() {
    const target = abandonFor
    if (!target || busy) return
    setBusy(true)
    setAbandonError(null)
    try {
      const closed = await api<Server>(`/api/servers/${target.id}/ssh-access/abandon`, {
        method: 'POST', body: JSON.stringify({ password: abandonPassword }),
      })
      setServers(previous => previous.map(server => server.id === target.id ? { ...closed, ssh_access_pending: false } : server))
      setAbandonFor(null)
      setAbandonPassword('')
      await load()
      const warning = parseCheckInfo(closed)?.ssh_access_warning
      setNotice(warning ? t(warning) : t('Настройка SSH завершена восстановлением.'))
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) return onUnauthorized()
      setAbandonError(err instanceof Error ? err.message : t('Неизвестная ошибка'))
    } finally {
      setBusy(false)
    }
  }

  async function confirmDelete() {
    if (!deleteFor) return
    setDeleting(true)
    try {
      const res = await api<{ key_removed: boolean | null; message: string }>(
        `/api/servers/${deleteFor.id}?remove_key=${deleteRemoveKey}`,
        { method: 'DELETE' },
      )
      setDeleteFor(null)
      await load()
      setNotice(res.message || t('Сервер «{name}» убран из панели.', { name: deleteFor.name }))
    } catch (err) {
      handleError(err)
    } finally {
      setDeleting(false)
    }
  }

  const [collapsed, setCollapsed] = useState<Record<string, boolean>>(() => {
    try {
      return JSON.parse(localStorage.getItem('acontrol_groups_collapsed') || '{}')
    } catch {
      return {}
    }
  })

  function toggleGroup(name: string) {
    setCollapsed((prev) => {
      const next = { ...prev, [name]: !prev[name] }
      localStorage.setItem('acontrol_groups_collapsed', JSON.stringify(next))
      return next
    })
  }

  // серверы, сгруппированные по group_name; порядок карточек и групп — ручной
  // (position, drag-and-drop). Группа выводится по первому появлению в
  // отсортированном списке (= по минимальной позиции участника), пустая — в конце.
  const listed = useMemo(() => serverListItems(servers, cascades), [servers, cascades])
  const groupList = useMemo(() => groupServerList(listed), [listed])
  const sharedAnchors = useMemo(() => {
    const counts = new Map<number, number>()
    for (const item of listed) if (item.anchor) counts.set(item.anchor.id, (counts.get(item.anchor.id) ?? 0) + 1)
    return new Set([...counts].filter(([, count]) => count > 1).map(([id]) => id))
  }, [listed])

  // --- drag-and-drop: перетаскивание карточек и групп ---
  const dragServer = useRef<number | null>(null)
  const dragGroup = useRef<string | null>(null)
  const [dropHint, setDropHint] = useState<string | null>(null)

  const applyOrder = useCallback(
    (flat: Server[]) => {
      const next = flat.map((s, i) => ({ ...s, position: i }))
      // оптимистично; выходы каскадов в списке не участвуют, но нужны карточкам
      setServers((prev) => [...next, ...prev.filter((s) => !next.some((n) => n.id === s.id))])
      void reorderServers(
        next.map((s) => ({ id: s.id, group_name: s.group_name })),
      ).catch(() => {
        setError(t('Не удалось сохранить порядок'))
        void load()
      })
    },
    [load, t],
  )

  const flatServers = useCallback(
    () => serverListAnchors(groupList.flatMap((g) => g.items)),
    [groupList],
  )

  // бросили сервер перед другим сервером (в т.ч. в другую группу)
  const dropOnServer = useCallback(
    (targetId: number) => {
      const srcId = dragServer.current
      dragServer.current = null
      setDropHint(null)
      if (srcId == null || srcId === targetId) return
      const flat = flatServers()
      const src = flat.find((s) => s.id === srcId)
      const target = flat.find((s) => s.id === targetId)
      if (!src || !target) return
      const moved = { ...src, group_name: target.group_name }
      const without = flat.filter((s) => s.id !== srcId)
      const idx = without.findIndex((s) => s.id === targetId)
      without.splice(idx, 0, moved)
      applyOrder(without)
    },
    [applyOrder, flatServers],
  )

  // бросили сервер на заголовок группы → в конец этой группы
  const dropServerOnGroup = useCallback(
    (groupName: string) => {
      const srcId = dragServer.current
      dragServer.current = null
      setDropHint(null)
      if (srcId == null) return
      const flat = flatServers()
      const src = flat.find((s) => s.id === srcId)
      if (!src) return
      const moved = { ...src, group_name: groupName }
      const without = flat.filter((s) => s.id !== srcId)
      let insertAt = without.length
      for (let i = without.length - 1; i >= 0; i--) {
        if ((without[i].group_name || '') === groupName) {
          insertAt = i + 1
          break
        }
      }
      without.splice(insertAt, 0, moved)
      applyOrder(without)
    },
    [applyOrder, flatServers],
  )

  // бросили заголовок группы на другой заголовок → двигаем весь блок группы
  const dropGroupOnGroup = useCallback(
    (targetGroup: string) => {
      const src = dragGroup.current
      dragGroup.current = null
      setDropHint(null)
      if (src == null || src === targetGroup) return
      const order = groupList.map((g) => g.name)
      const from = order.indexOf(src)
      if (from < 0 || order.indexOf(targetGroup) < 0) return
      order.splice(from, 1)
      order.splice(order.indexOf(targetGroup), 0, src)
      const byGroup = new Map(groupList.map((g) => [g.name, g.items]))
      applyOrder(serverListAnchors(order.flatMap((name) => byGroup.get(name) || [])))
    },
    [applyOrder, groupList],
  )

  const hasGroups = groupList.some((g) => g.name !== '')
  // существующие имена групп — для подсказки в форме
  const existingGroups = useMemo(
    () =>
      [...new Set(servers.map((s) => s.group_name).filter(Boolean))].sort((a, b) =>
        a.localeCompare(b, 'ru'),
      ),
    [servers],
  )

  function cascadeOf(s: Server): Cascade | undefined {
    return selectedItem?.members.some((member) => member.id === s.id)
      ? selectedItem.cascade
      : cascades.find((c) => c.entry_server_id === s.id || c.exit_server_id === s.id)
  }

  const problem = useCallback((item: ServerListItem): boolean =>
    serverListProblem(item, (server) => isProblem(server, metrics[server.id])), [metrics])

  const cascadePeer = useCallback((s: Server, c: Cascade | undefined): Server | undefined => {
    if (!c) return undefined
    const id = c.entry_server_id === s.id ? c.exit_server_id : c.entry_server_id
    return servers.find((x) => x.id === id)
  }, [servers])

  async function confirmUnbuild(force: boolean, replace = false) {
    if (!unbuild) return
    setUnbuilding(true)
    try {
      await deleteCascade(unbuild.c.id, force)
      invalidateLoads()
      setCascades((rows) => rows.filter((row) => row.id !== unbuild.c.id))
      setUnbuild(null)
      if (replace) setWizard({ replacement: unbuild.c })
      setNotice(replace ? null : force
        ? t('Запись каскада удалена. Проверьте, остались ли на серверах шлюз и туннель.')
        : t('Каскад разобран: клиенты входа снова выходят в интернет с него самого.'))
      await load()
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) onUnauthorized()
      else setUnbuild({
        c: unbuild.c,
        error: err instanceof Error ? err.message : t('Ошибка'),
        canForget: err instanceof ApiError && err.status === 502,
      })
    } finally {
      setUnbuilding(false)
    }
  }

  // меню «Ещё» сервера: в карточке справа. «Проверить» там отдельной кнопкой.
  function serverMenu(s: Server): MenuItem[] {
    const info = parseCheckInfo(s)
    const protocols = protocolsFromContainers(
      info?.amnezia_containers ?? [],
      info?.protocols ?? {},
    )
    const online = s.last_check_ok === true
    const items: MenuItem[] = [{ label: t('Проверить сайты'), onClick: () => setSiteCheckFor(s) }]
    if (online && protocols.length === 0) {
      items.push({
        label: t('Развернуть AmneziaWG'),
        onClick: () => setDeployFor({ server: s, mode: 'deploy', protocol: 'awg' }),
      })
    }
    if (online && !protocols.some((p) => p.key === 'awg3')) {
      items.push({
        label: t('Развернуть AmneziaWG 3.1'),
        onClick: () => setDeployFor({ server: s, mode: 'deploy', protocol: 'awg3' }),
      })
    }
    if (online && !protocols.some((p) => p.key === 'xray')) {
      items.push({
        label: t('Развернуть XRay / REALITY'),
        onClick: () => setDeployFor({ server: s, mode: 'deploy', protocol: 'xray' }),
      })
    }
    if (online && !protocols.some((p) => p.key === 'openvpn')) {
      items.push({
        label: t('Развернуть OpenVPN + Cloak'),
        onClick: () => setDeployFor({ server: s, mode: 'deploy', protocol: 'openvpn' }),
      })
    }
    if (online && !protocols.some(p => p.key === 'wireguard')) items.push({
      label: t('Развернуть WireGuard'), onClick: () => setDeployFor({ server: s, mode: 'deploy', protocol: 'wireguard' }),
    })
    if (online && !protocols.some(p => p.key === 'openvpn-native')) items.push({
      label: t('Развернуть OpenVPN'), onClick: () => setDeployFor({ server: s, mode: 'deploy', protocol: 'openvpn-native' }),
    })
    if (online && fullAccessSupported(info?.amnezia_containers ?? [])) {
      items.push({
        label: faBusyId === s.id ? t('Генерация…') : t('Полный доступ'),
        disabled: faBusyId === s.id,
        onClick: () => {
          setError(null)
          setFaPassword('')
          setFaStepUp(s)
        },
      })
    }
    if (online && info?.fullaccess_key) {
      items.push({
        label: t('Отозвать полный доступ'),
        disabled: faBusyId === s.id,
        onClick: () => void revokeFullAccess(s),
      })
    }
    if (!online) {
      items.push({ label: t('Скрипт настройки'), onClick: () => openScript(s) })
    }
    const cas = cascadeOf(s)
    if (cas) {
      // проверка каскада и переход на соседний сервер - на самой карточке, в маршруте
      if (cas.status !== 'ready') {
        items.push({ label: t('Каскад: ход установки'), onClick: () => setWizard({ resume: cas }) })
      }
      items.push({
        label: t('Разобрать каскад…'),
        danger: true,
        onClick: () => setUnbuild({ c: cas }),
      })
    }
    items.push({ label: t('Выгрузить в файл'), onClick: () => setExportFor(s) })
    items.push({ label: t('Изменить'), onClick: () => openEdit(s) })
    items.push({ label: t('Заменить ключ SSH'), onClick: () => setHostKeyReplacementFor(s) })
    if (s.ssh_access_pending) items.push({
      label: t('Восстановить настройку SSH'),
      disabled: busy || formOpen,
      onClick: () => { void recoverSshAccess(s.id) },
    })
    if (s.ssh_access_pending) items.push({
      label: t('Закрыть настройку SSH без сервера…'),
      disabled: busy || formOpen,
      onClick: () => { setAbandonPassword(''); setAbandonError(null); setAbandonFor(s) },
    })
    // опасное - в конце меню за чертой, подальше от выдачи конфигов в окне клиентов
    items.push({ divider: true })
    if (online) {
      for (const p of protocols) {
        items.push({
          label: t('Удалить протокол {proto}…', { proto: p.label }),
          danger: true,
          onClick: () => {
            const ok = window.confirm(
              t('Удалить {proto} с сервера «{server}» вместе со ВСЕМИ его клиентами? Их конфиги перестанут работать. Перед удалением на ноде сохраняется снимок конфига.', {
                proto: p.label,
                server: s.name,
              }),
            )
            if (ok) setRemoveProto({ server: s, protocol: p })
          },
        })
      }
    }
    items.push({
      label: t('Удалить сервер'),
      danger: true,
      onClick: () => {
        setDeleteRemoveKey(false)
        setDeleteFor(s)
      },
    })
    return items
  }

  const q = query.trim().toLowerCase()
  const filtering = q !== '' || onlyProblems
  const visibleGroups = useMemo(
    () =>
      groupList
        .map((g) => ({
          ...g,
          items: g.items.filter((item) => {
            if (onlyProblems && !problem(item)) return false
            if (!q) return true
            return serverListMatches(item, q, (server) => {
              const info = parseCheckInfo(server)
              const labels = protocolsFromContainers(info?.amnezia_containers ?? [], info?.protocols ?? {}).map((p) => p.label)
              return [server.name, server.host, server.note, server.group_name, ...labels].join(' ')
            }, servers)
          }),
        }))
        .filter((g) => g.items.length > 0),
    [groupList, onlyProblems, q, problem, servers],
  )
  const visibleFlat = visibleGroups.flatMap((g) => g.items)
  const problemCount = listed.filter(problem).length
  const { item: selectedItem, server: selected } = resolveServerSelection(visibleFlat, selection)

  function selectItem(item: ServerListItem, server?: Server) {
    const node = server ?? item.members.find((member) => member.id === selection.serverId) ?? item.anchor
    const nextSelection = { key: item.key, serverId: node?.id ?? null }
    setSelection(nextSelection)
    try {
      localStorage.setItem('acontrol_selected_row', item.key)
      if (node) localStorage.setItem('acontrol_selected_server', String(node.id))
      else localStorage.removeItem('acontrol_selected_server')
    } catch {
      // приватный режим: просто не запоминаем
    }
    const url = new URL(window.location.href)
    url.search = serverSelectionParams(url.searchParams, item, node).toString()
    if (url.href !== window.location.href) {
      const state = window.history.state && typeof window.history.state === 'object' ? window.history.state : {}
      window.history.pushState({ ...state, acontrolServerSelection: nextSelection }, '', url)
    }
    // на телефоне карточка под списком: прокручиваем к ней
    if (window.matchMedia('(max-width: 900px)').matches) {
      requestAnimationFrame(() =>
        detailRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' }),
      )
    }
  }

  function select(server: Server) {
    const item = selectedItem?.members.some((member) => member.id === server.id)
      ? selectedItem : listed.find((row) => row.members.some((member) => member.id === server.id))
    if (item) selectItem(item, server)
  }

  function groupSummary(list: ServerListItem[]) {
    const online = serverListClients(list, stats).online
    const bad = list.filter(problem).length
    return (
      <span className="group-sum">
        {t('{n} онлайн', { n: online })}
        {bad > 0 && <span className="group-sum-bad"> · {t('проблем: {n}', { n: bad })}</span>}
      </span>
    )
  }

  return (
    <section>
      <div className="page-head">
        <h2>{t('Серверы')}</h2>
        <div className="page-head-actions">
          <button className="ghost" onClick={() => setFileImportOpen(true)}>
            {t('Из файла')}
          </button>
          <button className="ghost" onClick={() => setImportOpen(true)}>
            {t('Импорт')}
          </button>
          <button className="ghost" onClick={() => setWizard({})}>
            {t('+ Каскад')}
          </button>
          <button onClick={openCreate}>{t('+ Добавить сервер')}</button>
        </div>
      </div>

      {notice && <p className="form-notice">{notice}</p>}
      {error && <p className="form-error">{error}</p>}
      {loading && <p className="muted">{t('загрузка…')}</p>}

      {!loading && listed.length === 0 && (
        <div className="card">
          <p className="muted">
            {t('Серверов пока нет — добавьте первый: имя, хост и SSH-доступ.')}
          </p>
        </div>
      )}

      {listed.length > 0 && (
        <div className="srv-split">
          <div className="srv-side">
            <div className="srv-side-tools">
              <input
                className="srv-search"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder={t('Имя, IP, заметка, протокол')}
              />
              <div className="srv-side-chips">
                <button
                  className={`srv-fchip${!onlyProblems ? ' on' : ''}`}
                  onClick={() => setOnlyProblems(false)}
                >
                  {t('Все')} <b>{listed.length}</b>
                </button>
                <button
                  className={`srv-fchip${onlyProblems ? ' on bad' : ''}`}
                  onClick={() => setOnlyProblems(true)}
                  disabled={problemCount === 0 && !onlyProblems}
                >
                  {t('Проблемы')} <b>{problemCount}</b>
                </button>
              </div>
            </div>
            <div className="srv-side-list">
              {visibleGroups.length === 0 && (
                <p className="muted small srv-side-empty">{t('Ничего не найдено')}</p>
              )}
              {visibleGroups.map((g) => {
                const open = filtering || !collapsed[g.name]
                return (
                  <div className="srv-side-group" key={g.name || '__ungrouped'}>
                    {hasGroups && (
                      <button
                        type="button"
                        className={`srv-side-gh${dropHint === `grp-${g.name}` ? ' drag-over' : ''}`}
                        onClick={() => toggleGroup(g.name)}
                        onDragOver={(e) => {
                          if (dragServer.current != null || dragGroup.current != null) {
                            e.preventDefault()
                            if (dropHint !== `grp-${g.name}`) setDropHint(`grp-${g.name}`)
                          }
                        }}
                        onDragLeave={() => {
                          if (dropHint === `grp-${g.name}`) setDropHint(null)
                        }}
                        onDrop={() => {
                          if (dragServer.current != null) dropServerOnGroup(g.name)
                          else if (dragGroup.current != null) dropGroupOnGroup(g.name)
                        }}
                      >
                        {g.name !== '' && !filtering && (
                          <span
                            className="drag-handle"
                            draggable
                            title={t('Перетащить группу')}
                            onClick={(e) => e.stopPropagation()}
                            onDragStart={(e) => {
                              dragGroup.current = g.name
                              dragServer.current = null
                              e.dataTransfer.effectAllowed = 'move'
                              e.dataTransfer.setData('text/plain', g.name)
                            }}
                            onDragEnd={() => {
                              dragGroup.current = null
                              setDropHint(null)
                            }}
                          >
                            ⠿
                          </span>
                        )}
                        <span className="group-caret">{open ? '▾' : '▸'}</span>
                        <span className="group-name">{g.name || t('Без группы')}</span>
                        <span className="group-count">{g.items.length}</span>
                        {groupSummary(g.items)}
                      </button>
                    )}
                    {open &&
                      g.items.map((item) => {
                        const s = item.anchor
                        const cas = item.cascade
                        const route = serverListRoute(item, servers)
                        const st = serverListClients([item], stats)
                        const draggable = !!s && !sharedAnchors.has(s.id)
                        const routeTitle = route
                          ? `${route.entry.name}: ${route.entry.host} → ${route.exit.name}: ${route.exit.host}`
                          : item.members.map((server) => `${server.name}: ${server.host}`).join(' → ')
                        return (
                          <button
                            type="button"
                            key={item.key}
                            className={`srv-item${selectedItem?.key === item.key ? ' selected' : ''}${
                              problem(item) ? ' server-down' : ''
                            }${s && dropHint === `srv-${s.id}` ? ' drag-over' : ''}`}
                            aria-pressed={selectedItem?.key === item.key}
                            onClick={() => selectItem(item)}
                            title={routeTitle}
                            aria-label={route ? `${t('Каскад')}: ${routeTitle}${st.available ? `, ${st.online}/${st.total}` : ''}` : undefined}
                            onDragOver={(e) => {
                              if (s && draggable && dragServer.current != null) {
                                e.preventDefault()
                                if (dropHint !== `srv-${s.id}`) setDropHint(`srv-${s.id}`)
                              }
                            }}
                            onDragLeave={() => {
                              if (s && dropHint === `srv-${s.id}`) setDropHint(null)
                            }}
                            onDrop={() => { if (s && draggable) dropOnServer(s.id) }}
                          >
                            {!filtering && s && draggable && (
                              <span
                                className="drag-handle"
                                draggable
                                title={t('Перетащить')}
                                onClick={(e) => e.stopPropagation()}
                                onDragStart={(e) => {
                                  dragServer.current = s.id
                                  dragGroup.current = null
                                  e.dataTransfer.effectAllowed = 'move'
                                  e.dataTransfer.setData('text/plain', String(s.id))
                                }}
                                onDragEnd={() => {
                                  dragServer.current = null
                                  setDropHint(null)
                                }}
                              >
                                ⠿
                              </span>
                            )}
                            <ListStatusDot item={item} />
                            {route ? (
                              <CascadeListName route={route} />
                            ) : s && <>
                              {countryFlag(s.country) && <span className="server-flag" title={s.country}>{countryFlag(s.country)}</span>}
                              {s.egress_ip && <span className="srv-item-route" title={t('выход в интернет: {ip}', { ip: s.egress_ip })}>→ <span className="server-flag">{countryFlag(s.egress_country) || '?'}</span></span>}
                              <span className="srv-item-name">{s.name}</span>
                              {item.sharedExitCount > 1 && <span className="srv-shared-exit-tag" title={t('Общий выход для {n} каскадов', { n: item.sharedExitCount })}>{t('Выход')} · {item.sharedExitCount}</span>}
                              <GreBadge server={s} />
                            </>}
                            {st.available && (
                              <span className="srv-item-cl" title={cas
                                ? item.exit && !item.countedMembers.some(s => s.id === item.exit!.id)
                                  ? t('Клиенты входа: онлайн / всего') : t('Клиенты входа и выхода: онлайн / всего')
                                : t('онлайн / всего клиентов')}>
                                <b>{st.online}</b>/{st.total}
                              </span>
                            )}
                          </button>
                        )
                      })}
                  </div>
                )
              })}
            </div>
          </div>

          <div className="srv-detail-wrap" ref={detailRef}>
            {selected ? (
              <>
              {selectedItem?.sharedExitCount > 1 && <div className="card srv-shared-exit-card">
                <strong>{t('Общий выход для {n} каскадов', { n: selectedItem.sharedExitCount })}</strong>
                <p className="muted small">{t('Клиенты этого сервера учитываются один раз. Выберите вход, чтобы открыть конкретный каскад.')}</p>
                <div className="srv-shared-exit-links">
                  {cascades.filter(c => c.exit_server_id === selected.id).map(c => {
                    const entry = servers.find(s => s.id === c.entry_server_id)
                    const item = listed.find(row => row.cascade?.id === c.id)
                    return <button className="ghost" key={c.id} disabled={!item} onClick={() => item && selectItem(item, selected)}>
                      {entry?.name || c.entry_ip} → {selected.name}
                    </button>
                  })}
                </div>
              </div>}
              <ServerDetail
                server={selected}
                metric={metrics[selected.id]}
                stat={stats[selected.id]}
                checking={checkingId === selected.id}
                menu={serverMenu(selected)}
                onCheck={() => check(selected)}
                onClients={(proto) => {
                  setClientsTab(proto)
                  setClientsFor(selected)
                }}
                cascade={cascadeOf(selected)}
                peer={cascadePeer(selected, cascadeOf(selected))}
                onCascade={(c) => setWizard({ resume: c })}
                onOpen={select}
                onCascadeCheck={setCasCheck}
                onCascadeRoutes={setCasRoutes}
                onEgressCheck={() => setEgressCheck(selected)}
              />
              </>
            ) : selectedItem?.cascade ? (
              <div className="card srv-detail">
                <CascadeRoute cascade={selectedItem.cascade} entry={selectedItem.entry} exit={selectedItem.exit}
                  onOpen={select} />
                <button className="ghost" onClick={() => setWizard({ resume: selectedItem.cascade })}>
                  {t('Подробнее')}
                </button>
                <p className="muted">{t('Узлы каскада недоступны. Откройте ход установки или обновите список.')}</p>
              </div>
            ) : (
              <div className="card srv-detail muted">{t('Ничего не найдено')}</div>
            )}
          </div>
        </div>
      )}

      {formOpen && (
        <div className="modal-backdrop">
          <form
            className="card modal"
            onClick={(e) => e.stopPropagation()}
            onSubmit={submit}
            aria-busy={busy}
          >
            <h3>{editingId === null ? t('Новый сервер') : t('Изменить сервер')}</h3>
            <fieldset disabled={busy} style={{ display: 'contents' }}>
              <label>
                {t('Имя')}
                <input
                  value={form.name}
                  onChange={(e) => setForm({ ...form, name: e.target.value })}
                  placeholder="kz-almaty-1"
                  required
                />
              </label>
              <label>
                {t('Хост (IP или домен)')}
                <input
                  value={form.host}
                  onChange={(e) => setForm({ ...form, host: e.target.value })}
                  placeholder="203.0.113.10"
                  required
                />
              </label>
              <div className="server-ssh-endpoint">
                <label>
                  {t('SSH-порт')}
                  <input
                    type="number"
                    min={1}
                    max={65535}
                    value={form.ssh_port}
                    onChange={(e) =>
                      setForm({ ...form, ssh_port: Number(e.target.value) })
                    }
                    required
                  />
                </label>
                <label>
                  {t('SSH-пользователь')}
                  <input
                    value={form.ssh_user}
                    onChange={(e) => setForm({ ...form, ssh_user: e.target.value })}
                    required
                  />
                </label>
              </div>
              <SshAccessEditor value={form} servers={servers} serverId={editingId} onChange={update => { setForm({ ...form, ...update }); setSshPreview(null) }} />
              {editingId !== null && editingServer?.ssh_access_pending && (
                <button type="button" className="ghost" disabled={busy} onClick={() => { void recoverSshAccess(editingId, true) }}>
                  {t('Восстановить настройку SSH')}
                </button>
              )}
              {sshPreview && <div className="bootstrap-block" role="status">
                <b>{t('Предпросмотр изменения SSH')}</b>
                <p>{t('Разрешенные источники')}: {sshPreview.unrestricted ? t('Без ограничения') : sshPreview.sources.join(', ')}</p>
                <ul>{sshPreview.actions.map(action => <li key={action}>{t(action)}</li>)}</ul>
                {sshPreview.jump_user && <p>{t('На промежуточной ноде будет настроен отдельный пользователь и его SSH drop-in, разрешающий только соединение к этой цели.')}</p>}
                <p className="muted small">{t('При сбое панель восстанавливает прежний ключ и удаляет только свои новые правила firewall. Если подтверждение отката не получено, сохранится операция восстановления.')}</p>
              </div>}
              <label>
                {t('Адрес VPN для клиентов (Client Endpoint)')}
                <input
                  value={form.client_endpoint}
                  onChange={(e) => setForm({ ...form, client_endpoint: e.target.value })}
                  placeholder="vpn.example.com"
                  maxLength={255}
                  autoComplete="off"
                  spellCheck={false}
                  aria-describedby="server-client-endpoint-help"
                />
                <small className="muted" id="server-client-endpoint-help">
                  {t('Домен или IP без порта для AmneziaWG и WireGuard. Если поле пустое, новые профили используют хост SSH, а у сохраненных остается исходный адрес.')}
                </small>
              </label>
              <label>
                {t('Страна сервера')}
                <input className="mono" value={form.country_override ?? ''} maxLength={2} pattern="[A-Za-z]{2}"
                  placeholder={t('Автоматически')} autoCapitalize="characters" spellCheck={false}
                  onChange={event => setForm({ ...form, country_override: event.target.value.toUpperCase() })} />
                <small className="muted">{t('Пусто — авто по адресу SSH или публичному выходу самого сервера. Изменение страны не применяет маршруты действующего каскада.')}</small>
              </label>
              <label>
                {t('Заметка')}
                <input
                  value={form.note}
                  onChange={(e) => setForm({ ...form, note: e.target.value })}
                  placeholder={t('необязательно')}
                />
              </label>
              <label>
                {t('Группа (папка)')}
                <input
                  list="acontrol-groups"
                  value={form.group_name}
                  onChange={(e) => setForm({ ...form, group_name: e.target.value })}
                  placeholder={t('необязательно — компания, локация…')}
                />
                <datalist id="acontrol-groups">
                  {existingGroups.map((g) => (
                    <option key={g} value={g} />
                  ))}
                </datalist>
              </label>

              {editingId !== null && form.manual_exit_name !== undefined && <>
                <label>{t('Название выхода')}
                  <input value={form.manual_exit_name || ''} maxLength={128}
                    onChange={e => setForm({ ...form, manual_exit_name: e.target.value })}
                    placeholder={t('необязательно')} />
                </label>
                <p className="muted small">{t('В списке используется имя известного сервера, иначе это название или адрес выхода.')}</p>
              </>}

              {editingId !== null && (
                <div className="torrent-opts">
                  <label className="checkbox">
                    <input
                      type="checkbox"
                      checked={!!form.alerts_enabled}
                      onChange={(e) =>
                        setForm({ ...form, alerts_enabled: e.target.checked })
                      }
                    />
                    {t('Присылать алерты этого сервера')}
                  </label>
                  <p className="muted small">
                    {t(
                      'По умолчанию выключено. Включает алерты о доступности, каскаде, клиентах, диске и торрентах этого сервера.',
                    )}
                  </p>
                  <label className="checkbox">
                    <input
                      type="checkbox"
                      checked={!!form.torrent_block}
                      onChange={(e) =>
                        setForm({
                          ...form,
                          torrent_block: e.target.checked,
                          torrent_autopause: e.target.checked ? form.torrent_autopause : false,
                        })
                      }
                    />
                    {t('Блокировать торренты')}
                  </label>
                  {form.torrent_block && (
                    <label className="checkbox torrent-sub">
                      <input
                        type="checkbox"
                        checked={!!form.torrent_autopause}
                        onChange={(e) => setForm({ ...form, torrent_autopause: e.target.checked })}
                      />
                      {t('Ставить на паузу того, кто качает')}
                    </label>
                  )}
                  <p className="muted small">
                    {t(
                      'AmneziaWG и OpenVPN: торрент-трафик режется на сервере, у клиента в списке видна отметка. При включенных алертах приходит уведомление. Шифрованные торренты могут пройти, XRay не охвачен.',
                    )}
                  </p>
                </div>
              )}

              {editingId === null && (
                <div className="bootstrap-block">
                  <div className="setup-choice">
                    <label
                      className={`setup-option${useBootstrap ? ' setup-option-active' : ''}`}
                    >
                      <input
                        type="radio"
                        name="setup-method"
                        checked={useBootstrap}
                        onChange={() => setUseBootstrap(true)}
                      />
                      <div>
                        <span className="setup-option-title">
                          {t('Автоматически по SSH-паролю')}
                        </span>
                        <span className="setup-option-desc">
                          {t('Панель сама зайдёт по паролю и всё настроит')}
                        </span>
                      </div>
                    </label>
                    <label
                      className={`setup-option${!useBootstrap ? ' setup-option-active' : ''}`}
                    >
                      <input
                        type="radio"
                        name="setup-method"
                        checked={!useBootstrap}
                        onChange={() => setUseBootstrap(false)}
                      />
                      <div>
                        <span className="setup-option-title">
                          {t('Скриптом — запущу на сервере сам')}
                        </span>
                        <span className="setup-option-desc">
                          {t('Панель подготовит скрипт с выбранными настройками SSH и firewall')}
                        </span>
                      </div>
                    </label>
                  </div>
                  {useBootstrap ? (
                    <>
                      <p className="muted small">
                        {t(
                          'Панель один раз зайдет по паролю, установит свой ключ с выбранными ограничениями и проверит вход по нему. Пароль не сохраняется.',
                        )}
                      </p>
                      <p className="muted small">
                        {t(
                          'Если firewall блокирует вход по SSH со стороны панели или промежуточной ноды, выберите ручную настройку и запустите скрипт на целевом сервере.',
                        )}
                      </p>
                      <label>
                        {t('SSH-пароль пользователя {user}', { user: form.ssh_user })}
                        <input
                          type="password"
                          value={password}
                          onChange={(e) => setPassword(e.target.value)}
                          autoComplete="new-password"
                          required
                        />
                      </label>
                      {showAdvanced ? (
                        <label>
                          {t('Пароль для sudo (если отличается)')}
                          <input
                            type="password"
                            value={sudoPassword}
                            onChange={(e) => setSudoPassword(e.target.value)}
                            autoComplete="new-password"
                          />
                        </label>
                      ) : (
                        <button
                          type="button"
                          className="linklike"
                          onClick={() => setShowAdvanced(true)}
                        >
                          {t('Отдельный пароль для sudo?')}
                        </button>
                      )}
                    </>
                  ) : (
                    <p className="muted small">
                      {t(
                        'После «Сохранить» панель покажет скрипт. Выполните его под root: он создаст пользователя «{user}», обновит только ключ панели и применит выбранный режим firewall. Затем нажмите «Проверить».',
                        { user: form.ssh_user },
                      )}
                    </p>
                  )}
                </div>
              )}
            </fieldset>

            {savedSsh && editingServer && !accessChanged(editingServer, form) && (
              <div className="bootstrap-block" role="status">
                <p>{t('Настройки SSH применены. Остальные изменения еще не сохранены.')}</p>
                {savedSsh.warning && <p>{t(savedSsh.warning)}</p>}
              </div>
            )}
            {hostKeyConfirm && (
              <div className="bootstrap-block" role="status">
                <p>{t('Сервер добавлен. Перед отправкой пароля сверьте ключ SSH сервера:')}</p>
                <p className="mono">{hostKeyConfirm.fingerprint} ({hostKeyConfirm.key_type})</p>
                <p className="muted small">
                  {t('На самом сервере (консоль хостера или уже открытая сессия) выполните')}{' '}
                  <span className="mono">ssh-keygen -lf /etc/ssh/ssh_host_{keyFileType(hostKeyConfirm.key_type)}_key.pub</span>.{' '}
                  {t('Отпечатки должны совпасть. Пароль уйдет только серверу с этим ключом.')}
                </p>
              </div>
            )}
            {formError && <p className="error" role="alert">{t(formError)}</p>}
            <div className="modal-actions">
              <button type="button" className="ghost" disabled={busy} onClick={hostKeyConfirm ? () => void declineHostKey() : closeForm}>
                {hostKeyConfirm ? t('Не отправлять пароль') : t('Отмена')}
              </button>
              <button type="submit" disabled={busy || editingServer?.ssh_access_pending}>
                {busy ? t(busyLabel) : hostKeyConfirm ? t('Ключ совпадает, подключиться') : sshPreview ? t('Применить SSH и сохранить') : t('Сохранить')}
              </button>
            </div>
          </form>
        </div>
      )}

      {clientsFor && (
        <ClientsModal
          server={clientsFor}
          initialProtocol={clientsTab}
          protocols={protocolsFromContainers(
            parseCheckInfo(clientsFor)?.amnezia_containers ?? [],
            parseCheckInfo(clientsFor)?.protocols ?? {},
          )}
          onClose={() => setClientsFor(null)}
          onUnauthorized={onUnauthorized}
          onRequestUpdate={(protocol) => {
            const srv = clientsFor
            if (!srv) return
            // на ноде с AmneziaWG 3.0 пересборка мигрирует конфиг до 3.1, и старые
            // клиентские конфиги перестают работать
            const migrates30 = protocol === 'awg3' && isAwg30Node(parseCheckInfo(srv))
            if (
              !window.confirm(
                migrates30
                  ? t(
                      'Пересобрать "{name}"? На ноде стоит AmneziaWG 3.0: конфиг мигрирует до 3.1, ключ сервера и порт сохраняются, но выданные конфиги клиентов работать перестанут, всех клиентов придется перевыпустить. Перед пересборкой снимается снимок для отката.',
                      { name: srv.name },
                    )
                  : t(
                      'Пересобрать образ на «{name}»? Текущие клиенты и ключи сохраняются.',
                      { name: srv.name },
                    ),
              )
            )
              return
            setClientsFor(null)
            setDeployFor({ server: srv, mode: 'update', protocol })
          }}
          onRequestUpgrade31={() => {
            const srv = clientsFor
            if (!srv) return
            if (
              !window.confirm(
                t(
                  'Обновить протокол на «{name}» до AmneziaWG 3.1?\n\nОбновление идёт внутри того же контейнера: порт, ключ сервера и подсеть сохраняются, приложение AmneziaVPN увидит 3.1 в «полном доступе».\n\nВАЖНО: выданные ранее конфиги 2.0 работать перестанут — всех клиентов придётся перевыпустить. Перед обновлением снимается снимок для отката.',
                  { name: srv.name },
                ),
              )
            )
              return
            setClientsFor(null)
            setDeployFor({ server: srv, mode: 'upgrade31', protocol: 'awg' })
          }}
          onRequestAdopt={() => {
            const srv = clientsFor
            if (!srv) return
            if (
              !window.confirm(
                t(
                  'Взять AmneziaWG на «{name}» под управление панели?\n\nПанель перечитает текущий конфиг, сохранит порт и ключи и заменит контейнер своим. Клиенты остаются рабочими, туннель кратко перезапустится. Перед этим снимается снимок для отката.',
                  { name: srv.name },
                ),
              )
            )
              return
            setClientsFor(null)
            setDeployFor({ server: srv, mode: 'adopt', protocol: 'awg' })
          }}
        />
      )}

      {exportFor && (
        <ServerExportModal
          server={exportFor}
          onClose={() => setExportFor(null)}
          onUnauthorized={onUnauthorized}
        />
      )}

      {fileImportOpen && (
        <ServerImportModal
          onClose={() => setFileImportOpen(false)}
          onDone={() => void load()}
          onUnauthorized={onUnauthorized}
        />
      )}

      {importOpen && (
        <ImportModal
          onClose={() => setImportOpen(false)}
          onDone={load}
          onUnauthorized={onUnauthorized}
        />
      )}

      {deployFor && (
        <DeployModal
          serverId={deployFor.server.id}
          serverName={deployFor.server.name}
          mode={deployFor.mode}
          protocol={deployFor.protocol}
          onClose={() => setDeployFor(null)}
          onDone={() => check(deployFor.server)}
          onUnauthorized={onUnauthorized}
        />
      )}

      {abandonFor && (
        <div className="modal-backdrop">
          <form
            className="card modal"
            onClick={(e) => e.stopPropagation()}
            onSubmit={(e) => { e.preventDefault(); void abandonSshAccess() }}
          >
            <h3>{t('Закрыть настройку SSH · {name}', { name: abandonFor.name })}</h3>
            <p className="muted small">
              {t('Панель сначала попробует обычное восстановление. Если сервер недоступен, незавершенная настройка будет закрыта без проверки сервера: состояние ключа панели и firewall на нем останется неизвестным. Используйте это, только если сервер удален или недоступен навсегда. После этого снова работают бэкапы, удаление сервера и настройка SSH.')}
            </p>
            {abandonError && <p className="form-error">{t(abandonError)}</p>}
            <input
              type="password"
              autoFocus
              autoComplete="current-password"
              placeholder={t('Пароль')}
              value={abandonPassword}
              onChange={(e) => setAbandonPassword(e.target.value)}
            />
            <div className="modal-actions">
              <button type="button" className="ghost" disabled={busy} onClick={() => setAbandonFor(null)}>
                {t('Отмена')}
              </button>
              <button type="submit" className="danger-solid" disabled={!abandonPassword || busy}>
                {busy ? t('Восстановление…') : t('Закрыть настройку')}
              </button>
            </div>
          </form>
        </div>
      )}

      {faStepUp && (
        <div className="modal-backdrop">
          <form
            className="card modal"
            onClick={(e) => e.stopPropagation()}
            onSubmit={(e) => {
              e.preventDefault()
              if (faStepUp) void exportFullAccess(faStepUp, faPassword)
            }}
          >
            <h3>{t('Подтвердите пароль')}</h3>
            <p className="muted small">
              {t(
                'Ссылка «Полного доступа» содержит SSH-ключ управления сервером (по сути root). Введите пароль от панели, чтобы продолжить.',
              )}
            </p>
            {error && <p className="form-error">{error}</p>}
            <input
              type="password"
              autoFocus
              autoComplete="current-password"
              placeholder={t('Пароль')}
              value={faPassword}
              onChange={(e) => setFaPassword(e.target.value)}
            />
            <div className="modal-actions">
              <button
                type="button"
                className="ghost"
                onClick={() => setFaStepUp(null)}
              >
                {t('Отмена')}
              </button>
              <button
                type="submit"
                disabled={!faPassword || faBusyId === faStepUp.id}
              >
                {faBusyId === faStepUp.id ? t('Генерация…') : t('Подтвердить')}
              </button>
            </div>
          </form>
        </div>
      )}

      {fullAccess && (
        <div className="modal-backdrop">
          <div className="card modal modal-wide" onClick={(e) => e.stopPropagation()}>
            <h3>{t('Полный доступ · {name}', { name: fullAccess.server.name })}</h3>
            <p className="muted small">
              {t(
                'Вставьте эту ссылку в приложении AmneziaVPN (на компьютере или телефоне): «+» → «Настроить свой сервер» → вставить из буфера. Сервер добавится как управляемый — можно выдавать конфиги и ставить протоколы прямо из приложения. Подключение пойдёт по SSH под пользователем',
              )}{' '}
              <span className="mono">{fullAccess.user}</span> {t('(нужен доступ к docker — группа docker или sudo).')}
            </p>
            <p className="form-error small">
              {t(
                '⚠️ Ссылка содержит приватный SSH-ключ управления сервером — не публикуйте её и не пересылайте. Ключ работает с любого адреса, без срока, пока его не отзовут: «Отозвать полный доступ» в меню сервера. При повторной генерации прежний ключ перестаёт работать.',
              )}
            </p>
            <pre className="script-box">{fullAccess.config}</pre>
            <div className="modal-actions">
              <button className="ghost" onClick={() => setFullAccess(null)}>
                {t('Закрыть')}
              </button>
              <button
                className="ghost"
                onClick={() => {
                  const blob = new Blob([fullAccess.config], { type: 'text/plain' })
                  const url = URL.createObjectURL(blob)
                  const a = document.createElement('a')
                  a.href = url
                  a.download = `${fullAccess.server.name.replace(/[^a-zA-Z0-9_-]+/g, '_')}-fullaccess.txt`
                  a.click()
                  URL.revokeObjectURL(url)
                }}
              >
                {t('Скачать .txt')}
              </button>
              <button
                onClick={async () => setFaCopied(await copyText(fullAccess.config))}
              >
                {faCopied ? t('Скопировано ✓') : t('Скопировать')}
              </button>
            </div>
          </div>
        </div>
      )}

      {wizard && (
        <CascadeWizard
          servers={servers}
          cascades={cascades}
          defaultUser={config?.default_ssh_user ?? FALLBACK_USER}
          resume={wizard.resume}
          replacement={wizard.replacement}
          onClose={() => setWizard(null)}
          onRemove={(c) => {
            setWizard(null)
            setUnbuild({ c })
          }}
          onChanged={() => void load()}
          onUnauthorized={onUnauthorized}
        />
      )}

      {unbuild && (
        <div className="modal-backdrop">
          <div className="card modal" onClick={(e) => e.stopPropagation()}>
            <h3>{t('Разобрать каскад?')}</h3>
            <p className="muted small">
              {t(
                'Панель уберет шлюз и туннель с обоих серверов. Клиенты входа останутся подключенными, но в интернет пойдут с адреса самого входа.',
              )}
            </p>
            {cascades.some(c => c.id !== unbuild.c.id && c.exit_server_id === unbuild.c.exit_server_id) && <p className="muted small">
              {t('Будет удален только выбранный каскад. Другие входы и собственные клиенты общего выхода сохраняются.')}
            </p>}
            {unbuild.error && <p className="small err-text" role="alert">{unbuild.error}</p>}
            {unbuild.canForget && (
              <p className="muted small">{t('Если убрать запись из панели, на серверах могут остаться шлюз и туннель.')}</p>
            )}
            <div className="modal-actions">
              <button className="ghost" disabled={unbuilding} onClick={() => setUnbuild(null)}>
                {t('Отмена')}
              </button>
              {unbuild.canForget && (
                <button className="ghost" disabled={unbuilding} onClick={() => confirmUnbuild(true)}>
                  {t('Убрать только из панели')}
                </button>
              )}
              {unbuild.canForget && (
                <button className="ghost" disabled={unbuilding} onClick={() => confirmUnbuild(true, true)}>
                  {t('Разобрать и выбрать новый выход')}
                </button>
              )}
              <button
                className="danger-solid"
                disabled={unbuilding}
                onClick={() => confirmUnbuild(false)}
              >
                {unbuilding ? t('Разбираю…') : t('Разобрать')}
              </button>
            </div>
          </div>
        </div>
      )}

      {siteCheckFor && <SiteCheckModal server={servers.find((server) => server.id === siteCheckFor.id) || siteCheckFor} onClose={() => setSiteCheckFor(null)} onUnauthorized={onUnauthorized} />}
      {hostKeyReplacementFor && <HostKeyReplacement server={hostKeyReplacementFor} onClose={() => setHostKeyReplacementFor(null)}
        onReplaced={() => {
          setHostKeyReplacementFor(null)
          setNotice(t('Ключ SSH заменен'))
          void check(hostKeyReplacementFor)
        }} />}
      {egressCheck && (
        <EgressCheckModal
          server={egressCheck}
          onClose={() => setEgressCheck(null)}
          onChecked={() => void load()}
          onUnauthorized={onUnauthorized}
        />
      )}
      {casRoutes && (
        <CascadeRoutesModal
          cascade={casRoutes}
          entry={servers.find((server) => server.id === casRoutes.entry_server_id)}
          exit={servers.find((server) => server.id === casRoutes.exit_server_id)}
          onClose={() => setCasRoutes(null)}
          onUnauthorized={onUnauthorized}
          onSaved={(saved) => {
            setCascades((prev) => prev.map((row) => row.id === saved.id ? saved : row))
            setCasRoutes(null)
          }}
        />
      )}
      {casCheck && (
        <CascadeCheckModal
          cascade={casCheck}
          entry={servers.find((x) => x.id === casCheck.entry_server_id)}
          exit={servers.find((x) => x.id === casCheck.exit_server_id)}
          onClose={() => setCasCheck(null)}
          onChecked={() => void load()}
          onUnauthorized={onUnauthorized}
        />
      )}
      {removeProto && (
        <RemoveProtocolModal
          serverId={removeProto.server.id}
          serverName={removeProto.server.name}
          protocol={removeProto.protocol}
          onCancel={() => setRemoveProto(null)}
          onUnauthorized={onUnauthorized}
          onRemoved={() => {
            const srv = removeProto.server
            setRemoveProto(null)
            setNotice(t('Протокол удален с сервера «{name}», снимок конфига остался на ноде.', { name: srv.name }))
            void load()
          }}
        />
      )}
      {deleteFor && (
        <div className="modal-backdrop">
          <div className="card modal" onClick={(e) => e.stopPropagation()}>
            <h3>{t('Удалить сервер «{name}»?', { name: deleteFor.name })}</h3>
            <p className="muted small">
              {t(
                'Сервер и VPN не тронутся — он только пропадёт из панели. Все выданные клиентские конфиги останутся рабочими.',
              )}
            </p>
            <label className="checkbox">
              <input
                type="checkbox"
                checked={deleteRemoveKey}
                onChange={(e) => setDeleteRemoveKey(e.target.checked)}
              />
              {t('Также убрать с сервера SSH-ключ панели и ключ полного доступа (панель зайдёт по SSH)')}
            </label>
            <div className="modal-actions">
              <button className="ghost" onClick={() => setDeleteFor(null)}>
                {t('Отмена')}
              </button>
              <button
                className="danger-solid"
                onClick={confirmDelete}
                disabled={deleting}
              >
                {deleting ? t('Удаление…') : t('Удалить')}
              </button>
            </div>
          </div>
        </div>
      )}

      {scriptFor && (
        <div className="modal-backdrop">
          <div className="card modal modal-wide" onClick={(e) => e.stopPropagation()}>
            <h3>{t('Подготовка сервера «{name}»', { name: scriptFor.server.name })}</h3>
            {scriptFor.onboardingError && <p className="error" role="alert">{scriptFor.onboardingError}</p>}
            {scriptFor.error && <p className="error" role="alert">{t(scriptFor.error)}</p>}
            {scriptFor.text === undefined && !scriptFor.error && <p className="muted" role="status">{t('загрузка…')}</p>}
            {scriptFor.text !== undefined && <>
              <p className="muted small">
                {t('Выполните этот скрипт под root на сервере. Он добавит SSH-ключ панели пользователю')}{' '}
                <b>{scriptFor.server.ssh_user}</b>{t(', применит выбранные ограничения ключа и режим firewall, сохранит остальные ключи и правила и ответит')}{' '}
                <span className="mono">ACONTROL SETUP OK</span>{t('. После этого нажмите «Проверить».')}
              </p>
              <pre className="script-box">{scriptFor.text}</pre>
            </>}
            <div className="modal-actions">
              {scriptFor.error && <button className="ghost" onClick={() => openScript(scriptFor.server, scriptFor.onboardingError)}>
                {t('Повторить')}
              </button>}
              {scriptFor.text !== undefined && scriptFor.server.ssh_jump_server_id && <button className="ghost" onClick={async () => {
                try {
                  await api(`/api/servers/${scriptFor.server.id}/ssh-access/prepare`, { method: 'POST' })
                  setNotice(t('Промежуточная SSH-нода подготовлена. Выполните скрипт на целевом сервере.'))
                } catch (err) { handleError(err) }
              }}>{t('Подготовить промежуточную ноду')}</button>}
              <button className="ghost" onClick={() => setScriptFor(null)}>
                {t('Закрыть')}
              </button>
              {scriptFor.text !== undefined && <button onClick={copyScript}>
                {copied ? t('Скопировано ✓') : t('Скопировать')}
              </button>}
            </div>
          </div>
        </div>
      )}
    </section>
  )
}
