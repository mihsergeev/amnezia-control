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
  checkCascade,
  deleteCascade,
  listCascades,
  parseCheckInfo,
  protocolsFromContainers,
  reorderServers,
  type Cascade,
  type NodeMetric,
  type Overview,
  type PanelConfig,
  type Protocol,
  type Server,
  type ServerForm,
  type ServerStat,
} from './api'
import { ClientsModal } from './ClientsModal'
import { ImportModal } from './ImportModal'
import { DeployModal } from './DeployModal'
import { Menu, type MenuItem } from './Menu'
import { ServerExportModal, ServerImportModal } from './ServerTransfer'
import { copyText } from './clipboard'
import { countryFlag, formatBytes, formatUptime } from './format'
import { CascadeWizard } from './CascadeWizard'
import { useI18n } from './i18n'

const FALLBACK_USER = 'acontrol'

function emptyForm(defaultUser: string): ServerForm {
  return {
    name: '',
    host: '',
    ssh_port: 22,
    ssh_user: defaultUser,
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
  return (
    <span className="tun-badge" title={t('GRE-туннель до {ip}', { ip: remotes })}>
      {withRemote ? `GRE → ${remotes}` : 'GRE'}
    </span>
  )
}

// путь трафика клиентов, когда нода - вход каскада: выход в интернет с другого адреса.
// cascade - каскад, собранный панелью: выход известен и до первой проверки адреса
function EgressRoute({
  server,
  cascade,
  exitServer,
}: {
  server: Server
  cascade?: Cascade
  exitServer?: Server
}) {
  const { t } = useI18n()
  const viaGre = !cascade && greTunnels(server).length > 0
  const exitIp = server.egress_ip || cascade?.result.egress || cascade?.exit_ip || ''
  const exitCountry = server.egress_country || exitServer?.country || ''
  const exitSub = [exitServer?.name, server.egress_org].filter(Boolean).join(', ')
  return (
    <div className="srv-route">
      <span className="srv-route-label">{t('Клиенты')}</span>
      <span className="srv-route-arrow">→</span>
      <div className="srv-hop">
        {countryFlag(server.country) && (
          <span className="server-flag">{countryFlag(server.country)}</span>
        )}
        <div>
          <div className="mono">{server.host}</div>
          <div className="muted small">{t('этот сервер')}</div>
        </div>
      </div>
      <span className="srv-route-arrow">
        {viaGre && <GreBadge server={server} />}
        {cascade && (
          <span className="tun-badge">{cascade.transport === 'gre' ? 'GRE' : 'VLESS'}</span>
        )}
        →
      </span>
      <div className="srv-hop srv-hop-exit">
        {countryFlag(exitCountry) && (
          <span className="server-flag">{countryFlag(exitCountry)}</span>
        )}
        <div>
          <div className="mono">{exitIp}</div>
          <div className="muted small">
            {exitSub
              ? t('выход в интернет, {org}', { org: exitSub })
              : t('выход в интернет')}
          </div>
        </div>
      </div>
    </div>
  )
}

// exitDown: выход каскада этого сервера не отвечает - у клиентов не открывается все, что идет через выход
function StatusDot({ server, exitDown = false }: { server: Server; exitDown?: boolean }) {
  const { t } = useI18n()
  const cls =
    server.last_check_ok === null
      ? 'dot-unknown'
      : server.last_check_ok && !exitDown
        ? 'dot-ok'
        : 'dot-fail'
  const title =
    server.last_check_ok === null
      ? t('не проверялся')
      : !server.last_check_ok
        ? t('ошибка (см. лог)')
        : exitDown
          ? t('выход каскада не отвечает')
          : t('онлайн')
  return <span className={`dot ${cls}`} title={title} />
}

function pct(used: number, total: number): number {
  return total > 0 ? Math.round((used / total) * 100) : 0
}

// пороги те же, что подсвечивают метрики в карточке: диск и память от 90%,
// загрузка от 1 на ядро - это уже проблема, а не "много"
function loadLevel(m: NodeMetric): string {
  if (m.cpu_count <= 0) return ''
  const r = m.load1 / m.cpu_count
  return r >= 1 ? 'res-crit' : r >= 0.7 ? 'res-warn' : ''
}

function pctLevel(p: number, warn: number): string {
  return p >= 90 ? 'res-crit' : p >= warn ? 'res-warn' : ''
}

function isProblem(s: Server, m: NodeMetric | undefined): boolean {
  if (s.last_check_ok === false) return true
  if (!m) return false
  return (
    loadLevel(m) === 'res-crit' ||
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
}: {
  server: Server
  metric: NodeMetric | undefined
  stat: ServerStat | undefined
  checking: boolean
  menu: MenuItem[]
  onCheck: () => void
  onClients: (proto?: Protocol['key']) => void
  // каскад панели с этим сервером и второй его сервер
  cascade?: Cascade
  peer?: Server
  onCascade: (c: Cascade) => void
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
  const loadPct = m && m.cpu_count > 0 ? Math.round((m.load1 / m.cpu_count) * 100) : 0
  const isEntry = cascade?.entry_server_id === server.id
  const health = isEntry ? cascade?.result.health : undefined
  const exitDown = isEntry && (peer?.last_check_ok === false || health?.ok === false)
  return (
    <div className={`card srv-detail${server.last_check_ok === false ? ' server-down' : ''}`}>
      <div className="srv-detail-head">
        <StatusDot server={server} exitDown={exitDown} />
        <h3 className="srv-detail-name" title={server.name}>
          {server.name}
        </h3>
        {server.group_name && <span className="group-count">{server.group_name}</span>}
        <div className="srv-detail-actions">
          {online && protocols.length > 0 && (
            <button onClick={() => onClients()}>{t('Клиенты')}</button>
          )}
          <button className="ghost" onClick={onCheck} disabled={checking}>
            {checking ? t('Проверка…') : t('Проверить')}
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

      {cascade && cascade.exit_server_id === server.id ? (
        <div className="muted small">
          {t('Выход каскада: сюда идет трафик клиентов с «{name}», своих клиентов тут нет.', {
            name: peer?.name ?? '?',
          })}
        </div>
      ) : server.egress_ip || cascade ? (
        <EgressRoute server={server} cascade={cascade} exitServer={peer} />
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
        <div className="muted small">
          {server.country
            ? t('Сайты страны входа напрямую с этого сервера, остальное через выход.')
            : t('Весь трафик клиентов идет через выход: страна этого сервера неизвестна.')}
        </div>
      )}
      {health?.ok === false && (
        <div className="small err-text cas-exit-down">
          {t('Каскад не работает с {time}: {reason}', {
            time: health.since
              ? new Date(health.since).toLocaleString(lang === 'en' ? 'en-GB' : 'ru-RU', {
                  day: 'numeric',
                  month: 'short',
                  hour: '2-digit',
                  minute: '2-digit',
                })
              : '?',
            reason: t(health.reason ?? ''),
          })}
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
                value={`${loadPct}%`}
                sub={t('загрузка {l} на {n} ядер', {
                  l: m.load1.toFixed(2),
                  n: m.cpu_count,
                })}
                bar={loadPct}
                level={loadLevel(m)}
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
          protocols.map((p) => (
            <div className="srv-proto-row" key={p.key}>
              <span className="proto-badge">{p.label}</span>
              {online && (
                <button className="primary-ghost" onClick={() => onClients(p.key)}>
                  {t('Клиенты')}
                </button>
              )}
            </div>
          ))
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
  const [selectedId, setSelectedId] = useState<number | null>(() => {
    try {
      return Number(localStorage.getItem('acontrol_selected_server')) || null
    } catch {
      return null
    }
  })
  const detailRef = useRef<HTMLDivElement>(null)
  const [config, setConfig] = useState<PanelConfig | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)

  const [form, setForm] = useState<ServerForm>(emptyForm(FALLBACK_USER))
  const [editingId, setEditingId] = useState<number | null>(null)
  const [formOpen, setFormOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  // храним ключ, а не перевод: подпись должна меняться вместе с языком
  const [busyLabel, setBusyLabel] = useState('Сохранить')

  // автонастройка по паролю (только при создании)
  const [useBootstrap, setUseBootstrap] = useState(true)
  const [password, setPassword] = useState('')
  const [sudoPassword, setSudoPassword] = useState('')
  const [showAdvanced, setShowAdvanced] = useState(false)

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
    protocol: 'awg' | 'awg3' | 'xray' | 'openvpn'
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
  const [scriptFor, setScriptFor] = useState<Server | null>(null)
  const [deleteFor, setDeleteFor] = useState<Server | null>(null)
  const [deleteRemoveKey, setDeleteRemoveKey] = useState(false)
  const [deleting, setDeleting] = useState(false)
  const [scriptText, setScriptText] = useState('')
  const [copied, setCopied] = useState(false)
  const [cascades, setCascades] = useState<Cascade[]>([])
  // мастер каскада: новый (resume нет) или ход установки уже созданного
  const [wizard, setWizard] = useState<{ resume?: Cascade } | null>(null)
  const [unbuild, setUnbuild] = useState<{ c: Cascade; error?: string } | null>(null)
  const [unbuilding, setUnbuilding] = useState(false)
  const [casChecking, setCasChecking] = useState<number | null>(null)

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
      else if (formOpen) setFormOpen(false)
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [faStepUp, fullAccess, scriptFor, deleteFor, unbuild, formOpen])

  const handleError = useCallback(
    (err: unknown) => {
      if (err instanceof ApiError && err.status === 401) {
        onUnauthorized()
        return
      }
      setError(err instanceof Error ? err.message : t('Неизвестная ошибка'))
    },
    [onUnauthorized],
  )

  const load = useCallback(async () => {
    try {
      setServers(await api<Server[]>('/api/servers'))
      setError(null)
      // метрики нод — необязательны, грузим отдельно и молча
      api<NodeMetric[]>('/api/stats/nodes')
        .then((rows) =>
          setMetrics(Object.fromEntries(rows.map((r) => [r.server_id, r]))),
        )
        .catch(() => {})
      listCascades()
        .then(setCascades)
        .catch(() => {})
      api<Overview>('/api/stats/overview')
        .then((o) => setStats(Object.fromEntries(o.per_server.map((r) => [r.id, r]))))
        .catch(() => {})
    } catch (err) {
      handleError(err)
    } finally {
      setLoading(false)
    }
  }, [handleError])

  useEffect(() => {
    void load()
    api<PanelConfig>('/api/config')
      .then(setConfig)
      .catch(() => setConfig(null))
  }, [load])

  function resetForm(defaultUser: string) {
    setForm(emptyForm(defaultUser))
    setPassword('')
    setSudoPassword('')
    setShowAdvanced(false)
    setUseBootstrap(true)
  }

  function openCreate() {
    resetForm(config?.default_ssh_user ?? FALLBACK_USER)
    setEditingId(null)
    setFormOpen(true)
  }

  function openEdit(server: Server) {
    setForm({
      name: server.name,
      host: server.host,
      ssh_port: server.ssh_port,
      ssh_user: server.ssh_user,
      note: server.note,
      group_name: server.group_name,
    })
    setEditingId(server.id)
    setFormOpen(true)
  }

  async function openScript(server: Server) {
    try {
      const { script } = await api<{ script: string }>(
        `/api/servers/${server.id}/setup-script`,
      )
      setScriptText(script)
      setScriptFor(server)
      setCopied(false)
    } catch (err) {
      handleError(err)
    }
  }

  async function copyScript() {
    setCopied(await copyText(scriptText))
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
    } catch (err) {
      handleError(err) // на неверный пароль (403) окно остаётся, показываем ошибку
    } finally {
      setFaBusyId(null)
    }
  }

  async function submit(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    setNotice(null)
    try {
      if (editingId !== null) {
        setBusyLabel('Сохранение…')
        await api<Server>(`/api/servers/${editingId}`, {
          method: 'PATCH',
          body: JSON.stringify(form),
        })
        setFormOpen(false)
        await load()
        return
      }

      setBusyLabel('Создание…')
      const created = await api<Server>('/api/servers', {
        method: 'POST',
        body: JSON.stringify(form),
      })

      if (useBootstrap && password) {
        // панель сама зайдёт по паролю, поставит ключ и настроит фаервол
        setBusyLabel('Подключаюсь и настраиваю…')
        try {
          await api<Server>(`/api/servers/${created.id}/bootstrap`, {
            method: 'POST',
            body: JSON.stringify({
              password,
              become_password: sudoPassword || null,
            }),
          })
          setFormOpen(false)
          await load()
          setNotice(t('Сервер «{name}» настроен и подключён.', { name: created.name }))
        } catch (err) {
          setFormOpen(false)
          await load()
          const msg = err instanceof Error ? err.message : t('ошибка')
          setError(
            t('Сервер создан, но автонастройка не удалась: {msg}. ', { msg }) +
              t('Откройте «Скрипт» для ручной установки.'),
          )
        }
      } else {
        // ручной путь — показываем скрипт для запуска на сервере
        setFormOpen(false)
        await load()
        await openScript(created)
      }
    } catch (err) {
      handleError(err)
    } finally {
      setBusy(false)
      setBusyLabel('Сохранить')
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
  // выходы каскадов панели: своих клиентов нет, в списке они часть сервера-входа
  const exitIds = useMemo(() => new Set(cascades.map((c) => c.exit_server_id)), [cascades])
  const listed = useMemo(() => servers.filter((s) => !exitIds.has(s.id)), [servers, exitIds])

  const groupList = useMemo(() => {
    const sorted = [...listed].sort(
      (a, b) => a.position - b.position || a.id - b.id,
    )
    const map = new Map<string, Server[]>()
    for (const s of sorted) {
      const g = s.group_name || ''
      const arr = map.get(g)
      if (arr) arr.push(s)
      else map.set(g, [s])
    }
    const names = [...map.keys()].filter((n) => n !== '')
    if (map.has('')) names.push('')
    return names.map((name) => ({ name, servers: map.get(name)! }))
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
    () => groupList.flatMap((g) => g.servers),
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
      const byGroup = new Map(groupList.map((g) => [g.name, g.servers]))
      applyOrder(order.flatMap((name) => byGroup.get(name) || []))
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
    return cascades.find((c) => c.entry_server_id === s.id || c.exit_server_id === s.id)
  }

  function exitDown(s: Server): boolean {
    const c = cascades.find((x) => x.entry_server_id === s.id)
    if (!c) return false
    if (c.result.health?.ok === false) return true
    return servers.find((x) => x.id === c.exit_server_id)?.last_check_ok === false
  }

  // проблема сервера с учетом выхода его каскада: выход в списке не виден
  function problem(s: Server): boolean {
    if (isProblem(s, metrics[s.id])) return true
    const c = cascades.find((x) => x.entry_server_id === s.id)
    if (c?.result.health?.ok === false) return true
    const exit = c && servers.find((x) => x.id === c.exit_server_id)
    return !!exit && isProblem(exit, metrics[exit.id])
  }

  function cascadePeer(s: Server, c: Cascade | undefined): Server | undefined {
    if (!c) return undefined
    const id = c.entry_server_id === s.id ? c.exit_server_id : c.entry_server_id
    return servers.find((x) => x.id === id)
  }

  async function checkCas(c: Cascade) {
    setCasChecking(c.id)
    setNotice(null)
    setError(null)
    try {
      const r = await checkCascade(c.id)
      const parts = [
        r.egress
          ? t('остальное через {ip}', { ip: r.egress })
          : t('через выход интернет не открывается'),
        r.ru ? t('местное напрямую с {ip}', { ip: r.ru }) : '',
        !r.gateway ? t('шлюз не запущен') : '',
        !r.tproxy ? t('клиенты не заворачиваются в шлюз') : '',
        c.transport === 'gre' && !r.tunnel ? t('GRE-туннеля нет') : '',
      ].filter(Boolean)
      const msg = t('Каскад: {parts}', { parts: parts.join(', ') })
      if (r.ok) setNotice(msg)
      else setError(msg)
      await load()
    } catch (err) {
      handleError(err)
    } finally {
      setCasChecking(null)
    }
  }

  async function confirmUnbuild(force: boolean) {
    if (!unbuild) return
    setUnbuilding(true)
    try {
      await deleteCascade(unbuild.c.id, force)
      setUnbuild(null)
      setNotice(t('Каскад разобран: клиенты входа снова выходят в интернет с него самого.'))
      await load()
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) onUnauthorized()
      else setUnbuild({ c: unbuild.c, error: err instanceof Error ? err.message : t('Ошибка') })
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
    const items: MenuItem[] = []
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
        label: t('Развернуть OpenVPN / Cloak'),
        onClick: () => setDeployFor({ server: s, mode: 'deploy', protocol: 'openvpn' }),
      })
    }
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
    if (!online) {
      items.push({ label: t('Скрипт настройки'), onClick: () => openScript(s) })
    }
    const cas = cascadeOf(s)
    if (cas) {
      if (cas.status === 'ready') {
        items.push({
          label: casChecking === cas.id ? t('Проверка…') : t('Каскад: проверить канал'),
          disabled: casChecking === cas.id,
          onClick: () => void checkCas(cas),
        })
      } else {
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
          servers: g.servers.filter((s) => {
            if (onlyProblems && !problem(s)) return false
            if (!q) return true
            const info = parseCheckInfo(s)
            const labels = protocolsFromContainers(
              info?.amnezia_containers ?? [],
              info?.protocols ?? {},
            ).map((p) => p.label)
            // по имени и адресу выхода находится его вход
            const exit = cascadePeer(s, cascades.find((c) => c.entry_server_id === s.id))
            return [s.name, s.host, s.note, s.group_name, ...labels, exit?.name, exit?.host]
              .join(' ')
              .toLowerCase()
              .includes(q)
          }),
        }))
        .filter((g) => g.servers.length > 0),
    [groupList, metrics, onlyProblems, q, cascades, servers],
  )
  const visibleFlat = visibleGroups.flatMap((g) => g.servers)
  const problemCount = listed.filter(problem).length
  const selected =
    visibleFlat.find((s) => s.id === selectedId) ?? visibleFlat[0] ?? null

  function select(s: Server) {
    setSelectedId(s.id)
    try {
      localStorage.setItem('acontrol_selected_server', String(s.id))
    } catch {
      // приватный режим: просто не запоминаем
    }
    // на телефоне карточка под списком: прокручиваем к ней
    if (window.matchMedia('(max-width: 900px)').matches) {
      requestAnimationFrame(() =>
        detailRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' }),
      )
    }
  }

  function groupSummary(list: Server[]) {
    const online = list.reduce((a, s) => a + (stats[s.id]?.clients_online ?? 0), 0)
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

      {!loading && servers.length === 0 && (
        <div className="card">
          <p className="muted">
            {t('Серверов пока нет — добавьте первый: имя, хост и SSH-доступ.')}
          </p>
        </div>
      )}

      {servers.length > 0 && (
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
                        <span className="group-count">{g.servers.length}</span>
                        {groupSummary(g.servers)}
                      </button>
                    )}
                    {open &&
                      g.servers.map((s) => {
                        const st = stats[s.id]
                        return (
                          <button
                            type="button"
                            key={s.id}
                            className={`srv-item${selected?.id === s.id ? ' selected' : ''}${
                              s.last_check_ok === false ? ' server-down' : ''
                            }${dropHint === `srv-${s.id}` ? ' drag-over' : ''}`}
                            onClick={() => select(s)}
                            title={s.host}
                            onDragOver={(e) => {
                              if (dragServer.current != null) {
                                e.preventDefault()
                                if (dropHint !== `srv-${s.id}`) setDropHint(`srv-${s.id}`)
                              }
                            }}
                            onDragLeave={() => {
                              if (dropHint === `srv-${s.id}`) setDropHint(null)
                            }}
                            onDrop={() => dropOnServer(s.id)}
                          >
                            {!filtering && (
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
                            <StatusDot server={s} exitDown={exitDown(s)} />
                            {countryFlag(s.country) && (
                              <span className="server-flag" title={s.country}>
                                {countryFlag(s.country)}
                              </span>
                            )}
                            {(() => {
                              // вход каскада: стрелка и флаг страны выхода
                              const cas = cascadeOf(s)
                              const isEntry = cas?.entry_server_id === s.id
                              if (!s.egress_ip && !isEntry) return null
                              const peer = isEntry ? cascadePeer(s, cas) : undefined
                              const ip = s.egress_ip || cas?.exit_ip || ''
                              return (
                                <span
                                  className="srv-item-route"
                                  title={t('выход в интернет: {ip}', { ip })}
                                >
                                  →
                                  <span className="server-flag">
                                    {countryFlag(s.egress_country || peer?.country || '') || '?'}
                                  </span>
                                </span>
                              )
                            })()}
                            <span className="srv-item-name">{s.name}</span>
                            <GreBadge server={s} />
                            {st?.online && (
                              <span className="srv-item-cl" title={t('онлайн / всего клиентов')}>
                                <b>{st.clients_online}</b>/{st.clients_total}
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
              <ServerDetail
                server={selected}
                metric={metrics[selected.id]}
                stat={stats[selected.id]}
                checking={checkingId === selected.id}
                menu={serverMenu(selected)}
                onCheck={() => void check(selected)}
                onClients={(proto) => {
                  setClientsTab(proto)
                  setClientsFor(selected)
                }}
                cascade={cascadeOf(selected)}
                peer={cascadePeer(selected, cascadeOf(selected))}
                onCascade={(c) => setWizard({ resume: c })}
              />
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
          >
            <h3>{editingId === null ? t('Новый сервер') : t('Изменить сервер')}</h3>
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
            <div className="form-row">
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
                        {t('Панель даст скрипт: создаст юзера, ключ, откроет фаервол')}
                      </span>
                    </div>
                  </label>
                </div>
                {useBootstrap ? (
                  <>
                    <p className="muted small">
                      {t(
                        'Панель один раз зайдёт по паролю, установит свой ключ и откроет SSH-порт только для IP панели. Пароль не сохраняется.',
                      )}
                    </p>
                    <p className="muted small">
                      {t(
                        '⚠️ Если на сервере включён фаервол и он блокирует SSH с IP панели — подключиться не получится (будет таймаут). В этом случае снимите галку и запустите ручной скрипт прямо на сервере — он откроет доступ панели.',
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
                      'После «Сохранить» панель покажет скрипт. Зайдите на сервер по SSH под root и вставьте его — он создаст пользователя «{user}», добавит ключ панели и откроет фаервол (если есть). Затем нажмите «Проверить» на карточке сервера — он подключится.',
                      { user: form.ssh_user },
                    )}
                  </p>
                )}
              </div>
            )}

            <div className="modal-actions">
              <button type="button" className="ghost" onClick={() => setFormOpen(false)}>
                {t('Отмена')}
              </button>
              <button type="submit" disabled={busy}>
                {busy ? t(busyLabel) : t('Сохранить')}
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
          onProtocolRemoved={() => {
            const srv = clientsFor
            setClientsFor(null)
            if (srv) setNotice(t('Протокол удален с сервера «{name}», снимок конфига остался на ноде.', { name: srv.name }))
            void load()
          }}
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
                '⚠️ Ссылка содержит приватный SSH-ключ управления сервером — не публикуйте её и не пересылайте. Панель поставила отдельный ключ для этого доступа; при повторной генерации прежний перестаёт работать.',
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
          onClose={() => setWizard(null)}
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
            {unbuild.error && <p className="small err-text">{unbuild.error}</p>}
            <div className="modal-actions">
              <button className="ghost" onClick={() => setUnbuild(null)}>
                {t('Отмена')}
              </button>
              {unbuild.error && (
                <button className="ghost" disabled={unbuilding} onClick={() => confirmUnbuild(true)}>
                  {t('Убрать только из панели')}
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
              {t('Также убрать SSH-ключ панели с сервера (панель зайдёт по SSH)')}
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
            <h3>{t('Подготовка сервера «{name}»', { name: scriptFor.name })}</h3>
            <p className="muted small">
              {t('Выполните этот скрипт под root на сервере. Он добавит SSH-ключ панели пользователю')}{' '}
              <b>{scriptFor.ssh_user}</b>{t(', разрешит SSH-порт только для IP панели (ufw / firewalld / hosts.allow; ничего лишнего наружу не открывает) и ответит')}{' '}
              <span className="mono">ACONTROL SETUP OK</span>{t('. После этого нажмите «Проверить».')}
            </p>
            <pre className="script-box">{scriptText}</pre>
            <div className="modal-actions">
              <button className="ghost" onClick={() => setScriptFor(null)}>
                {t('Закрыть')}
              </button>
              <button onClick={copyScript}>
                {copied ? t('Скопировано ✓') : t('Скопировать')}
              </button>
            </div>
          </div>
        </div>
      )}
    </section>
  )
}
