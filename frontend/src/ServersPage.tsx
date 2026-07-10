import {
  useCallback,
  useEffect,
  useMemo,
  useState,
  type FormEvent,
} from 'react'
import {
  api,
  ApiError,
  parseCheckInfo,
  protocolsFromContainers,
  type NodeMetric,
  type PanelConfig,
  type Server,
  type ServerForm,
} from './api'
import { ClientsModal } from './ClientsModal'
import { ImportModal } from './ImportModal'
import { DeployModal } from './DeployModal'
import { Menu, type MenuItem } from './Menu'
import { formatBytes, formatUptime } from './format'
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

function StatusDot({ server }: { server: Server }) {
  const { t } = useI18n()
  const cls =
    server.last_check_ok === null
      ? 'dot-unknown'
      : server.last_check_ok
        ? 'dot-ok'
        : 'dot-fail'
  const title =
    server.last_check_ok === null
      ? t('не проверялся')
      : server.last_check_ok
        ? t('онлайн')
        : t('ошибка (см. лог)')
  return <span className={`dot ${cls}`} title={title} />
}

function pct(used: number, total: number): number {
  return total > 0 ? Math.round((used / total) * 100) : 0
}

function ResourceLine({ m }: { m: NodeMetric }) {
  const { t } = useI18n()
  const memPct = pct(m.mem_used, m.mem_total)
  const diskPct = pct(m.disk_used, m.disk_total)
  const diskCls = diskPct >= 90 ? 'res-crit' : diskPct >= 75 ? 'res-warn' : ''
  const loadCls =
    m.cpu_count > 0 && m.load1 / m.cpu_count >= 1
      ? 'res-crit'
      : m.cpu_count > 0 && m.load1 / m.cpu_count >= 0.7
        ? 'res-warn'
        : ''
  return (
    <div className="server-res">
      <span className={`res-item ${loadCls}`} title={t('Средняя загрузка (1 мин) / ядер')}>
        CPU {m.load1.toFixed(2)}
        {m.cpu_count > 0 && <span className="res-sub">/{m.cpu_count}</span>}
      </span>
      <span className="res-item" title={t('Память')}>
        RAM {memPct}%
        <span className="res-sub">
          {' '}
          {formatBytes(m.mem_used)}/{formatBytes(m.mem_total)}
        </span>
      </span>
      <span className={`res-item ${diskCls}`} title={t('Диск /')}>
        {t('Диск')} {diskPct}%
        <span className="res-sub">
          {' '}
          {formatBytes(m.disk_used)}/{formatBytes(m.disk_total)}
        </span>
      </span>
      <span className="res-item res-sub" title={t('Аптайм')}>
        ↑ {formatUptime(m.uptime_seconds)}
      </span>
    </div>
  )
}

export function ServersPage({ onUnauthorized }: Props) {
  const { t } = useI18n()
  const [servers, setServers] = useState<Server[]>([])
  const [metrics, setMetrics] = useState<Record<number, NodeMetric>>({})
  const [config, setConfig] = useState<PanelConfig | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)

  const [form, setForm] = useState<ServerForm>(emptyForm(FALLBACK_USER))
  const [editingId, setEditingId] = useState<number | null>(null)
  const [formOpen, setFormOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  const [busyLabel, setBusyLabel] = useState(t('Сохранить'))

  // автонастройка по паролю (только при создании)
  const [useBootstrap, setUseBootstrap] = useState(true)
  const [password, setPassword] = useState('')
  const [sudoPassword, setSudoPassword] = useState('')
  const [showAdvanced, setShowAdvanced] = useState(false)

  const [checkingId, setCheckingId] = useState<number | null>(null)
  const [clientsFor, setClientsFor] = useState<Server | null>(null)
  const [importOpen, setImportOpen] = useState(false)
  const [deployFor, setDeployFor] = useState<{
    server: Server
    mode: 'deploy' | 'update' | 'adopt'
    protocol: 'awg' | 'xray' | 'openvpn'
  } | null>(null)
  const [fullAccess, setFullAccess] = useState<{
    server: Server
    config: string
    user: string
  } | null>(null)
  const [faBusyId, setFaBusyId] = useState<number | null>(null)
  const [faCopied, setFaCopied] = useState(false)
  const [scriptFor, setScriptFor] = useState<Server | null>(null)
  const [deleteFor, setDeleteFor] = useState<Server | null>(null)
  const [deleteRemoveKey, setDeleteRemoveKey] = useState(false)
  const [deleting, setDeleting] = useState(false)
  const [scriptText, setScriptText] = useState('')
  const [copied, setCopied] = useState(false)

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
    try {
      await navigator.clipboard.writeText(scriptText)
      setCopied(true)
    } catch {
      setCopied(false)
    }
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

  async function exportFullAccess(server: Server) {
    setFaBusyId(server.id)
    setError(null)
    try {
      const r = await api<{ config: string; ssh_user: string }>(
        `/api/servers/${server.id}/fullaccess`,
        { method: 'POST' },
      )
      setFaCopied(false)
      setFullAccess({ server, config: r.config, user: r.ssh_user })
    } catch (err) {
      handleError(err)
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
        setBusyLabel(t('Сохранение…'))
        await api<Server>(`/api/servers/${editingId}`, {
          method: 'PATCH',
          body: JSON.stringify(form),
        })
        setFormOpen(false)
        await load()
        return
      }

      setBusyLabel(t('Создание…'))
      const created = await api<Server>('/api/servers', {
        method: 'POST',
        body: JSON.stringify(form),
      })

      if (useBootstrap && password) {
        // панель сама зайдёт по паролю, поставит ключ и настроит фаервол
        setBusyLabel(t('Подключаюсь и настраиваю…'))
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
      setBusyLabel(t('Сохранить'))
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

  // серверы, сгруппированные по group_name; без группы — в конце
  const groupList = useMemo(() => {
    const map = new Map<string, Server[]>()
    for (const s of servers) {
      const g = s.group_name || ''
      const arr = map.get(g)
      if (arr) arr.push(s)
      else map.set(g, [s])
    }
    const names = [...map.keys()].sort((a, b) => {
      if (a === '') return 1
      if (b === '') return -1
      return a.localeCompare(b, 'ru', { numeric: true, sensitivity: 'base' })
    })
    return names.map((name) => ({ name, servers: map.get(name)! }))
  }, [servers])

  const hasGroups = groupList.some((g) => g.name !== '')
  // существующие имена групп — для подсказки в форме
  const existingGroups = useMemo(
    () =>
      [...new Set(servers.map((s) => s.group_name).filter(Boolean))].sort((a, b) =>
        a.localeCompare(b, 'ru'),
      ),
    [servers],
  )

  return (
    <section>
      <div className="page-head">
        <h2>{t('Серверы')}</h2>
        <div className="page-head-actions">
          <button className="ghost" onClick={() => setImportOpen(true)}>
            {t('Импорт')}
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

      <div className="server-list">
        {groupList.map((g) => {
          const cards = g.servers.map((s) => {
          const info = parseCheckInfo(s)
          const protocols = protocolsFromContainers(info?.amnezia_containers ?? [])
          const online = s.last_check_ok === true
          const moreItems: MenuItem[] = []
          if (online && protocols.length === 0) {
            moreItems.push({
              label: t('Развернуть AmneziaWG'),
              onClick: () => setDeployFor({ server: s, mode: 'deploy', protocol: 'awg' }),
            })
          }
          if (online && !protocols.some((p) => p.key === 'xray')) {
            moreItems.push({
              label: t('Развернуть XRay / REALITY'),
              onClick: () => setDeployFor({ server: s, mode: 'deploy', protocol: 'xray' }),
            })
          }
          if (online && !protocols.some((p) => p.key === 'openvpn')) {
            moreItems.push({
              label: t('Развернуть OpenVPN / Cloak'),
              onClick: () => setDeployFor({ server: s, mode: 'deploy', protocol: 'openvpn' }),
            })
          }
          if (online) {
            moreItems.push({
              label:
                faBusyId === s.id ? t('Генерация…') : t('Полный доступ'),
              disabled: faBusyId === s.id,
              onClick: () => exportFullAccess(s),
            })
          }
          if (!online) {
            moreItems.push({ label: t('Скрипт настройки'), onClick: () => openScript(s) })
          }
          moreItems.push({ label: t('Изменить'), onClick: () => openEdit(s) })
          moreItems.push({
            label: t('Удалить сервер'),
            danger: true,
            onClick: () => {
              setDeleteRemoveKey(false)
              setDeleteFor(s)
            },
          })
          const canOpenClients = online && protocols.length > 0
          return (
          <div
            className={`server-card${canOpenClients ? ' card-clickable' : ''}`}
            key={s.id}
            role={canOpenClients ? 'button' : undefined}
            tabIndex={canOpenClients ? 0 : undefined}
            title={canOpenClients ? t('Открыть клиентов') : undefined}
            onClick={canOpenClients ? () => setClientsFor(s) : undefined}
            onKeyDown={
              canOpenClients
                ? (e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault()
                      setClientsFor(s)
                    }
                  }
                : undefined
            }
          >
            <div className="server-top">
              <div className="server-title">
                <span className="server-name" title={s.name}>
                  {s.name}
                </span>
                <StatusDot server={s} />
              </div>
              <div
                className="server-actions"
                onClick={(e) => e.stopPropagation()}
              >
                {canOpenClients && (
                  <button className="primary-ghost" onClick={() => setClientsFor(s)}>
                    {t('Клиенты')}
                  </button>
                )}
                <button
                  className="ghost"
                  onClick={() => check(s)}
                  disabled={checkingId === s.id}
                >
                  {checkingId === s.id ? t('Проверка…') : t('Проверить')}
                </button>
                <Menu label={t('Ещё')} items={moreItems} />
              </div>
            </div>

            {s.note && <div className="muted small server-note">{s.note}</div>}

            <div className="server-meta">
              <span className="mono host">{s.host}</span>
              <span className="chip">
                SSH {s.ssh_user}@{s.host}:{s.ssh_port}
              </span>
              {protocols.map((p) => (
                <span key={p.key} className="proto-badge">
                  {p.label}
                </span>
              ))}
              {online && protocols.length === 0 && info?.docker === false && (
                <span className="muted small">{t('· docker недоступен')}</span>
              )}
            </div>

            {online && metrics[s.id] && <ResourceLine m={metrics[s.id]} />}

            {s.last_check_ok === false && info?.error && (
              <div className="muted small err-text">{info.error}</div>
            )}
          </div>
          )
          })
          if (!hasGroups) return cards
          return (
            <div className="server-group" key={g.name || '__ungrouped'}>
              <button
                type="button"
                className="group-header"
                onClick={() => toggleGroup(g.name)}
              >
                <span className="group-caret">
                  {collapsed[g.name] ? '▸' : '▾'}
                </span>
                <span className="group-name">{g.name || t('Без группы')}</span>
                <span className="group-count">{g.servers.length}</span>
              </button>
              {!collapsed[g.name] && (
                <div className="group-cards">{cards}</div>
              )}
            </div>
          )
        })}
      </div>

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
                {busy ? busyLabel : t('Сохранить')}
              </button>
            </div>
          </form>
        </div>
      )}

      {clientsFor && (
        <ClientsModal
          server={clientsFor}
          protocols={protocolsFromContainers(
            parseCheckInfo(clientsFor)?.amnezia_containers ?? [],
          )}
          onClose={() => setClientsFor(null)}
          onUnauthorized={onUnauthorized}
          onRequestUpdate={(protocol) => {
            const srv = clientsFor
            if (!srv) return
            if (
              !window.confirm(
                t(
                  'Пересобрать образ на «{name}»? Текущие клиенты и ключи сохраняются.',
                  { name: srv.name },
                ),
              )
            )
              return
            setClientsFor(null)
            setDeployFor({ server: srv, mode: 'update', protocol })
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
                onClick={async () => {
                  try {
                    await navigator.clipboard.writeText(fullAccess.config)
                    setFaCopied(true)
                  } catch {
                    setFaCopied(false)
                  }
                }}
              >
                {faCopied ? t('Скопировано ✓') : t('Скопировать')}
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
