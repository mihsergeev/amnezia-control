import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import QRCode from 'qrcode'
import {
  api,
  ApiError,
  setClientLimit,
  type AwgClient,
  type AwgState,
  type CreatedClient,
  type Protocol,
  type Server,
  type VersionInfo,
} from './api'
import { formatBytes, formatHandshake, isOnline } from './format'
import { RollbackMenu } from './RollbackMenu'
import { OpenVpnClients } from './OpenVpnClients'
import { XrayClients } from './XrayClients'
import { AmneziaQr } from './AmneziaQr'
import { ExpiryCell, ExpirySelect } from './Expiry'
import { ClientStatsModal } from './ClientStatsModal'
import { useI18n } from './i18n'

type Props = {
  server: Server
  protocols: Protocol[]
  onClose: () => void
  onUnauthorized: () => void
  onRequestUpdate: (protocol: 'awg' | 'xray') => void
  onRequestAdopt?: () => void
}

type SortKey = 'name' | 'handshake' | 'traffic'
type CfgFormat = 'conf' | 'amnezia'
type ConfigView = { name: string; config: string; amnezia: string }

export function ClientsModal({
  server,
  protocols,
  onClose,
  onUnauthorized,
  onRequestUpdate,
  onRequestAdopt,
}: Props) {
  const { t } = useI18n()
  const hasAwg = protocols.some((p) => p.key === 'awg')
  const [proto, setProto] = useState<Protocol['key']>(
    protocols[0]?.key ?? 'awg',
  )
  const [state, setState] = useState<AwgState | null>(null)
  const [version, setVersion] = useState<VersionInfo | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [addOpen, setAddOpen] = useState(false)
  const [newName, setNewName] = useState('')
  const [newNote, setNewNote] = useState('')
  const [newExpiry, setNewExpiry] = useState<string | null>(null)
  const [creating, setCreating] = useState(false)
  const [busyKey, setBusyKey] = useState<string | null>(null)

  const [statsFor, setStatsFor] = useState<AwgClient | null>(null)
  const [view, setView] = useState<ConfigView | null>(null)
  const [cfgFormat, setCfgFormat] = useState<CfgFormat>('conf')
  const [qr, setQr] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)

  const [search, setSearch] = useState('')
  const [sortKey, setSortKey] = useState<SortKey>('name')
  const [sortAsc, setSortAsc] = useState(true)

  const [editKey, setEditKey] = useState<string | null>(null)
  const [draft, setDraft] = useState('')
  const escaping = useRef(false)

  const handleError = useCallback(
    (err: unknown) => {
      if (err instanceof ApiError && err.status === 401) {
        onUnauthorized()
        return
      }
      setError(err instanceof Error ? err.message : t('Неизвестная ошибка'))
    },
    [onUnauthorized, t],
  )

  const load = useCallback(async () => {
    setLoading(true)
    try {
      setState(await api<AwgState>(`/api/servers/${server.id}/awg`))
      setError(null)
    } catch (err) {
      handleError(err)
    } finally {
      setLoading(false)
    }
  }, [server.id, handleError])

  useEffect(() => {
    if (!hasAwg) return
    void load()
    api<VersionInfo>(`/api/servers/${server.id}/awg/version`)
      .then(setVersion)
      .catch(() => setVersion(null))
  }, [load, server.id, hasAwg])

  function showConfig(name: string, config: string, amnezia: string) {
    setView({ name, config, amnezia })
    setCfgFormat('conf')
    setCopied(false)
  }

  const currentText = view
    ? cfgFormat === 'conf'
      ? view.config
      : view.amnezia
    : ''

  // обычный QR только для .conf (amnezia-формат рисует AmneziaQr — анимированный)
  useEffect(() => {
    if (!view || cfgFormat !== 'conf') {
      setQr(null)
      return
    }
    let alive = true
    QRCode.toDataURL(view.config, { margin: 1, width: 360 })
      .then((url) => {
        if (alive) setQr(url)
      })
      .catch(() => {
        if (alive) setQr(null)
      })
    return () => {
      alive = false
    }
  }, [view, cfgFormat])

  function openAdd() {
    setNewName('')
    setNewNote('')
    setNewExpiry(null)
    setAddOpen(true)
  }

  async function addClient() {
    if (!newName.trim()) return
    setCreating(true)
    setError(null)
    try {
      const result = await api<CreatedClient>(
        `/api/servers/${server.id}/awg/clients`,
        {
          method: 'POST',
          body: JSON.stringify({
            name: newName.trim(),
            note: newNote.trim(),
            expires_at: newExpiry,
          }),
        },
      )
      setAddOpen(false)
      showConfig(result.client.name, result.config, result.config_amnezia)
      await load()
    } catch (err) {
      handleError(err)
    } finally {
      setCreating(false)
    }
  }

  function startEdit(client: AwgClient) {
    escaping.current = false
    setDraft(client.note || '')
    setEditKey(client.public_key)
  }

  function cancelEdit() {
    escaping.current = true
    setEditKey(null)
  }

  async function commitNote(client: AwgClient) {
    if (escaping.current) {
      escaping.current = false
      return
    }
    const value = draft.trim()
    setEditKey(null)
    if (value === (client.note || '')) return
    try {
      await api<void>(`/api/servers/${server.id}/awg/note`, {
        method: 'POST',
        body: JSON.stringify({ public_key: client.public_key, note: value }),
      })
      await load()
    } catch (err) {
      handleError(err)
    }
  }

  async function viewConfig(client: AwgClient) {
    setBusyKey(client.public_key)
    setError(null)
    try {
      const result = await api<{
        config: string
        config_amnezia: string
        name: string
      }>(`/api/servers/${server.id}/awg/config`, {
        method: 'POST',
        body: JSON.stringify({ public_key: client.public_key }),
      })
      showConfig(result.name, result.config, result.config_amnezia)
    } catch (err) {
      handleError(err)
    } finally {
      setBusyKey(null)
    }
  }

  async function reissue(client: AwgClient) {
    if (
      !window.confirm(
        t('Перевыпустить конфиг для «{name}»? Старый ключ перестанет работать.', {
          name: client.name,
        }),
      )
    )
      return
    setBusyKey(client.public_key)
    setError(null)
    try {
      const result = await api<CreatedClient>(
        `/api/servers/${server.id}/awg/reissue`,
        { method: 'POST', body: JSON.stringify({ public_key: client.public_key }) },
      )
      showConfig(result.client.name, result.config, result.config_amnezia)
      await load()
    } catch (err) {
      handleError(err)
    } finally {
      setBusyKey(null)
    }
  }

  async function revoke(client: AwgClient) {
    if (
      !window.confirm(
        t('Отозвать клиента «{name}»? Он потеряет доступ.', { name: client.name }),
      )
    )
      return
    setBusyKey(client.public_key)
    try {
      await api<void>(`/api/servers/${server.id}/awg/revoke`, {
        method: 'POST',
        body: JSON.stringify({ public_key: client.public_key }),
      })
      await load()
    } catch (err) {
      handleError(err)
    } finally {
      setBusyKey(null)
    }
  }

  async function changeLimit(client: AwgClient, iso: string | null) {
    try {
      await setClientLimit(server.id, 'awg', client.public_key, client.name, iso)
      await load()
    } catch (err) {
      handleError(err)
    }
  }

  async function copyConfig() {
    if (!view) return
    try {
      await navigator.clipboard.writeText(currentText)
      setCopied(true)
    } catch {
      setCopied(false)
    }
  }

  function downloadConfig() {
    if (!view) return
    const safe = view.name.replace(/[^a-zA-Z0-9_-]+/g, '_')
    const ext = cfgFormat === 'conf' ? 'conf' : 'txt'
    const blob = new Blob([currentText], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${safe || 'client'}.${ext}`
    a.click()
    URL.revokeObjectURL(url)
  }

  function toggleSort(key: SortKey) {
    if (sortKey === key) {
      setSortAsc((v) => !v)
    } else {
      setSortKey(key)
      setSortAsc(true)
    }
  }

  const visibleClients = useMemo(() => {
    if (!state) return []
    const q = search.trim().toLowerCase()
    const filtered = q
      ? state.clients.filter(
          (c) =>
            c.name.toLowerCase().includes(q) || c.address.toLowerCase().includes(q),
        )
      : state.clients.slice()
    filtered.sort((a, b) => {
      let cmp = 0
      if (sortKey === 'name') cmp = a.name.localeCompare(b.name, 'ru')
      else if (sortKey === 'handshake')
        cmp = (a.latest_handshake ?? 0) - (b.latest_handshake ?? 0)
      else cmp = a.rx_bytes + a.tx_bytes - (b.rx_bytes + b.tx_bytes)
      return sortAsc ? cmp : -cmp
    })
    return filtered
  }, [state, search, sortKey, sortAsc])

  const arrow = (key: SortKey) =>
    sortKey === key ? (sortAsc ? ' ▲' : ' ▼') : ''

  return (
    <div className="modal-backdrop">
      <div
        className="card modal modal-wide modal-clients"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="clients-head">
          <h3>{t('Клиенты')} · {server.name}</h3>
          <button className="ghost" onClick={onClose}>
            {t('Закрыть')}
          </button>
        </div>

        {protocols.length > 1 && (
          <div className="tabs">
            {protocols.map((p) => (
              <button
                key={p.key}
                className={proto === p.key ? 'tab tab-active' : 'tab'}
                onClick={() => setProto(p.key)}
              >
                {p.label}
              </button>
            ))}
          </div>
        )}

        {proto === 'openvpn' && (
          <OpenVpnClients
            serverId={server.id}
            serverName={server.name}
            onUnauthorized={onUnauthorized}
          />
        )}

        {proto === 'xray' && (
          <XrayClients
            serverId={server.id}
            serverName={server.name}
            onUnauthorized={onUnauthorized}
            onRequestUpdate={() => onRequestUpdate('xray')}
          />
        )}

        {proto === 'awg' && (
          <>
        {state && (
          <div className="awg-summary muted small">
            {state.interface} · endpoint <span className="mono">{state.endpoint}</span> ·
            {' '}{t('подсеть')} <span className="mono">{state.address}</span>
          </div>
        )}

        {version && (
          <div className="version-line">
            <span className="muted small">
              AmneziaWG:{' '}
              <span className="mono">
                {version.current_version ?? version.current_awg_go ?? '—'}
              </span>
              {version.deployed && version.update_available && (
                <span className="update-badge">
                  {t('есть')} {version.latest_version ?? t('новее')}
                </span>
              )}
              {version.deployed && !version.update_available && (
                <span className="version-ok"> {t('актуальна')}</span>
              )}
              {!version.deployed && (
                <span className="muted">
                  {' '}·{' '}
                  {version.foreign_container
                    ? t('образ собран не панелью')
                    : t('базовый образ не считывается')}
                </span>
              )}
            </span>
            <div className="version-actions">
              {/* откат к снимку, снятому перед пересборкой (страховка) */}
              <RollbackMenu
                serverId={server.id}
                serverName={server.name}
                proto="awg"
                onRestored={load}
                onUnauthorized={onUnauthorized}
              />
              {/* Внешний контейнер amnezia-awg (собран клиентом) — предлагаем
                  «Взять под управление»: панель перечитает конфиг из живого
                  контейнера, сохранит порт/ключи и заменит его своим. В остальных
                  случаях (панельный amnezia-awg2, в т.ч. без читаемого дайджеста)
                  пересборка безопасна — конфиг переносится из живого контейнера. */}
              {!version.deployed && version.foreign_container ? (
                onRequestAdopt && (
                  <button className="ghost" onClick={onRequestAdopt}>
                    {t('Взять под управление')}
                  </button>
                )
              ) : (
                <button className="ghost" onClick={() => onRequestUpdate('awg')}>
                  {version.deployed && version.update_available
                    ? t('Обновить')
                    : t('Переустановить')}
                </button>
              )}
            </div>
          </div>
        )}

        {error && <p className="form-error">{error}</p>}
        {loading && <p className="muted">{t('загрузка…')}</p>}

        {state && !loading && (
          <>
            {addOpen ? (
              <div className="add-form">
                <input
                  autoFocus
                  placeholder={t('Имя клиента (например, phone-max)')}
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && addClient()}
                />
                <input
                  placeholder={t('Заметка (необязательно): кому выдан, устройство…')}
                  value={newNote}
                  onChange={(e) => setNewNote(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && addClient()}
                />
                <label className="expiry-row">
                  <span className="muted small">{t('Срок действия:')}</span>
                  <ExpirySelect value={newExpiry} onChange={setNewExpiry} />
                </label>
                <div className="add-form-actions">
                  <button className="ghost" onClick={() => setAddOpen(false)}>
                    {t('Отмена')}
                  </button>
                  <button onClick={addClient} disabled={creating || !newName.trim()}>
                    {creating ? t('Создание…') : t('Создать конфиг')}
                  </button>
                </div>
              </div>
            ) : (
              <div className="toolbar">
                <button onClick={openAdd}>{t('+ Выдать конфиг')}</button>
                {state.clients.length > 0 && (
                  <input
                    className="search-box"
                    placeholder={t('Поиск по имени или адресу…')}
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                  />
                )}
              </div>
            )}

            {state.clients.length === 0 ? (
              <p className="muted">{t('Клиентов пока нет.')}</p>
            ) : (
              <div className="table-card clients-scroll">
                <table>
                  <thead>
                    <tr>
                      <th className="sortable" onClick={() => toggleSort('name')}>
                        {t('Имя')}{arrow('name')}
                      </th>
                      <th>{t('Адрес')}</th>
                      <th className="sortable" onClick={() => toggleSort('handshake')}>
                        {t('Последний хендшейк')}{arrow('handshake')}
                      </th>
                      <th className="sortable" onClick={() => toggleSort('traffic')}>
                        {t('Трафик (↓ / ↑)')}{arrow('traffic')}
                      </th>
                      <th>{t('Срок')}</th>
                      <th></th>
                    </tr>
                  </thead>
                  <tbody>
                    {visibleClients.map((c) => {
                      const busy = busyKey === c.public_key
                      const editing = editKey === c.public_key
                      return (
                        <tr key={c.public_key}>
                          <td className="name-cell">
                            <div className="client-row-name">
                              <span
                                className={`dot ${
                                  isOnline(c.latest_handshake)
                                    ? 'dot-ok'
                                    : 'dot-unknown'
                                }`}
                              />
                              <span className="cname" title={c.name}>
                                {c.name}
                              </span>
                              {!editing && (
                                <button
                                  className="note-edit"
                                  title={t('Заметка')}
                                  onClick={() => startEdit(c)}
                                >
                                  ✎
                                </button>
                              )}
                            </div>
                            {editing ? (
                              <input
                                className="note-input"
                                autoFocus
                                value={draft}
                                placeholder={t('заметка…')}
                                onChange={(e) => setDraft(e.target.value)}
                                onKeyDown={(e) => {
                                  if (e.key === 'Enter') commitNote(c)
                                  if (e.key === 'Escape') cancelEdit()
                                }}
                                onBlur={() => commitNote(c)}
                              />
                            ) : (
                              c.note && (
                                <div
                                  className="note-line"
                                  title={c.note}
                                  onClick={() => startEdit(c)}
                                >
                                  {c.note}
                                </div>
                              )
                            )}
                          </td>
                          <td className="mono">{c.address}</td>
                          <td className="muted">
                            {formatHandshake(c.latest_handshake)}
                          </td>
                          <td className="muted mono traffic-cell">
                            <div>↓ {formatBytes(c.tx_bytes)}</div>
                            <div>↑ {formatBytes(c.rx_bytes)}</div>
                          </td>
                          <td>
                            <ExpiryCell
                              value={c.expires_at}
                              disabled={busy}
                              onSave={(iso) => changeLimit(c, iso)}
                            />
                          </td>
                          <td className="row-actions">
                            {c.has_config ? (
                              <button
                                className="ghost"
                                disabled={busy}
                                onClick={() => viewConfig(c)}
                              >
                                {t('Конфиг')}
                              </button>
                            ) : (
                              <button
                                className="ghost"
                                disabled={busy}
                                onClick={() => reissue(c)}
                              >
                                {busy ? '…' : t('Перевыпустить')}
                              </button>
                            )}
                            <button
                              className="ghost"
                              disabled={busy}
                              onClick={() => setStatsFor(c)}
                              title={t('Трафик клиента')}
                            >
                              {t('Стата')}
                            </button>
                            <button
                              className="ghost danger"
                              disabled={busy}
                              onClick={() => revoke(c)}
                            >
                              {t('Отозвать')}
                            </button>
                          </td>
                        </tr>
                      )
                    })}
                    {visibleClients.length === 0 && (
                      <tr>
                        <td colSpan={6} className="muted">
                          {t('Ничего не найдено.')}
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            )}
          </>
        )}

        {view && (
          <div className="modal-backdrop">
            <div className="card modal" onClick={(e) => e.stopPropagation()}>
              <h3>{t('Конфиг клиента «{name}»', { name: view.name })}</h3>

              <div className="tabs">
                <button
                  className={cfgFormat === 'conf' ? 'tab tab-active' : 'tab'}
                  onClick={() => {
                    setCfgFormat('conf')
                    setCopied(false)
                  }}
                >
                  {t('AmneziaWG (.conf)')}
                </button>
                <button
                  className={cfgFormat === 'amnezia' ? 'tab tab-active' : 'tab'}
                  onClick={() => {
                    setCfgFormat('amnezia')
                    setCopied(false)
                  }}
                >
                  {t('Для приложения AmneziaVPN')}
                </button>
              </div>

              <p className="muted small">
                {cfgFormat === 'conf'
                  ? t('Оригинальный AmneziaWG — импортируется в приложение AmneziaWG или WireGuard.')
                  : t('Ссылка vpn:// — вставьте её в приложение AmneziaVPN («+» → вставить из буфера) или отсканируйте QR.')}
              </p>

              <div className="qr-wrap">
                {cfgFormat === 'amnezia' ? (
                  <AmneziaQr text={view.amnezia} format="vpn" />
                ) : qr ? (
                  <img src={qr} alt={t('QR конфига')} width={240} height={240} />
                ) : (
                  <span className="muted small">{t('генерация QR…')}</span>
                )}
              </div>
              <pre className="script-box">{currentText}</pre>
              <div className="modal-actions">
                <button className="ghost" onClick={() => setView(null)}>
                  {t('Готово')}
                </button>
                <button className="ghost" onClick={downloadConfig}>
                  {t('Скачать')} {cfgFormat === 'conf' ? '.conf' : '.txt'}
                </button>
                <button onClick={copyConfig}>
                  {copied ? t('Скопировано ✓') : t('Скопировать')}
                </button>
              </div>
            </div>
          </div>
        )}

        {statsFor && (
          <ClientStatsModal
            serverId={server.id}
            protocol="awg"
            clientId={statsFor.public_key}
            name={statsFor.name}
            onClose={() => setStatsFor(null)}
            onUnauthorized={onUnauthorized}
          />
        )}
          </>
        )}
      </div>
    </div>
  )
}
