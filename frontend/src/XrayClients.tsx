import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import QRCode from 'qrcode'
import { AmneziaQr } from './AmneziaQr'
import {
  api,
  ApiError,
  pauseClient,
  renameClient,
  setClientLimit,
  type XrayClient,
  type XrayConfig,
  type XrayCreated,
  type XrayState,
  type XrayVariant,
  type XrayVersion,
} from './api'
import { ExpiryCell } from './Expiry'
import { QuickIssueForm } from './QuickIssueForm'
import { groupClients } from './clientGrouping'
import { BulkRevokeBar, SelectAllCell, SelectCell } from './BulkActions'
import { useSelection } from './useSelection'
import { Menu } from './Menu'
import { NoteCell } from './NoteCell'
import { ClientStatsModal } from './ClientStatsModal'
import { RollbackMenu } from './RollbackMenu'
import { XrayRealitySettings } from './XrayRealitySettings'
import { copyText } from './clipboard'
import { formatBytes } from './format'
import { useShareLink } from './ShareLink'
import { translate, useI18n } from './i18n'
import { useModalLayer } from './useModalDismiss'

type Props = {
  serverId: number
  serverName: string
  groupName?: string
  onUnauthorized: () => void
  onRequestUpdate?: () => void
  // карточка одного клиента (открыт из поиска)
  focusClient?: string | null
}

type ConfigView = { name: string; variants: XrayVariant[] }
type ConfigFormat = 'amnezia' | 'uri'

// старый бэкенд отдает только config_amnezia - показываем его как единственный вариант
function variantsOf(r: { config_amnezia: string; configs?: XrayVariant[] }) {
  if (r.configs && r.configs.length) return r.configs
  return [{ key: 'vision', label: 'VLESS Reality', amnezia: r.config_amnezia, uri: '' }]
}

// обычный QR для vless:// (Happ и др. не понимают кадры AmneziaVPN)
function PlainQr({ text }: { text: string }) {
  const [src, setSrc] = useState('')
  useEffect(() => {
    let alive = true
    QRCode.toDataURL(text, { margin: 1, width: 360 })
      .then((u) => alive && setSrc(u))
      .catch(() => alive && setSrc(''))
    return () => {
      alive = false
    }
  }, [text])
  return src ? <img src={src} alt="QR" width={240} height={240} /> : null
}

export function XrayClients({
  serverId,
  serverName,
  groupName = '',
  onUnauthorized,
  onRequestUpdate,
  focusClient,
}: Props) {
  const { t } = useI18n()
  const [state, setState] = useState<XrayState | null>(null)
  const [version, setVersion] = useState<XrayVersion | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState<string | null>(null)
  const [realityOpen, setRealityOpen] = useState(false)

  const [addOpen, setAddOpen] = useState(false)
  const [newName, setNewName] = useState('')
  const [newGroup, setNewGroup] = useState('')
  const [newDevice, setNewDevice] = useState('')
  const [grouped, setGrouped] = useState(false)
  const [allColumns, setAllColumns] = useState(false)
  const [metadataFor, setMetadataFor] = useState<XrayClient | null>(null)
  const [savingMetadata, setSavingMetadata] = useState(false)
  const savingMetadataRef = useRef(false)
  const [newExpiry, setNewExpiry] = useState<string | null>(null)
  const [creating, setCreating] = useState(false)
  // повторный Enter до ответа не выдает второго клиента (state обновится позже)
  const creatingRef = useRef(false)

  const configGeneration = useRef(0)
  useEffect(() => () => { configGeneration.current += 1 }, [])
  const loadSeq = useRef(0)
  useEffect(() => () => { loadSeq.current += 1 }, [])

  const [view, setView] = useState<ConfigView | null>(null)
  const resultHeading = useRef<HTMLHeadingElement>(null)
  useEffect(() => {
    if (!view) return
    resultHeading.current?.focus({ preventScroll: true })
    resultHeading.current?.scrollIntoView({ block: 'nearest' })
  }, [view])
  // Escape скрывает готовый конфиг, сохраняя список клиентов
  useModalLayer(view !== null, closeConfig)
  const [variantIdx, setVariantIdx] = useState(0)
  const [format, setFormat] = useState<ConfigFormat>('amnezia')
  const [statsFor, setStatsFor] = useState<{ id: string; name: string } | null>(
    null,
  )
  const [copied, setCopied] = useState(false)

  const variant = view ? view.variants[Math.min(variantIdx, view.variants.length - 1)] : null
  const shownText = variant ? (format === 'uri' && variant.uri ? variant.uri : variant.amnezia) : ''
  const shareLink = useShareLink(shownText, view?.name ?? '', groupName)

  const handleError = useCallback(
    (err: unknown) => {
      if (err instanceof ApiError && err.status === 401) {
        onUnauthorized()
        return
      }
      setError(err instanceof Error ? err.message : translate('Ошибка'))
    },
    [onUnauthorized],
  )

  const load = useCallback(async () => {
    setLoading(true)
    const seq = ++loadSeq.current
    try {
      const result = await api<XrayState>(`/api/servers/${serverId}/xray`)
      if (seq !== loadSeq.current) return
      setState(result)
      setError(null)
    } catch (err) {
      if (seq === loadSeq.current) handleError(err)
    } finally {
      if (seq === loadSeq.current) setLoading(false)
    }
  }, [serverId, handleError])

  useEffect(() => {
    void load()
  }, [load])

  useEffect(() => {
    api<XrayVersion>(`/api/servers/${serverId}/xray/version`)
      .then(setVersion)
      .catch(() => setVersion(null))
  }, [serverId])

  function closeConfig() {
    configGeneration.current += 1
    setBusy(null)
    setView(null)
  }

  function showConfig(name: string, variants: XrayVariant[]) {
    setMetadataFor(null)
    setAddOpen(false)
    setView({ name, variants })
    setVariantIdx(0)
    setFormat('amnezia')
    setCopied(false)
  }

  function openAdd() {
    setMetadataFor(null)
    configGeneration.current += 1
    setBusy(null)
    setView(null)
    setError(null)
    setNewName('')
    setNewGroup('')
    setNewDevice('')
    setNewExpiry(null)
    setAddOpen(true)
  }

  async function addClient() {
    if (!newName.trim() || creatingRef.current) return
    creatingRef.current = true
    setCreating(true)
    setError(null)
    const generation = ++configGeneration.current
    try {
      const result = await api<XrayCreated>(
        `/api/servers/${serverId}/xray/clients`,
        {
          method: 'POST',
          body: JSON.stringify({ name: newName.trim(), expires_at: newExpiry, group_name: newGroup.trim(), device_name: newDevice.trim() }),
        },
      )
      if (generation !== configGeneration.current) return
      setAddOpen(false)
      setNewName('')
      setNewExpiry(null)
      showConfig(result.client.name, variantsOf(result))
      await load()
    } catch (err) {
      if (generation === configGeneration.current) handleError(err)
    } finally {
      creatingRef.current = false
      setCreating(false)
    }
  }

  async function viewConfig(clientId: string) {
    setBusy(clientId)
    setError(null)
    const generation = ++configGeneration.current
    try {
      const result = await api<XrayConfig>(
        `/api/servers/${serverId}/xray/config`,
        { method: 'POST', body: JSON.stringify({ client_id: clientId }) },
      )
      if (generation !== configGeneration.current) return
      showConfig(result.name, variantsOf(result))
    } catch (err) {
      if (generation === configGeneration.current) handleError(err)
    } finally {
      if (generation === configGeneration.current) setBusy(null)
    }
  }

  function editMetadata(client: XrayClient) {
    configGeneration.current += 1
    setView(null)
    setAddOpen(false)
    setError(null)
    setNewGroup(client.group_name ?? '')
    setNewDevice(client.device_name ?? '')
    setMetadataFor(client)
  }

  async function saveMetadata() {
    const client = metadataFor
    if (!client || savingMetadataRef.current) return
    savingMetadataRef.current = true
    setSavingMetadata(true)
    setError(null)
    const generation = configGeneration.current
    try {
      await api<void>(`/api/servers/${serverId}/client-metadata`, {
        method: 'POST',
        body: JSON.stringify({ protocol: 'xray', client_id: client.client_id, group_name: newGroup.trim(), device_name: newDevice.trim() }),
      })
      if (generation !== configGeneration.current) return
      setMetadataFor(null)
      await load()
    } catch (err) {
      if (generation === configGeneration.current) handleError(err)
    } finally {
      savingMetadataRef.current = false
      setSavingMetadata(false)
    }
  }

  async function rename(clientId: string, name: string) {
    const next = window.prompt(t('Новое имя клиента'), name)?.trim()
    if (!next || next === name) return
    setBusy(clientId)
    try {
      await renameClient(serverId, 'xray', clientId, next)
      await load()
    } catch (err) {
      handleError(err)
    } finally {
      setBusy(null)
    }
  }

  async function revoke(clientId: string, name: string) {
    if (
      !window.confirm(
        t('Отозвать XRay-клиента «{name}»? Он потеряет доступ.', { name }),
      )
    )
      return
    setBusy(clientId)
    try {
      await api<void>(`/api/servers/${serverId}/xray/revoke`, {
        method: 'POST',
        body: JSON.stringify({ client_id: clientId }),
      })
      await load()
    } catch (err) {
      handleError(err)
    } finally {
      setBusy(null)
    }
  }

  async function reissue(clientId: string, name: string) {
    if (
      !window.confirm(
        t('Перевыпустить конфиг для «{name}»? Старый UUID перестанет работать.', {
          name,
        }),
      )
    )
      return
    setBusy(clientId)
    setError(null)
    const generation = ++configGeneration.current
    try {
      const result = await api<XrayCreated>(
        `/api/servers/${serverId}/xray/reissue`,
        { method: 'POST', body: JSON.stringify({ client_id: clientId }) },
      )
      if (generation !== configGeneration.current) return
      showConfig(result.client.name, variantsOf(result))
      await load()
    } catch (err) {
      if (generation === configGeneration.current) handleError(err)
    } finally {
      if (generation === configGeneration.current) setBusy(null)
    }
  }

  async function changeLimit(clientId: string, name: string, iso: string | null) {
    try {
      await setClientLimit(serverId, 'xray', clientId, name, iso)
      await load()
    } catch (err) {
      handleError(err)
    }
  }

  async function togglePause(c: XrayClient) {
    const resume = !!c.paused
    if (
      !resume &&
      !window.confirm(
        t('Поставить «{name}» на паузу? Клиент не сможет подключиться, но его можно вернуть без пересоздания.', {
          name: c.name,
        }),
      )
    )
      return
    setBusy(c.client_id)
    try {
      await pauseClient(serverId, 'xray', c.client_id, resume)
      await load()
    } catch (err) {
      handleError(err)
    } finally {
      setBusy(null)
    }
  }

  async function saveNote(clientId: string, note: string) {
    try {
      await api<void>(`/api/servers/${serverId}/xray/note`, {
        method: 'POST',
        body: JSON.stringify({ client_id: clientId, note }),
      })
      await load()
    } catch (err) {
      handleError(err)
    }
  }

  async function copyConfig() {
    if (!view) return
    setCopied(await copyText(shownText))
  }

  function downloadConfig() {
    if (!view || !variant) return
    const safe = view.name.replace(/[^a-zA-Z0-9_-]+/g, '_')
    const suffix = view.variants.length > 1 ? `-${variant.key}` : ''
    const blob = new Blob([shownText], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${safe || 'client'}${suffix}.txt`
    a.click()
    URL.revokeObjectURL(url)
  }

  const sel = useSelection(
    useMemo(() => state?.clients.map((c) => c.client_id) ?? [], [state]),
  )

  return (
    <>
      <p className="muted small">
        {t(
          'Xray VLESS + REALITY маскирует трафик под TLS к настоящему сайту. Для AmneziaVPN используйте ссылку vpn://, для Happ, v2rayN и других клиентов - vless://.',
        )}
        {' '}
        {t(
          'Одиночная выдача и отзыв перезапускают Xray. Пакетная выдача и отзыв работают через локальный API без перезапуска. Если API недоступен, его можно включить плановым обновлением или переустановкой Xray из панели.',
        )}
      </p>

      {(version || state) && (
        <div className="version-line xray-version-line">
          {version && (
            <span className="muted small">
              {t('XRay-core:')}{' '}
              <span className="mono">{version.current_version ?? '—'}</span>
              {version.update_available && (
                <span className="update-badge">
                  {t('есть {ver}', { ver: version.latest_version ?? t('новее') })}
                </span>
              )}
              {!version.update_available && version.current_version && (
                <span className="version-ok"> {t('актуальна')}</span>
              )}
            </span>
          )}
          <div className="version-actions">
            {(state || version?.deployed) && !focusClient && (
              <button className="ghost" onClick={() => setRealityOpen(true)}>{t('Настройки REALITY')}</button>
            )}
            {version && (
              <RollbackMenu
                serverId={serverId}
                serverName={serverName}
                proto="xray"
                onRestored={load}
                onUnauthorized={onUnauthorized}
              />
            )}
            {version && onRequestUpdate && (
              <button className="ghost" onClick={onRequestUpdate}>
                {version.update_available
                  ? t('Обновить ядро')
                  : t('Переустановить')}
              </button>
            )}
          </div>
        </div>
      )}

      {error && <p className="form-error">{error}</p>}
      {loading && <p className="muted">{t('загрузка…')}</p>}
      {realityOpen && (
        <XrayRealitySettings
          key={serverId}
          serverId={serverId}
          onClose={() => setRealityOpen(false)}
          onUnauthorized={onUnauthorized}
        />
      )}

      {metadataFor && <QuickIssueForm metadataOnly name={metadataFor.name} onName={() => {}}
        expiry={null} onExpiry={() => {}}
        group={newGroup} onGroup={setNewGroup} device={newDevice} onDevice={setNewDevice}
        creating={savingMetadata} onCreate={saveMetadata} onCancel={() => setMetadataFor(null)} />}

      {view && variant && (
        <section className="quick-issue-result" aria-label={t('Готовый конфиг')}>
          <div className="quick-issue-result-content">
            <h3 tabIndex={-1} ref={resultHeading}>{t('Конфиг клиента «{name}»', { name: view.name })}</h3>
            <div className="modal-config-body">
              {view.variants.length > 1 && (
                <div className="tabs">
                  {view.variants.map((v, i) => (
                    <button
                      key={v.key}
                      className={i === variantIdx ? 'tab tab-active' : 'tab'}
                      onClick={() => {
                        setVariantIdx(i)
                        setCopied(false)
                      }}
                    >
                      {v.label}
                    </button>
                  ))}
                </div>
              )}
              {variant.uri && (
                <div className="tabs">
                  <button
                    className={format === 'amnezia' ? 'tab tab-active' : 'tab'}
                    onClick={() => {
                      setFormat('amnezia')
                      setCopied(false)
                    }}
                  >
                    {t('Для приложения AmneziaVPN')}
                  </button>
                  <button
                    className={format === 'uri' ? 'tab tab-active' : 'tab'}
                    onClick={() => {
                      setFormat('uri')
                      setCopied(false)
                    }}
                  >
                    {t('Ссылка vless://')}
                  </button>
                </div>
              )}
              <p className="muted small">
                {format === 'uri' && variant.uri
                  ? t(
                      'Ссылка vless:// для Happ, v2rayN, v2rayNG, INCY, Shadowrocket и других клиентов на Xray: импорт из буфера или по QR.',
                    )
                  : t(
                      'Ссылка vpn:// — вставьте её в приложение AmneziaVPN («+» → вставить из буфера) или отсканируйте QR.',
                    )}
                {variant.key === 'xhttp' &&
                  ' ' +
                    t(
                      'XHTTP - запасной вариант на том же порту: включайте, если Vision режут или он рвется.',
                    )}
              </p>

              <div className="qr-wrap">
                {format === 'uri' && variant.uri ? (
                  <PlainQr key={variant.uri} text={variant.uri} />
                ) : (
                  <AmneziaQr key={variant.amnezia} text={variant.amnezia} format="vpn" />
                )}
              </div>
              <details className="quick-issue-text" key={shownText}>
                <summary>{t('Текст конфига')}</summary>
                <pre className="script-box">{shownText}</pre>
              </details>
              {shareLink.result}
            </div>
            <div className="modal-actions">
              <button onClick={openAdd} disabled={creating}>{t('Создать следующего')}</button>
              <button className="ghost" onClick={closeConfig}>
                {t('Готово')}
              </button>
              <button className="ghost" onClick={downloadConfig}>
                {t('Скачать .txt')}
              </button>
              {shareLink.control}
              <button onClick={copyConfig}>
                {copied ? t('Скопировано ✓') : t('Скопировать')}
              </button>
            </div>
          </div>
        </section>
      )}

      {state && !loading && (
        <>
          {addOpen ? (
            <QuickIssueForm name={newName} onName={setNewName}
              expiry={newExpiry} onExpiry={setNewExpiry}
              group={newGroup} onGroup={setNewGroup} device={newDevice} onDevice={setNewDevice}
              creating={creating} onCreate={addClient} onCancel={() => setAddOpen(false)} />
          ) : (
            <div className="toolbar">
              <button
                onClick={openAdd}
              >
                {t('+ Выдать конфиг')}
              </button>
            </div>
          )}

          <label className="client-group-toggle small">
            <input type="checkbox" checked={grouped} onChange={(event) => setGrouped(event.target.checked)} />
            {t('Группировать по клиенту')}
          </label>

          <BulkRevokeBar
            serverId={serverId}
            serverName={serverName}
            protocol="xray"
            protocolLabel="XRay/REALITY"
            sel={sel}
            onDone={load}
            onUnauthorized={onUnauthorized}
          />

          <details className="client-table-options">
            <summary>{t('Столбцы таблицы')}</summary>
            <label className="small"><input type="checkbox" checked={allColumns} onChange={(event) => setAllColumns(event.target.checked)} /> {t('Показать все столбцы')}</label>
          </details>
          <div className={`table-card client-table client-table-other${allColumns ? ' client-details-visible' : ''}`}>
            {state.clients.length === 0 ? (
              <p className="muted">{t('Клиентов пока нет.')}</p>
            ) : (
              <table>
                <thead>
                  <tr>
                    <SelectAllCell sel={sel} />
                    <th>{t('Имя')}</th>
                    <th>{t('Создан')}</th>
                    <th>{t('Трафик (↓ / ↑)')}</th>
                    <th>{t('Срок')}</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {groupClients(state.clients.filter((c) => !focusClient || c.client_id === focusClient), grouped)
                    .map((c, index, rows) => (
                    <tr key={`xray:${c.client_id}`}>
                      <SelectCell sel={sel} id={c.client_id} />
                      <td className="name-cell">
                        {grouped && c.group_name && (index === 0 || rows[index - 1]?.group_name !== c.group_name) && <div className="client-group-heading">{c.group_name}</div>}
                        {(c.group_name || c.device_name) && <div className="client-device-label muted small">{[!grouped && c.group_name, c.device_name].filter(Boolean).join(' · ')}</div>}
                        <NoteCell
                          name={c.paused ? `${c.name} ⏸` : c.name}
                          note={c.note || ''}
                          onSave={(note) => saveNote(c.client_id, note)}
                        />
                      </td>
                      <td className="muted">{c.creation_date || '—'}</td>
                      <td className="muted mono traffic-cell">
                        <div>↓ {formatBytes(c.tx_bytes ?? 0)}</div>
                        <div>↑ {formatBytes(c.rx_bytes ?? 0)}</div>
                      </td>
                      <td>
                        <ExpiryCell
                          value={c.expires_at}
                          disabled={busy === c.client_id}
                          onSave={(iso) => changeLimit(c.client_id, c.name, iso)}
                        />
                      </td>
                      <td className="row-actions">
                        {c.paused ? (
                          <button
                            disabled={busy === c.client_id}
                            onClick={() => togglePause(c)}
                            title={t('Вернуть клиента на сервер')}
                          >
                            {busy === c.client_id ? '…' : t('Возобновить')}
                          </button>
                        ) : (
                          <button
                            className="ghost"
                            disabled={busy === c.client_id}
                            onClick={() => viewConfig(c.client_id)}
                          >
                            {busy === c.client_id ? '…' : t('Конфиг')}
                          </button>
                        )}
                        <Menu
                          fixed
                          align="right"
                          className="ghost icon-btn"
                          caret={false}
                          title={t('Ещё')}
                          label="⋯"
                          items={
                            c.paused
                              ? [
                                  {
                                    label: t('Клиент и устройство'),
                                    onClick: () => editMetadata(c),
                                  },
                                  {
                                    label: t('Переименовать'),
                                    onClick: () => rename(c.client_id, c.name),
                                  },
                                  {
                                    label: t('Отозвать'),
                                    danger: true,
                                    onClick: () => revoke(c.client_id, c.name),
                                  },
                                ]
                              : [
                                  {
                                    label: t('Перевыпустить'),
                                    onClick: () => reissue(c.client_id, c.name),
                                  },
                                  {
                                    label: t('Трафик клиента'),
                                    onClick: () =>
                                      setStatsFor({ id: c.client_id, name: c.name }),
                                  },
                                  {
                                    label: t('Клиент и устройство'),
                                    onClick: () => editMetadata(c),
                                  },
                                  {
                                    label: t('Переименовать'),
                                    onClick: () => rename(c.client_id, c.name),
                                  },
                                  {
                                    label: t('Пауза'),
                                    onClick: () => togglePause(c),
                                  },
                                  { divider: true },
                                  {
                                    label: t('Отозвать'),
                                    danger: true,
                                    onClick: () => revoke(c.client_id, c.name),
                                  },
                                ]
                          }
                        />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </>
      )}

      {statsFor && (
        <ClientStatsModal
          serverId={serverId}
          protocol="xray"
          clientId={statsFor.id}
          name={statsFor.name}
          onClose={() => setStatsFor(null)}
          onUnauthorized={onUnauthorized}
        />
      )}
    </>
  )
}
