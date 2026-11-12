import { Fragment, useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { AmneziaQr } from './AmneziaQr'
import {
  api,
  ApiError,
  pauseClient,
  renameClient,
  setClientLimit,
  type OvpnClient,
  type OvpnConfig,
  type OvpnCreated,
  type OvpnState,
  type NativeClientConfig,
  type NativeCreatedClient,
} from './api'
import { ExpiryCell } from './Expiry'
import { QuickIssueForm } from './QuickIssueForm'
import { groupClients, clientGroupNames, clientGroupHeader } from './clientGrouping'
import { ClientGroupHeader, ClientGroupingBar, ClientViewSwitch } from './ClientPeople'
import { useAddClientDevice } from './useAddClientDevice'
import { BulkRevokeBar, SelectAllCell, SelectCell } from './BulkActions'
import { useSelection } from './useSelection'
import { ClientStatsModal } from './ClientStatsModal'
import { Menu } from './Menu'
import { NoteCell } from './NoteCell'
import { RollbackMenu } from './RollbackMenu'
import { copyText } from './clipboard'
import { formatBytes } from './format'
import { useShareLink } from './ShareLink'
import { TorrentBadge } from './Torrent'
import { useTorrentHits } from './useTorrentHits'
import { translate, useI18n } from './i18n'
import { useModalLayer } from './useModalDismiss'
import { configFilename } from './clientExports'

type Props = {
  serverId: number
  serverName: string
  protocol?: 'openvpn' | 'openvpn-native'
  groupName?: string
  onUnauthorized: () => void
  onRequestUpdate?: () => void
  // карточка одного клиента (открыт из поиска)
  focusClient?: string | null
}

type ConfigView = { name: string; text: string; native: boolean; filename?: string }

export function OpenVpnClients({
  serverId,
  serverName,
  protocol = 'openvpn',
  groupName = '',
  onUnauthorized,
  onRequestUpdate,
  focusClient,
}: Props) {
  const { t } = useI18n()
  const native = protocol === 'openvpn-native'
  const protocolLabel = native ? 'OpenVPN' : 'OpenVPN + Cloak'
  const [state, setState] = useState<OvpnState | null>(null)
  const torrentHits = useTorrentHits(serverId)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState<string | null>(null)

  const [addOpen, setAddOpen] = useState(false)
  const [addRevision, setAddRevision] = useState(0)
  const [newName, setNewName] = useState('')
  const [newGroup, setNewGroup] = useState('')
  const [newDevice, setNewDevice] = useState('')
  const [grouped, setGrouped] = useState(true)
  const [allColumns, setAllColumns] = useState(false)
  const [metadataFor, setMetadataFor] = useState<OvpnClient | null>(null)
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
  const shareLink = useShareLink(view?.text ?? '', view?.name ?? '', groupName)
  const [statsFor, setStatsFor] = useState<{ id: string; name: string } | null>(
    null,
  )
  const [copied, setCopied] = useState(false)

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
      const result = await api<OvpnState>(`/api/servers/${serverId}/${protocol}`)
      if (seq !== loadSeq.current) return
      setState(result)
      setError(null)
    } catch (err) {
      if (seq === loadSeq.current) handleError(err)
    } finally {
      if (seq === loadSeq.current) setLoading(false)
    }
  }, [serverId, protocol, handleError])

  useEffect(() => {
    void load()
  }, [load])

  function closeConfig() {
    configGeneration.current += 1
    setBusy(null)
    setView(null)
  }

  function showConfig(name: string, text: string, filename?: string) {
    setMetadataFor(null)
    setAddOpen(false)
    setView({ name, text, native, filename })
    setCopied(false)
  }

  function openAdd() {
    setAddRevision((revision) => revision + 1)
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

  function openGroup(group: string) {
    openAdd()
    setNewGroup(group)
    setGrouped(true)
  }

  const addDevice = useAddClientDevice({
    serverId: serverId, protocol: protocol, generation: configGeneration,
    onOpen: openGroup,
    onApplied: (id, group) => setState((previous) => previous ? { ...previous,
      clients: previous.clients.map((client) => client.client_id === id ? { ...client, group_name: group } : client),
    } : previous),
    onError: handleError,
  })

  async function addClient() {
    const configName = newName.trim() || newDevice.trim()
    if (!configName || creatingRef.current) return
    creatingRef.current = true
    setCreating(true)
    setError(null)
    const generation = ++configGeneration.current
    try {
      const result = await api<OvpnCreated | NativeCreatedClient<OvpnClient>>(
        `/api/servers/${serverId}/${protocol}/clients`,
        {
          method: 'POST',
          body: JSON.stringify({ name: configName, expires_at: newExpiry, group_name: newGroup.trim(), device_name: newDevice.trim() }),
        },
      )
      if (generation !== configGeneration.current) return
      setAddOpen(false)
      setNewName('')
      setNewExpiry(null)
      showConfig(result.client.name, 'config' in result ? result.config : result.config_amnezia, 'filename' in result ? result.filename : undefined)
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
      const result = await api<OvpnConfig | NativeClientConfig>(
        `/api/servers/${serverId}/${protocol}/config`,
        { method: 'POST', body: JSON.stringify({ client_id: clientId }) },
      )
      if (generation !== configGeneration.current) return
      showConfig(result.name, 'config' in result ? result.config : result.config_amnezia, 'filename' in result ? result.filename : undefined)
    } catch (err) {
      if (generation === configGeneration.current) handleError(err)
    } finally {
      if (generation === configGeneration.current) setBusy(null)
    }
  }

  async function reissue(clientId: string, name: string) {
    if (
      !window.confirm(
        t(
          'Перевыпустить конфиг для «{name}»? Старый ключ перестанет работать — клиенту нужно будет заново импортировать конфиг.',
          { name },
        ),
      )
    )
      return
    setBusy(clientId)
    setError(null)
    const generation = ++configGeneration.current
    try {
      const result = await api<OvpnCreated | NativeCreatedClient<OvpnClient>>(
        `/api/servers/${serverId}/${protocol}/reissue`,
        { method: 'POST', body: JSON.stringify({ client_id: clientId }) },
      )
      if (generation !== configGeneration.current) return
      showConfig(result.client.name, 'config' in result ? result.config : result.config_amnezia, 'filename' in result ? result.filename : undefined)
      await load()
    } catch (err) {
      if (generation === configGeneration.current) handleError(err)
    } finally {
      if (generation === configGeneration.current) setBusy(null)
    }
  }

  function editMetadata(client: OvpnClient) {
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
        body: JSON.stringify({ protocol, client_id: client.client_id, group_name: newGroup.trim(), device_name: newDevice.trim() }),
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
      await renameClient(serverId, protocol, clientId, next)
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
        t('Отозвать OpenVPN-клиента «{name}»? Он потеряет доступ.', { name }),
      )
    )
      return
    setBusy(clientId)
    try {
      await api<void>(`/api/servers/${serverId}/${protocol}/revoke`, {
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

  async function changeLimit(clientId: string, name: string, iso: string | null) {
    try {
      await setClientLimit(serverId, protocol, clientId, name, iso)
      await load()
    } catch (err) {
      handleError(err)
    }
  }

  async function togglePause(c: OvpnClient) {
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
      await pauseClient(serverId, protocol, c.client_id, resume)
      await load()
    } catch (err) {
      handleError(err)
    } finally {
      setBusy(null)
    }
  }

  async function saveNote(clientId: string, note: string) {
    try {
      await api<void>(`/api/servers/${serverId}/${protocol}/note`, {
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
    setCopied(await copyText(view.text))
  }

  function downloadConfig() {
    if (!view) return
    const blob = new Blob([view.text], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = configFilename(view.name, view.native ? 'ovpn' : 'txt', view.filename)
    a.click()
    URL.revokeObjectURL(url)
  }

  const sel = useSelection(
    useMemo(() => state?.clients.filter((c) => !focusClient || c.client_id === focusClient).map((c) => c.client_id) ?? [], [state, focusClient]),
  )

  return (
    <>
      <p className="muted small">
        {native ? t('Обычный OpenVPN. Файл .ovpn содержит сертификаты и ключ клиента; Cloak не требуется.') : t(
          'OpenVPN поверх Cloak (маскировка под HTTPS). Конфиг выдаётся ссылкой vpn:// «Для приложения AmneziaVPN».',
        )}
      </p>

      {error && <p className="form-error">{error}</p>}
      {loading && <p className="muted">{t('загрузка…')}</p>}

      {metadataFor && <QuickIssueForm key="metadata" metadataOnly name={metadataFor.name} onName={() => {}}
        expiry={null} onExpiry={() => {}}
        group={newGroup} onGroup={setNewGroup} device={newDevice} onDevice={setNewDevice}
        creating={savingMetadata} onCreate={saveMetadata} onCancel={() => setMetadataFor(null)} />}

      {view && (
        <section className={`quick-issue-result${view.native ? ' quick-issue-result-no-qr' : ''}`} aria-label={t('Готовый конфиг')}>
          <div className="quick-issue-result-content">
            <h3 tabIndex={-1} ref={resultHeading}>{t('Конфиг клиента «{name}»', { name: view.name })}</h3>
            <div className="modal-config-body">
            <p className="muted small">
              {view.native ? t('Импортируйте файл .ovpn в совместимый клиент OpenVPN.') : t(
                'Ссылка vpn:// — вставьте её в приложение AmneziaVPN («+» → вставить из буфера) или отсканируйте QR.',
              )}
            </p>

            {!view.native && <div className="qr-wrap">
              <AmneziaQr key={view.text} text={view.text} format="vpn" />
            </div>}
            <details className="quick-issue-text" key={view.text}>
                <summary>{t('Текст конфига')}</summary>
                <pre className="script-box">{view.text}</pre>
              </details>
            {shareLink.result}
            </div>
            <div className="modal-actions">
              <button onClick={openAdd} disabled={creating}>{t('Создать следующего')}</button>
              <button className="ghost" onClick={closeConfig}>
                {t('Готово')}
              </button>
              <button className="ghost" onClick={downloadConfig}>
                {view.native ? t('Скачать .ovpn') : t('Скачать .txt')}
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
          {native && <div className="info-chips">
            {state.port != null && <span className="info-chip mono">{state.port}{state.transport ? '/' + state.transport.toUpperCase() : ''}</span>}
            {state.version && <span className="info-chip mono">{state.version}</span>}
          </div>}
          {addOpen ? (
            <QuickIssueForm key={`create:${addRevision}`} groups={clientGroupNames(state?.clients ?? [])} name={newName} onName={setNewName}
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
              <span style={{ marginLeft: 'auto', display: 'inline-flex', gap: 8 }}>
                {(!native || state.capabilities?.config_restore === true) && <RollbackMenu
                  serverId={serverId}
                  serverName={serverName}
                  proto={protocol}
                  onRestored={load}
                  onUnauthorized={onUnauthorized}
                />}
                {onRequestUpdate && (!native || state.capabilities?.update === true) && (
                  <button
                    className="ghost"
                    onClick={onRequestUpdate}
                    title={native ? t('Обновить контейнер OpenVPN с сохранением порта, сертификатов и клиентов') : t('Пересобрать образ (свежий alpine + cloak); клиенты и PKI сохраняются)')}
                  >
                    {t('Переустановить')}
                  </button>
                )}
              </span>
            </div>
          )}

          <ClientViewSwitch grouped={grouped} onChange={setGrouped} />
          <ClientGroupingBar key={`${serverId}:${protocol}`} serverId={serverId} protocol={protocol}
            clients={(state?.clients ?? []).map((client) => ({ ...client, id: client.client_id }))} sel={sel}
            onDone={(ids, group) => {
              setState((previous) => previous ? { ...previous, clients: previous.clients.map((client) =>
                ids.includes(client.client_id) ? { ...client, group_name: group } : client) } : previous)
              setGrouped(true)
              void load()
            }} onUnauthorized={onUnauthorized} />

          <BulkRevokeBar
            serverId={serverId}
            serverName={serverName}
            protocol={protocol}
            protocolLabel={protocolLabel}
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
                    <Fragment key={`${protocol}:${c.client_id}`}>
                          {grouped && (() => { const heading = clientGroupHeader(rows, index, state.clients); return heading &&
                            <ClientGroupHeader {...heading} columns={6} onAdd={() => openGroup(heading.name)} disabled={addDevice.busy} /> })()}
                        <tr>
                      <SelectCell sel={sel} id={c.client_id} />
                      <td className="name-cell">

                        {(c.group_name || c.device_name) && <div className="client-device-label muted small">{[!grouped && c.group_name, c.device_name].filter(Boolean).join(' · ')}</div>}
                        <NoteCell
                          name={c.paused ? `${c.name} ⏸` : c.name}
                          note={c.note || ''}
                          online={c.paused ? false : !!c.connected}
                          badge={<TorrentBadge hit={torrentHits.get(`${protocol}:${c.client_id}`)} />}
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
                        {!c.group_name && <button className="ghost client-add-device" disabled={addDevice.busy}
                          onClick={() => void addDevice.add({ ...c, id: c.client_id })}>{t('Добавить устройство')}</button>}
                        {c.paused ? (
                          <button
                            disabled={busy === c.client_id}
                            onClick={() => togglePause(c)}
                            title={t('Вернуть клиента на сервер')}
                          >
                            {busy === c.client_id ? '…' : t('Возобновить')}
                          </button>
                        ) : c.has_config ? (
                          <button
                            className="ghost"
                            disabled={busy === c.client_id}
                            onClick={() => viewConfig(c.client_id)}
                          >
                            {busy === c.client_id ? '…' : t('Конфиг')}
                          </button>
                        ) : (
                          <button
                            className="ghost"
                            disabled={busy === c.client_id}
                            onClick={() => reissue(c.client_id, c.name)}
                          >
                            {busy === c.client_id ? '…' : t('Перевыпустить')}
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
                                  ...(c.has_config
                                    ? [
                                        {
                                          label: t('Перевыпустить'),
                                          onClick: () =>
                                            reissue(c.client_id, c.name),
                                        },
                                      ]
                                    : []),
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
                    </Fragment>
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
          protocol={protocol}
          clientId={statsFor.id}
          name={statsFor.name}
          onClose={() => setStatsFor(null)}
          onUnauthorized={onUnauthorized}
        />
      )}
    </>
  )
}
