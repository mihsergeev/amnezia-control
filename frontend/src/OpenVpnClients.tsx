import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
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
import { ExpiryCell, ExpirySelect } from './Expiry'
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
  const [newName, setNewName] = useState('')
  const [newExpiry, setNewExpiry] = useState<string | null>(null)
  const [creating, setCreating] = useState(false)
  // повторный Enter до ответа не выдает второго клиента (state обновится позже)
  const creatingRef = useRef(false)

  const [view, setView] = useState<ConfigView | null>(null)
  // Escape в окне конфига закрывает его, а не все окно клиентов
  useModalLayer(view !== null, () => setView(null))
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
    try {
      setState(await api<OvpnState>(`/api/servers/${serverId}/${protocol}`))
      setError(null)
    } catch (err) {
      handleError(err)
    } finally {
      setLoading(false)
    }
  }, [serverId, protocol, handleError])

  useEffect(() => {
    void load()
  }, [load])

  function showConfig(name: string, text: string, filename?: string) {
    setView({ name, text, native, filename })
    setCopied(false)
  }

  async function addClient() {
    if (!newName.trim() || creatingRef.current) return
    creatingRef.current = true
    setCreating(true)
    setError(null)
    try {
      const result = await api<OvpnCreated | NativeCreatedClient<OvpnClient>>(
        `/api/servers/${serverId}/${protocol}/clients`,
        {
          method: 'POST',
          body: JSON.stringify({ name: newName.trim(), expires_at: newExpiry }),
        },
      )
      setAddOpen(false)
      setNewName('')
      setNewExpiry(null)
      showConfig(result.client.name, 'config' in result ? result.config : result.config_amnezia, 'filename' in result ? result.filename : undefined)
      await load()
    } catch (err) {
      handleError(err)
    } finally {
      creatingRef.current = false
      setCreating(false)
    }
  }

  async function viewConfig(clientId: string) {
    setBusy(clientId)
    setError(null)
    try {
      const result = await api<OvpnConfig | NativeClientConfig>(
        `/api/servers/${serverId}/${protocol}/config`,
        { method: 'POST', body: JSON.stringify({ client_id: clientId }) },
      )
      showConfig(result.name, 'config' in result ? result.config : result.config_amnezia, 'filename' in result ? result.filename : undefined)
    } catch (err) {
      handleError(err)
    } finally {
      setBusy(null)
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
    try {
      const result = await api<OvpnCreated | NativeCreatedClient<OvpnClient>>(
        `/api/servers/${serverId}/${protocol}/reissue`,
        { method: 'POST', body: JSON.stringify({ client_id: clientId }) },
      )
      showConfig(result.client.name, 'config' in result ? result.config : result.config_amnezia, 'filename' in result ? result.filename : undefined)
      await load()
    } catch (err) {
      handleError(err)
    } finally {
      setBusy(null)
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
    useMemo(() => state?.clients.map((c) => c.client_id) ?? [], [state]),
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

      {state && !loading && (
        <>
          {native && <div className="info-chips">
            {state.port != null && <span className="info-chip mono">{state.port}{state.transport ? '/' + state.transport.toUpperCase() : ''}</span>}
            {state.version && <span className="info-chip mono">{state.version}</span>}
          </div>}
          {addOpen ? (
            <div className="add-form">
              <input
                autoFocus
                placeholder={t('Имя клиента (например, phone-max)')}
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
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
              <button
                onClick={() => {
                  setNewName('')
                  setAddOpen(true)
                }}
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

          <BulkRevokeBar
            serverId={serverId}
            serverName={serverName}
            protocol={protocol}
            protocolLabel={protocolLabel}
            sel={sel}
            onDone={load}
            onUnauthorized={onUnauthorized}
          />

          <div className="table-card">
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
                  {state.clients
                    .filter((c) => !focusClient || c.client_id === focusClient)
                    .map((c) => (
                    <tr key={c.client_id}>
                      <SelectCell sel={sel} id={c.client_id} />
                      <td className="name-cell">
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

      {view && (
        <div className="modal-backdrop">
          <div className="card modal modal-config" onClick={(e) => e.stopPropagation()}>
            <h3>{t('Конфиг клиента «{name}»', { name: view.name })}</h3>
            <div className="modal-config-body">
            <p className="muted small">
              {view.native ? t('Импортируйте файл .ovpn в совместимый клиент OpenVPN.') : t(
                'Ссылка vpn:// — вставьте её в приложение AmneziaVPN («+» → вставить из буфера) или отсканируйте QR.',
              )}
            </p>

            {!view.native && <div className="qr-wrap">
              <AmneziaQr text={view.text} format="vpn" />
            </div>}
            <pre className="script-box">{view.text}</pre>
            {shareLink.result}
            </div>
            <div className="modal-actions">
              <button className="ghost" onClick={() => setView(null)}>
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
        </div>
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
