import { useCallback, useEffect, useState } from 'react'
import QRCode from 'qrcode'
import { AmneziaQr } from './AmneziaQr'
import {
  api,
  ApiError,
  pauseClient,
  setClientLimit,
  type XrayClient,
  type XrayConfig,
  type XrayCreated,
  type XrayState,
  type XrayVariant,
  type XrayVersion,
} from './api'
import { ExpiryCell, ExpirySelect } from './Expiry'
import { Menu } from './Menu'
import { NoteCell } from './NoteCell'
import { ClientStatsModal } from './ClientStatsModal'
import { RollbackMenu } from './RollbackMenu'
import { copyText } from './clipboard'
import { formatBytes } from './format'
import { useI18n } from './i18n'

type Props = {
  serverId: number
  serverName: string
  onUnauthorized: () => void
  onRequestUpdate?: () => void
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
  onUnauthorized,
  onRequestUpdate,
}: Props) {
  const { t } = useI18n()
  const [state, setState] = useState<XrayState | null>(null)
  const [version, setVersion] = useState<XrayVersion | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState<string | null>(null)

  const [addOpen, setAddOpen] = useState(false)
  const [newName, setNewName] = useState('')
  const [newExpiry, setNewExpiry] = useState<string | null>(null)
  const [creating, setCreating] = useState(false)

  const [view, setView] = useState<ConfigView | null>(null)
  const [variantIdx, setVariantIdx] = useState(0)
  const [format, setFormat] = useState<ConfigFormat>('amnezia')
  const [statsFor, setStatsFor] = useState<{ id: string; name: string } | null>(
    null,
  )
  const [copied, setCopied] = useState(false)

  const variant = view ? view.variants[Math.min(variantIdx, view.variants.length - 1)] : null
  const shownText = variant ? (format === 'uri' && variant.uri ? variant.uri : variant.amnezia) : ''

  const handleError = useCallback(
    (err: unknown) => {
      if (err instanceof ApiError && err.status === 401) {
        onUnauthorized()
        return
      }
      setError(err instanceof Error ? err.message : t('Ошибка'))
    },
    [onUnauthorized],
  )

  const load = useCallback(async () => {
    setLoading(true)
    try {
      setState(await api<XrayState>(`/api/servers/${serverId}/xray`))
      setError(null)
    } catch (err) {
      handleError(err)
    } finally {
      setLoading(false)
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

  function showConfig(name: string, variants: XrayVariant[]) {
    setView({ name, variants })
    setVariantIdx(0)
    setCopied(false)
  }

  async function addClient() {
    if (!newName.trim()) return
    setCreating(true)
    setError(null)
    try {
      const result = await api<XrayCreated>(
        `/api/servers/${serverId}/xray/clients`,
        {
          method: 'POST',
          body: JSON.stringify({ name: newName.trim(), expires_at: newExpiry }),
        },
      )
      setAddOpen(false)
      setNewName('')
      setNewExpiry(null)
      showConfig(result.client.name, variantsOf(result))
      await load()
    } catch (err) {
      handleError(err)
    } finally {
      setCreating(false)
    }
  }

  async function viewConfig(clientId: string) {
    setBusy(clientId)
    setError(null)
    try {
      const result = await api<XrayConfig>(
        `/api/servers/${serverId}/xray/config`,
        { method: 'POST', body: JSON.stringify({ client_id: clientId }) },
      )
      showConfig(result.name, variantsOf(result))
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
    try {
      const result = await api<XrayCreated>(
        `/api/servers/${serverId}/xray/reissue`,
        { method: 'POST', body: JSON.stringify({ client_id: clientId }) },
      )
      showConfig(result.client.name, variantsOf(result))
      await load()
    } catch (err) {
      handleError(err)
    } finally {
      setBusy(null)
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

  return (
    <>
      <p className="muted small">
        {t(
          'XRay VLESS + REALITY (маскировка под TLS к настоящему сайту). Конфиг: ссылка vpn:// для AmneziaVPN или vless:// для Happ, v2rayN и других клиентов. Выдача/отзыв перезапускают xray (~2 сек, активные клиенты переподключатся).',
        )}
      </p>

      {version && (
        <div className="version-line">
          <span className="muted small">
            {t('XRay-core:')}{' '}
            <span className="mono">{version.current_version ?? '—'}</span>
            {version.update_available && (
              <span className="update-badge">
                {t('есть {ver}', { ver: version.latest_version ?? 'новее' })}
              </span>
            )}
            {!version.update_available && version.current_version && (
              <span className="version-ok"> {t('актуальна')}</span>
            )}
          </span>
          <div className="version-actions">
            <RollbackMenu
              serverId={serverId}
              serverName={serverName}
              proto="xray"
              onRestored={load}
              onUnauthorized={onUnauthorized}
            />
            {onRequestUpdate && (
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
            </div>
          )}

          <div className="table-card">
            {state.clients.length === 0 ? (
              <p className="muted">{t('Клиентов пока нет.')}</p>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>{t('Имя')}</th>
                    <th>{t('Создан')}</th>
                    <th>{t('Трафик (↓ / ↑)')}</th>
                    <th>{t('Срок')}</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {state.clients.map((c) => (
                    <tr key={c.client_id}>
                      <td className="name-cell">
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

      {view && variant && (
        <div className="modal-backdrop">
          <div className="card modal" onClick={(e) => e.stopPropagation()}>
            <h3>{t('Конфиг клиента «{name}»', { name: view.name })}</h3>
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
                <PlainQr text={variant.uri} />
              ) : (
                <AmneziaQr text={variant.amnezia} format="vpn" />
              )}
            </div>
            <pre className="script-box">{shownText}</pre>
            <div className="modal-actions">
              <button className="ghost" onClick={() => setView(null)}>
                {t('Готово')}
              </button>
              <button className="ghost" onClick={downloadConfig}>
                {t('Скачать .txt')}
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
