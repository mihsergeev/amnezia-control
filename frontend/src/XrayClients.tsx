import { useCallback, useEffect, useState } from 'react'
import { AmneziaQr } from './AmneziaQr'
import {
  api,
  ApiError,
  setClientLimit,
  type XrayConfig,
  type XrayCreated,
  type XrayState,
  type XrayVersion,
} from './api'
import { ExpiryCell, ExpirySelect } from './Expiry'
import { RollbackMenu } from './RollbackMenu'
import { useI18n } from './i18n'

type Props = {
  serverId: number
  serverName: string
  onUnauthorized: () => void
  onRequestUpdate?: () => void
}

type ConfigView = { name: string; amnezia: string }

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
  const [copied, setCopied] = useState(false)

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

  function showConfig(name: string, amnezia: string) {
    setView({ name, amnezia })
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
      showConfig(result.client.name, result.config_amnezia)
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
      showConfig(result.name, result.config_amnezia)
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

  async function changeLimit(clientId: string, name: string, iso: string | null) {
    try {
      await setClientLimit(serverId, 'xray', clientId, name, iso)
      await load()
    } catch (err) {
      handleError(err)
    }
  }

  async function copyConfig() {
    if (!view) return
    try {
      await navigator.clipboard.writeText(view.amnezia)
      setCopied(true)
    } catch {
      setCopied(false)
    }
  }

  function downloadConfig() {
    if (!view) return
    const safe = view.name.replace(/[^a-zA-Z0-9_-]+/g, '_')
    const blob = new Blob([view.amnezia], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${safe || 'client'}.txt`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <>
      <p className="muted small">
        {t(
          'XRay VLESS + REALITY (маскировка под TLS к настоящему сайту). Конфиг — ссылка vpn:// «Для приложения AmneziaVPN». Выдача/отзыв перезапускают xray (~2 сек, активные клиенты переподключатся).',
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
                    <th>{t('Срок')}</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {state.clients.map((c) => (
                    <tr key={c.client_id}>
                      <td className="name-cell">
                        <span className="cname" title={c.name}>
                          {c.name}
                        </span>
                      </td>
                      <td className="muted">{c.creation_date || '—'}</td>
                      <td>
                        <ExpiryCell
                          value={c.expires_at}
                          disabled={busy === c.client_id}
                          onSave={(iso) => changeLimit(c.client_id, c.name, iso)}
                        />
                      </td>
                      <td className="row-actions">
                        <button
                          className="ghost"
                          disabled={busy === c.client_id}
                          onClick={() => viewConfig(c.client_id)}
                        >
                          {busy === c.client_id ? '…' : t('Конфиг')}
                        </button>
                        <button
                          className="ghost danger"
                          disabled={busy === c.client_id}
                          onClick={() => revoke(c.client_id, c.name)}
                        >
                          {t('Отозвать')}
                        </button>
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
          <div className="card modal" onClick={(e) => e.stopPropagation()}>
            <h3>{t('Конфиг клиента «{name}»', { name: view.name })}</h3>
            <p className="muted small">
              {t(
                'Ссылка vpn:// — вставьте её в приложение AmneziaVPN («+» → вставить из буфера) или отсканируйте QR.',
              )}
            </p>

            <div className="qr-wrap">
              <AmneziaQr text={view.amnezia} format="vpn" />
            </div>
            <pre className="script-box">{view.amnezia}</pre>
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
    </>
  )
}
