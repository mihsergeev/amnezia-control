import { useCallback, useEffect, useState } from 'react'
import { AmneziaQr } from './AmneziaQr'
import {
  api,
  ApiError,
  setClientLimit,
  type OvpnConfig,
  type OvpnCreated,
  type OvpnState,
} from './api'
import { ExpiryCell, ExpirySelect } from './Expiry'
import { ClientStatsModal } from './ClientStatsModal'
import { RollbackMenu } from './RollbackMenu'
import { useI18n } from './i18n'

type Props = {
  serverId: number
  serverName: string
  onUnauthorized: () => void
}

type ConfigView = { name: string; amnezia: string }

export function OpenVpnClients({ serverId, serverName, onUnauthorized }: Props) {
  const { t } = useI18n()
  const [state, setState] = useState<OvpnState | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState<string | null>(null)

  const [addOpen, setAddOpen] = useState(false)
  const [newName, setNewName] = useState('')
  const [newExpiry, setNewExpiry] = useState<string | null>(null)
  const [creating, setCreating] = useState(false)

  const [view, setView] = useState<ConfigView | null>(null)
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
      setError(err instanceof Error ? err.message : t('Ошибка'))
    },
    [onUnauthorized],
  )

  const load = useCallback(async () => {
    setLoading(true)
    try {
      setState(await api<OvpnState>(`/api/servers/${serverId}/openvpn`))
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

  function showConfig(name: string, amnezia: string) {
    setView({ name, amnezia })
    setCopied(false)
  }

  async function addClient() {
    if (!newName.trim()) return
    setCreating(true)
    setError(null)
    try {
      const result = await api<OvpnCreated>(
        `/api/servers/${serverId}/openvpn/clients`,
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
      const result = await api<OvpnConfig>(
        `/api/servers/${serverId}/openvpn/config`,
        { method: 'POST', body: JSON.stringify({ client_id: clientId }) },
      )
      showConfig(result.name, result.config_amnezia)
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
      const result = await api<OvpnCreated>(
        `/api/servers/${serverId}/openvpn/reissue`,
        { method: 'POST', body: JSON.stringify({ client_id: clientId }) },
      )
      showConfig(result.client.name, result.config_amnezia)
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
      await api<void>(`/api/servers/${serverId}/openvpn/revoke`, {
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
      await setClientLimit(serverId, 'openvpn', clientId, name, iso)
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
          'OpenVPN поверх Cloak (маскировка под HTTPS). Конфиг выдаётся ссылкой vpn:// «Для приложения AmneziaVPN».',
        )}
      </p>

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
              <span style={{ marginLeft: 'auto' }}>
                <RollbackMenu
                  serverId={serverId}
                  serverName={serverName}
                  proto="openvpn"
                  onRestored={load}
                  onUnauthorized={onUnauthorized}
                />
              </span>
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
                        {c.has_config ? (
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
                            title={t('Конфиг не сохранён в панели — перевыпустить')}
                          >
                            {busy === c.client_id ? '…' : t('Перевыпустить')}
                          </button>
                        )}
                        <button
                          className="ghost"
                          disabled={busy === c.client_id}
                          onClick={() => setStatsFor({ id: c.client_id, name: c.name })}
                          title={t('Трафик клиента')}
                        >
                          {t('Стата')}
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

      {statsFor && (
        <ClientStatsModal
          serverId={serverId}
          protocol="openvpn"
          clientId={statsFor.id}
          name={statsFor.name}
          onClose={() => setStatsFor(null)}
          onUnauthorized={onUnauthorized}
        />
      )}
    </>
  )
}
