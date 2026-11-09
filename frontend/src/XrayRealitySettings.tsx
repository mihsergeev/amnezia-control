import { useEffect, useRef, useState, type FormEvent } from 'react'
import { api, ApiError } from './api'
import { useI18n } from './i18n'
import { useModalDismiss } from './useModalDismiss'

type RealityInbound = {
  index: number
  tag: string
  port: number | null
  published_ports: number[]
  server_names: string[]
  destination: string | null
  destination_port: number | null
  destination_field: 'dest' | 'target' | null
  public_key: string | null
  short_ids: string[]
  editable: boolean
}

type RealityState = { revision: string; inbounds: RealityInbound[] }

type Props = {
  serverId: number
  onClose: () => void
  onUnauthorized: () => void
}

export function XrayRealitySettings({ serverId, onClose, onUnauthorized }: Props) {
  const { t } = useI18n()
  const path = `/api/servers/${serverId}/xray/reality`
  const [state, setState] = useState<RealityState | null>(null)
  const [index, setIndex] = useState<number | null>(null)
  const [site, setSite] = useState('')
  const [dest, setDest] = useState('')
  const [error, setError] = useState('')
  const [saved, setSaved] = useState(false)
  const [busy, setBusy] = useState(false)
  const saving = useRef(false)
  const dismiss = () => {
    if (!saving.current) onClose()
  }
  useModalDismiss(dismiss)

  function select(inbound?: RealityInbound) {
    setIndex(inbound?.index ?? null)
    setSite(inbound?.server_names[0] ?? '')
    setDest(inbound?.destination ?? '')
    setSaved(false)
    setError('')
  }

  useEffect(() => {
    let alive = true
    api<RealityState>(path)
      .then((result) => {
        if (!alive) return
        setState(result)
        select(result.inbounds[0])
      })
      .catch((err: unknown) => {
        if (!alive) return
        if (err instanceof ApiError && err.status === 401) onUnauthorized()
        else setError(err instanceof Error ? err.message : String(err))
      })
    return () => { alive = false }
  }, [path, onUnauthorized])

  const inbound = state?.inbounds.find((item) => item.index === index)
  const changed = site.trim() !== inbound?.server_names[0] || dest.trim() !== inbound?.destination

  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (saving.current || !state || !inbound?.editable || !changed || !site.trim() || !dest.trim()) return
    saving.current = true
    setBusy(true)
    setSaved(false)
    setError('')
    try {
      const result = await api<RealityState>(path, {
        method: 'PUT',
        body: JSON.stringify({
          revision: state.revision, inbound_index: inbound.index, site, dest,
        }),
      })
      setState(result)
      select(result.inbounds.find((item) => item.index === inbound.index))
      setSaved(true)
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) onUnauthorized()
      else setError(err instanceof Error ? err.message : String(err))
    } finally {
      saving.current = false
      setBusy(false)
    }
  }

  return (
    <div className="modal-backdrop">
      <form className="card modal modal-wide" role="dialog" aria-modal="true" aria-labelledby="xray-reality-title" onSubmit={save}>
        <h3 id="xray-reality-title">{t('Настройки REALITY')}</h3>
        {!state && !error && <p className="muted">{t('загрузка…')}</p>}
        {state?.inbounds.length === 0 && <p className="muted">{t('Входы VLESS с REALITY не найдены.')}</p>}
        {state && state.inbounds.length > 1 && (
          <label>
            {t('Вход Xray')}
            <select value={index ?? ''} disabled={busy} onChange={(e) => select(state.inbounds.find((item) => item.index === Number(e.target.value)))}>
              {state.inbounds.map((item) => (
                <option key={item.index} value={item.index}>
                  {item.tag || t('Вход {number}', { number: item.index + 1 })} · {item.port ?? '—'}
                </option>
              ))}
            </select>
          </label>
        )}
        {inbound && (
          <>
            <dl className="reality-values">
              <dt>{t('Разрешенные SNI')}</dt>
              <dd>{inbound.server_names.join(', ') || '—'}</dd>
              <dt>{inbound.destination_field === 'target' ? 'Target' : 'Dest'}</dt>
              <dd>{inbound.destination ?? '—'}</dd>
              <dt>{t('Порт цели')}</dt>
              <dd>{inbound.destination_port ?? '—'}</dd>
              <dt>{t('Порт входа Xray')}</dt>
              <dd>{inbound.port ?? '—'}</dd>
              {inbound.published_ports.length > 0 && (
                <>
                  <dt>{t('Опубликованные порты')}</dt>
                  <dd>{inbound.published_ports.join(', ')}</dd>
                </>
              )}
              <dt>{t('Публичный ключ REALITY')}</dt>
              <dd>{inbound.public_key ?? '—'}</dd>
              <dt>Short IDs</dt>
              <dd>{inbound.short_ids.map((id) => id || t('(пустой)')).join(', ') || '—'}</dd>
            </dl>
            {inbound.editable ? (
              <div className="reality-setup">
                <label>
                  {t('SNI для выдаваемых профилей')}
                  <input autoComplete="off" value={site} required maxLength={254} disabled={busy} onChange={(e) => { setSite(e.target.value); setSaved(false) }} />
                </label>
                <label>
                  {t('Цель REALITY (Dest / Target)')}
                  <input autoComplete="off" value={dest} required maxLength={260} disabled={busy} onChange={(e) => { setDest(e.target.value); setSaved(false) }} />
                </label>
                <p className="muted small">
                  {t('Новая цель должна поддерживать TLS 1.3 и HTTP/2 для нового и всех прежних SNI. Панель сохранит прежние имена, ключи и UUID. При применении Xray перезапустится, клиенты переподключатся.')}
                </p>
              </div>
            ) : <p className="muted small">{t('Для этого входа доступен только просмотр настроек REALITY')}</p>}
          </>
        )}
        {error && <p className="form-error" role="alert">{t(error)}</p>}
        {saved && <p role="status">{t('Настройки REALITY сохранены.')}</p>}
        <div className="modal-actions">
          <button className="ghost" type="button" onClick={dismiss} disabled={busy}>{t('Закрыть')}</button>
          {inbound?.editable && (
            <button type="submit" disabled={busy || !changed || !site.trim() || !dest.trim()}>
              {busy ? t('Проверка и применение…') : t('Проверить и применить')}
            </button>
          )}
        </div>
      </form>
    </div>
  )
}
