import { useEffect, useId, useState } from 'react'
import {
  ApiError,
  listRememberedSessions,
  listTrustedDevices,
  revokeRememberedSession,
  revokeTrustedDevice,
  type BrowserAccessEntry,
} from './api'
import { useI18n } from './i18n'
import { useModalDismiss } from './useModalDismiss'

function browserName(agent: string): string | undefined {
  if (/\b(?:Edg|EdgA|EdgiOS)\//.test(agent)) return 'Microsoft Edge'
  if (/\b(?:OPR|Opera)\//.test(agent)) return 'Opera'
  if (/\bSamsungBrowser\//.test(agent)) return 'Samsung Internet'
  if (/\b(?:Firefox|FxiOS)\//.test(agent)) return 'Firefox'
  if (/\b(?:Chrome|CriOS|Chromium)\//.test(agent)) return 'Chrome'
  if (/\bSafari\//.test(agent)) return 'Safari'
}

export type BrowserAccessList = 'sessions' | 'trusted-devices'

type Props = {
  list: BrowserAccessList
  onClose: () => void
  onUnauthorized: () => void
}

export function BrowserAccessModal({ list, onClose, onUnauthorized }: Props) {
  const { lang, t } = useI18n()
  const title = useId()
  const dismiss = useModalDismiss(onClose)
  const [entries, setEntries] = useState<BrowserAccessEntry[] | null>(null)
  const [revoking, setRevoking] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const trusted = list === 'trusted-devices'

  useEffect(() => {
    const controller = new AbortController()
    const load = trusted ? listTrustedDevices : listRememberedSessions
    load(controller.signal).then((items) => {
      if (!controller.signal.aborted) setEntries(items)
    }).catch((err) => {
      if (controller.signal.aborted) return
      if (err instanceof ApiError && err.status === 401) onUnauthorized()
      else setError(err instanceof Error ? err.message : trusted
        ? t('Не удалось загрузить доверенные устройства.')
        : t('Не удалось загрузить сохранённые сеансы.'))
    })
    return () => controller.abort()
  }, [onUnauthorized, t, trusted])

  async function revoke(entry: BrowserAccessEntry) {
    const question = trusted
      ? t('Отозвать доверие к этому устройству? Для нового входа потребуется код 2FA.')
      : entry.current
        ? t('Отозвать текущий сеанс? Панель завершит вход в этом браузере.')
        : t('Отозвать этот сеанс? Для следующего входа потребуется пароль.')
    if (!window.confirm(question)) return
    setError(null)
    setRevoking(entry.id)
    try {
      const remove = trusted ? revokeTrustedDevice : revokeRememberedSession
      await remove(entry)
      setEntries((items) => items?.filter(({ id }) => id !== entry.id) ?? null)
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) onUnauthorized()
      else setError(err instanceof Error ? err.message : trusted
        ? t('Не удалось отозвать доверие к устройству.')
        : t('Не удалось отозвать сеанс.'))
    } finally {
      setRevoking(null)
    }
  }

  const dateFormat = new Intl.DateTimeFormat(lang, { dateStyle: 'medium', timeStyle: 'short' })
  function date(value: string) {
    const timestamp = Date.parse(value)
    return Number.isFinite(timestamp)
      ? <time dateTime={value}>{dateFormat.format(timestamp)}</time>
      : '—'
  }

  return (
    <div className="modal-backdrop" onClick={dismiss}>
      <div className="card modal" role="dialog" aria-modal="true" aria-labelledby={title}>
        <div className="clients-head">
          <h3 id={title}>{trusted ? t('Доверенные устройства') : t('Сохранённые сеансы')}</h3>
          <button className="ghost" onClick={onClose}>{t('Закрыть')}</button>
        </div>
        {error && <p className="form-error" role="alert">{error}</p>}
        {trusted && (
          <p className="muted">
            {t('При новом входе с доверенного устройства достаточно пароля. Для важных действий требуется и код 2FA.')}
          </p>
        )}
        {entries === null && !error && <p className="muted" role="status">{t('Загрузка…')}</p>}
        {entries?.length === 0 && (
          <p className="muted">{trusted ? t('Доверенных устройств нет.') : t('Сохранённых сеансов нет.')}</p>
        )}
        {!!entries?.length && (
          <ul className="remembered-sessions">
            {entries.map((entry) => (
              <li key={entry.id} className="remembered-session">
                <div className="remembered-session-label">
                  <strong title={entry.user_agent}>
                    {browserName(entry.user_agent) || t('Неизвестный браузер')}
                  </strong>
                  {entry.current && (
                    <span className="muted small">{trusted ? t('Текущий браузер') : t('Текущий сеанс')}</span>
                  )}
                </div>
                <dl className="remembered-session-dates small">
                  <dt>{t('Создан')}</dt><dd>{date(entry.created_at)}</dd>
                  <dt>{trusted ? t('Последний вход') : t('Последняя активность')}</dt>
                  <dd>{date(entry.last_used_at)}</dd>
                  <dt>{t('Действует до')}</dt><dd>{date(entry.expires_at)}</dd>
                </dl>
                <button className="ghost danger" disabled={revoking !== null} onClick={() => void revoke(entry)}>
                  {revoking === entry.id ? t('…') : t('Отозвать')}
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  )
}
