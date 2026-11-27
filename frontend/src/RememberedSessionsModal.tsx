import { useEffect, useId, useState } from 'react'
import {
  ApiError,
  listRememberedSessions,
  revokeRememberedSession,
  type RememberedSession,
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

type Props = {
  onClose: () => void
  onUnauthorized: () => void
}

export function RememberedSessionsModal({ onClose, onUnauthorized }: Props) {
  const { lang, t } = useI18n()
  const title = useId()
  const dismiss = useModalDismiss(onClose)
  const [sessions, setSessions] = useState<RememberedSession[] | null>(null)
  const [revoking, setRevoking] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const controller = new AbortController()
    listRememberedSessions(controller.signal).then((items) => {
      if (!controller.signal.aborted) setSessions(items)
    }).catch((err) => {
      if (controller.signal.aborted) return
      if (err instanceof ApiError && err.status === 401) onUnauthorized()
      else setError(err instanceof Error ? err.message : t('Не удалось загрузить сохранённые сеансы.'))
    })
    return () => controller.abort()
  }, [onUnauthorized, t])

  async function revoke(session: RememberedSession) {
    const question = session.current
      ? t('Отозвать текущий сеанс? Панель завершит вход в этом браузере.')
      : t('Отозвать этот сеанс? Для следующего входа потребуется пароль.')
    if (!window.confirm(question)) return
    setError(null)
    setRevoking(session.id)
    try {
      await revokeRememberedSession(session)
      setSessions((items) => items?.filter(({ id }) => id !== session.id) ?? null)
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) onUnauthorized()
      else setError(err instanceof Error ? err.message : t('Не удалось отозвать сеанс.'))
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
          <h3 id={title}>{t('Сохранённые сеансы')}</h3>
          <button className="ghost" onClick={onClose}>{t('Закрыть')}</button>
        </div>
        {error && <p className="form-error" role="alert">{error}</p>}
        {sessions === null && !error && <p className="muted" role="status">{t('Загрузка…')}</p>}
        {sessions?.length === 0 && <p className="muted">{t('Сохранённых сеансов нет.')}</p>}
        {!!sessions?.length && (
          <ul className="remembered-sessions">
            {sessions.map((session) => (
              <li key={session.id} className="remembered-session">
                <div className="remembered-session-label">
                  <strong title={session.user_agent}>
                    {browserName(session.user_agent) || t('Неизвестный браузер')}
                  </strong>
                  {session.current && <span className="muted small">{t('Текущий сеанс')}</span>}
                </div>
                <dl className="remembered-session-dates small">
                  <dt>{t('Создан')}</dt><dd>{date(session.created_at)}</dd>
                  <dt>{t('Последняя активность')}</dt><dd>{date(session.last_used_at)}</dd>
                  <dt>{t('Действует до')}</dt><dd>{date(session.expires_at)}</dd>
                </dl>
                <button className="ghost danger" disabled={revoking !== null} onClick={() => void revoke(session)}>
                  {revoking === session.id ? t('…') : t('Отозвать')}
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  )
}
