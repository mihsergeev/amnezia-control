import { useState } from 'react'
import { ApiError, changePassword } from './api'
import { useI18n } from './i18n'
import { useModalDismiss } from './useModalDismiss'

type Props = {
  onClose: () => void
  onUnauthorized: () => void
}

export function PasswordModal({ onClose, onUnauthorized }: Props) {
  const { t } = useI18n()
  const dismiss = useModalDismiss(onClose)
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [done, setDone] = useState(false)

  const tooShort = next.length > 0 && next.length < 8
  const mismatch = confirm.length > 0 && next !== confirm
  const canSubmit =
    !!current && next.length >= 8 && next === confirm && !busy

  async function submit() {
    setBusy(true)
    setError(null)
    try {
      await changePassword(current, next)
      setDone(true)
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        onUnauthorized()
        return
      }
      setError(err instanceof Error ? err.message : t('Ошибка'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="modal-backdrop" onClick={dismiss}>
      <div className="card modal" onClick={(e) => e.stopPropagation()}>
        <div className="clients-head">
          <h3>{t('Сменить пароль')}</h3>
          <button className="ghost" onClick={onClose}>
            {t('Закрыть')}
          </button>
        </div>

        {done ? (
          <>
            <p className="form-ok">
              {t('Пароль изменён. Все прежние сессии завершены.')}
            </p>
            <div className="modal-actions">
              <button onClick={onClose}>{t('Готово')}</button>
            </div>
          </>
        ) : (
          <>
            <p className="muted small">
              {t('Смена пароля завершит все другие активные сессии.')}
            </p>
            <label className="field">
              <span>{t('Текущий пароль')}</span>
              <input
                type="password"
                value={current}
                onChange={(e) => setCurrent(e.target.value)}
                autoComplete="current-password"
                autoFocus
              />
            </label>
            <label className="field">
              <span>{t('Новый пароль (мин. 8 символов)')}</span>
              <input
                type="password"
                value={next}
                onChange={(e) => setNext(e.target.value)}
                autoComplete="new-password"
              />
            </label>
            <label className="field">
              <span>{t('Повторите новый пароль')}</span>
              <input
                type="password"
                value={confirm}
                onChange={(e) => setConfirm(e.target.value)}
                autoComplete="new-password"
              />
            </label>
            {tooShort && (
              <p className="form-error">{t('Пароль должен быть не короче 8 символов')}</p>
            )}
            {mismatch && <p className="form-error">{t('Пароли не совпадают')}</p>}
            {error && <p className="form-error">{error}</p>}
            <div className="modal-actions">
              <button className="ghost" onClick={onClose}>
                {t('Отмена')}
              </button>
              <button onClick={submit} disabled={!canSubmit}>
                {busy ? t('…') : t('Сменить пароль')}
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  )
}
