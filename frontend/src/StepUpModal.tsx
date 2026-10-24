import { useState } from 'react'
import { useI18n } from './i18n'

type Props = {
  text: string
  onSubmit: (password: string) => Promise<void>
  onCancel: () => void
}

// Повторный ввод пароля перед опасным действием (бэкап с SSH-ключом панели,
// восстановление). Ошибку и ожидание показывает само, закрывает родитель.
export function StepUpModal({ text, onSubmit, onCancel }: Props) {
  const { t } = useI18n()
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  return (
    <div className="modal-backdrop">
      <form
        className="card modal"
        onClick={(e) => e.stopPropagation()}
        onSubmit={async (e) => {
          e.preventDefault()
          if (busy || !password) return
          setBusy(true)
          setError(null)
          try {
            await onSubmit(password)
          } catch (err) {
            setError(err instanceof Error ? err.message : t('Ошибка'))
          } finally {
            setBusy(false)
          }
        }}
      >
        <h3>{t('Подтвердите пароль')}</h3>
        <p className="muted small">{text}</p>
        {error && <p className="form-error">{error}</p>}
        <input
          type="password"
          autoFocus
          autoComplete="current-password"
          placeholder={t('Пароль')}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
        <div className="modal-actions">
          <button type="button" className="ghost" onClick={onCancel}>
            {t('Отмена')}
          </button>
          <button type="submit" disabled={busy || !password}>
            {busy ? t('…') : t('Продолжить')}
          </button>
        </div>
      </form>
    </div>
  )
}
