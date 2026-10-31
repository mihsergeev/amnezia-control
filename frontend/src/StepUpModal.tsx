import { useEffect, useRef, useState } from 'react'
import { get2FA, withStepUpOtp } from './api'
import { useI18n } from './i18n'
import { useModalDismiss } from './useModalDismiss'

type Props = {
  text: string
  onSubmit: (password: string) => Promise<void>
  onCancel: () => void
}

// Повторный ввод пароля перед опасным действием (бэкап с SSH-ключом панели,
// восстановление, API-ключи, алерты). Ошибку и ожидание показывает само,
// закрывает родитель. При включенной 2FA спрашивает и код: он уходит заголовком
// через withStepUpOtp, поэтому onSubmit по-прежнему получает только пароль.
export function StepUpModal({ text, onSubmit, onCancel }: Props) {
  const { t } = useI18n()
  const [password, setPassword] = useState('')
  const [otp, setOtp] = useState('')
  const [needOtp, setNeedOtp] = useState(false)
  const [busy, setBusy] = useState(false)
  const submitting = useRef(false)
  const [error, setError] = useState<string | null>(null)
  useModalDismiss(onCancel)

  // поле кода сразу, если 2FA включена; иначе его покажет ответ бэкенда
  useEffect(() => {
    get2FA()
      .then((s) => s.enabled && setNeedOtp(true))
      .catch(() => {})
  }, [])

  const ready = !!password && (!needOtp || !!otp.trim())

  return (
    <div className="modal-backdrop">
      <form
        className="card modal"
        onClick={(e) => e.stopPropagation()}
        onSubmit={async (e) => {
          e.preventDefault()
          if (submitting.current || !ready) return
          submitting.current = true
          setBusy(true)
          setError(null)
          try {
            await withStepUpOtp(otp, () => setNeedOtp(true), () => onSubmit(password))
          } catch (err) {
            setError(err instanceof Error ? err.message : t('Ошибка'))
            // код одноразовый: после неудачи нужен новый
            setOtp('')
          } finally {
            submitting.current = false
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
          maxLength={128}
          placeholder={t('Пароль')}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
        {needOtp && (
          <input
            inputMode="numeric"
            autoComplete="one-time-code"
            maxLength={16}
            placeholder={t('Код 2FA из приложения')}
            value={otp}
            onChange={(e) => setOtp(e.target.value)}
          />
        )}
        <div className="modal-actions">
          <button type="button" className="ghost" onClick={onCancel}>
            {t('Отмена')}
          </button>
          <button type="submit" disabled={busy || !ready}>
            {busy ? t('…') : t('Продолжить')}
          </button>
        </div>
      </form>
    </div>
  )
}
