import { useEffect, useId, useRef, useState } from 'react'
import { get2FA, withStepUpOtp } from './api'
import { useI18n } from './i18n'
import { useModalDismiss } from './useModalDismiss'

type Props = {
  text: string
  onCancel: () => void
} & (
  | { requiredOtp?: false; onSubmit: (password: string) => Promise<void> }
  | { requiredOtp: true; onSubmit: (password: string, otp: string) => Promise<void> }
)

// Повторный ввод пароля перед опасным действием (бэкап с SSH-ключом панели,
// восстановление, API-ключи, алерты). Ошибку и ожидание показывает само,
// закрывает родитель. Для установки код передаётся вместе с паролем.
// Остальные действия передают код заголовком через withStepUpOtp.
export function StepUpModal(props: Props) {
  const { text, onCancel, requiredOtp } = props
  const { t } = useI18n()
  const title = useId()
  const description = useId()
  const [password, setPassword] = useState('')
  const [otp, setOtp] = useState('')
  const [needOtp, setNeedOtp] = useState(false)
  const [busy, setBusy] = useState(false)
  const submitting = useRef(false)
  const [error, setError] = useState<string | null>(null)
  useModalDismiss(() => { if (!requiredOtp || !submitting.current) onCancel() })

  // поле кода сразу, если 2FA включена; иначе его покажет ответ бэкенда
  useEffect(() => {
    if (requiredOtp) return
    get2FA()
      .then((s) => s.enabled && setNeedOtp(true))
      .catch(() => {})
  }, [requiredOtp])

  const ready = !!password && (requiredOtp ? /^\d{6}$/.test(otp) : !needOtp || !!otp.trim())

  return (
    <div className="modal-backdrop">
      <form
        className={requiredOtp ? 'card modal panel-install-confirm' : 'card modal'}
        role="dialog"
        aria-modal="true"
        aria-labelledby={title}
        aria-describedby={description}
        onClick={(e) => e.stopPropagation()}
        onSubmit={async (e) => {
          e.preventDefault()
          if (submitting.current || !ready) return
          submitting.current = true
          setBusy(true)
          setError(null)
          try {
            if (props.requiredOtp) await props.onSubmit(password, otp)
            else await withStepUpOtp(otp, () => setNeedOtp(true), () => props.onSubmit(password))
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
        <h3 id={title}>{t(requiredOtp ? 'Подтвердите установку' : 'Подтвердите пароль')}</h3>
        <p className="muted small" id={description}>{text}</p>
        {error && <p className="form-error" role="alert">{error}</p>}
        <input
          type="password"
          autoFocus
          autoComplete="current-password"
          maxLength={128}
          aria-label={t('Пароль')}
          placeholder={t('Пароль')}
          value={password}
          disabled={requiredOtp && busy}
          onChange={(e) => setPassword(e.target.value)}
        />
        {(requiredOtp || needOtp) && (
          <input
            inputMode="numeric"
            autoComplete="one-time-code"
            maxLength={requiredOtp ? 6 : 16}
            aria-label={t('Код 2FA из приложения')}
            placeholder={t('Код 2FA из приложения')}
            value={otp}
            disabled={requiredOtp && busy}
            onChange={(e) => setOtp(e.target.value)}
          />
        )}
        <div className="modal-actions">
          <button type="button" className="ghost" disabled={requiredOtp && busy} onClick={onCancel}>
            {t('Отмена')}
          </button>
          <button type="submit" disabled={busy || !ready}>
            {busy ? t('…') : requiredOtp ? t('Установить') : t('Продолжить')}
          </button>
        </div>
      </form>
    </div>
  )
}
