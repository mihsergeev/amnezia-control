import { useState, type FormEvent } from 'react'
import { ApiError, loginPanel } from './api'
import { canRememberLogin } from './authSession'
import { useI18n } from './i18n'
import { PanelLogo } from './PanelLogo'

type Props = {
  onLogin: () => void
  logoSrc: string | null | undefined
  logoSize?: number
  onRetryRestore?: () => void
}

export function LoginPage({ onLogin, logoSrc, logoSize, onRetryRestore }: Props) {
  const { t } = useI18n()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [otp, setOtp] = useState('')
  const [needOtp, setNeedOtp] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [remember, setRemember] = useState(false)
  const rememberAvailable = canRememberLogin()

  async function submit(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await loginPanel(username, password, otp.trim() || null, rememberAvailable && remember)
      onLogin()
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        if (err.message === '2fa_required') {
          setNeedOtp(true)
          setError(null)
        } else if (err.message === '2fa_invalid') {
          setNeedOtp(true)
          setError(t('Неверный код 2FA'))
        } else {
          setError(t('Неверный логин или пароль'))
        }
      } else {
        setError(err instanceof Error ? err.message : t('Не удалось войти'))
      }
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="login-wrap">
      <form className="card login-card" onSubmit={submit}>
        <PanelLogo src={logoSrc} className="login-logo" alt="Amnezia Control" loginSize={logoSize} />
        <h2>{t('Вход в панель')}</h2>
        <label>
          {t('Логин')}
          <input
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="username"
            disabled={needOtp}
            required
          />
        </label>
        <label>
          {t('Пароль')}
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
            disabled={needOtp}
            required
          />
        </label>
        {needOtp && (
          <label>
            {t('Код из приложения (2FA)')}
            <input
              value={otp}
              onChange={(e) => setOtp(e.target.value)}
              autoComplete="one-time-code"
              inputMode="numeric"
              placeholder="123456"
              autoFocus
              required
            />
          </label>
        )}
        {rememberAvailable && (
          <div className="login-remember">
            <label>
              <input
                type="checkbox"
                checked={remember}
                onChange={(e) => setRemember(e.target.checked)}
                aria-describedby="login-remember-hint"
                disabled={busy}
              />
              {t('Запомнить вход на этом устройстве')}
            </label>
            <small id="login-remember-hint" className="muted">
              {t('Вход сохранится до 30 дней и завершится через 7 дней без продления. Используйте на личном устройстве.')}
            </small>
          </div>
        )}
        {onRetryRestore && (
          <div className="login-restore-error">
            <p className="form-error" role="status">{t('Не удалось восстановить сохранённый вход.')}</p>
            <button type="button" className="ghost" onClick={onRetryRestore} disabled={busy}>
              {t('Повторить восстановление входа')}
            </button>
          </div>
        )}
        {error && <p className="form-error">{error}</p>}
        <button type="submit" disabled={busy}>
          {busy ? t('Проверка…') : t('Войти')}
        </button>
      </form>
    </div>
  )
}
