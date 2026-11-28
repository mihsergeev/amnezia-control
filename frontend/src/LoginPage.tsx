import { useState, type FormEvent } from 'react'
import { ApiError, loginPanel } from './api'
import { canUseSessionCookies } from './authSession'
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
  const [trustDevice, setTrustDevice] = useState(false)
  const [showPassword, setShowPassword] = useState(false)
  const secure = canUseSessionCookies()

  async function submit(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await loginPanel(username, password, otp.trim() || null, secure && remember, secure && needOtp && trustDevice)
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
        <header className="login-heading">
          <PanelLogo src={logoSrc} className="login-logo" alt="Amnezia Control" loginSize={logoSize} />
          <h2>{t(needOtp ? 'Подтверждение входа' : 'Вход в панель')}</h2>
        </header>
        <div className="login-fields" hidden={needOtp}>
          <label htmlFor="login-username">{t('Логин')}</label>
          <input
            id="login-username"
            name="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="username"
            autoCapitalize="none"
            spellCheck={false}
            disabled={needOtp}
            required
          />
          <label htmlFor="login-password">{t('Пароль')}</label>
          <div className="login-password">
            <input
              id="login-password"
              name="password"
              type={showPassword ? 'text' : 'password'}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
              disabled={needOtp}
              required
            />
            <button
              type="button"
              className="ghost"
              aria-label={t(showPassword ? 'Скрыть пароль' : 'Показать пароль')}
              aria-controls="login-password"
              onClick={() => setShowPassword((shown) => !shown)}
            >
              {t(showPassword ? 'Скрыть' : 'Показать')}
            </button>
          </div>
        </div>
        {needOtp && (
          <label className="login-otp">
            {t('Код из приложения (2FA)')}
            <input
              value={otp}
              onChange={(e) => setOtp(e.target.value)}
              autoComplete="one-time-code"
              inputMode="numeric"
              autoFocus
              required
            />
          </label>
        )}
        {secure && (
          <div className="login-options">
            <div className="login-option">
              <input
                id="login-remember"
                type="checkbox"
                checked={remember}
                onChange={(e) => setRemember(e.target.checked)}
                aria-describedby="login-remember-hint"
                disabled={busy}
              />
              <div>
                <label htmlFor="login-remember">{t('Запомнить вход')}</label>
                <small id="login-remember-hint">{t('До 30 дней, 7 дней без активности')}</small>
              </div>
            </div>
            {needOtp && (
              <div className="login-option">
                <input
                  id="login-trust"
                  type="checkbox"
                  checked={trustDevice}
                  onChange={(e) => setTrustDevice(e.target.checked)}
                  aria-describedby="login-trust-hint"
                  disabled={busy}
                />
                <div>
                  <label htmlFor="login-trust">{t('Доверять этому устройству')}</label>
                  <small id="login-trust-hint">{t('Вход по паролю на 30 дней')}</small>
                </div>
              </div>
            )}
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
        {error && <p className="form-error" role="alert">{error}</p>}
        <button type="submit" className="login-submit" disabled={busy}>
          {busy ? t('Проверка…') : t('Войти')}
        </button>
        {needOtp && (
          <button type="button" className="ghost login-back" disabled={busy} onClick={() => {
            setNeedOtp(false)
            setOtp('')
            setTrustDevice(false)
            setShowPassword(false)
            setError(null)
          }}>
            {t('Назад')}
          </button>
        )}
      </form>
    </div>
  )
}
