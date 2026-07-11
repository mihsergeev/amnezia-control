import { useEffect, useState } from 'react'
import QRCode from 'qrcode'
import {
  disable2FA,
  enable2FA,
  get2FA,
  setup2FA,
  type TwoFASetup,
} from './api'
import { useI18n } from './i18n'
import { useModalDismiss } from './useModalDismiss'

type Props = {
  onClose: () => void
  onUnauthorized: () => void
}

export function TwoFAModal({ onClose, onUnauthorized }: Props) {
  const { t } = useI18n()
  const dismiss = useModalDismiss(onClose)
  const [enabled, setEnabled] = useState<boolean | null>(null)
  const [setup, setSetup] = useState<TwoFASetup | null>(null)
  const [qr, setQr] = useState<string | null>(null)
  const [otp, setOtp] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    get2FA()
      .then((s) => setEnabled(s.enabled))
      .catch(() => onUnauthorized())
  }, [onUnauthorized])

  useEffect(() => {
    if (!setup) {
      setQr(null)
      return
    }
    let alive = true
    QRCode.toDataURL(setup.otpauth_uri, { margin: 1, width: 240 })
      .then((url) => alive && setQr(url))
      .catch(() => alive && setQr(null))
    return () => {
      alive = false
    }
  }, [setup])

  async function startSetup() {
    setBusy(true)
    setError(null)
    try {
      setSetup(await setup2FA())
      setOtp('')
    } catch (err) {
      setError(err instanceof Error ? err.message : t('Ошибка'))
    } finally {
      setBusy(false)
    }
  }

  async function confirmEnable() {
    setBusy(true)
    setError(null)
    try {
      const s = await enable2FA(otp.trim())
      setEnabled(s.enabled)
      setSetup(null)
      setOtp('')
    } catch (err) {
      setError(err instanceof Error ? err.message : t('Неверный код'))
    } finally {
      setBusy(false)
    }
  }

  async function turnOff() {
    setBusy(true)
    setError(null)
    try {
      const s = await disable2FA(otp.trim())
      setEnabled(s.enabled)
      setOtp('')
    } catch (err) {
      setError(err instanceof Error ? err.message : t('Неверный код'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="modal-backdrop" onClick={dismiss}>
      <div className="card modal" onClick={(e) => e.stopPropagation()}>
        <div className="clients-head">
          <h3>{t('Двухфакторная аутентификация')}</h3>
          <button className="ghost" onClick={onClose}>
            {t('Закрыть')}
          </button>
        </div>

        {enabled === null ? (
          <p className="muted">{t('загрузка…')}</p>
        ) : enabled ? (
          <>
            <p className="form-ok">{t('2FA включена. Вход требует код из приложения.')}</p>
            <p className="muted small">
              {t('Чтобы отключить, введите текущий код из приложения-аутентификатора.')}
            </p>
            <label className="field">
              <span>{t('Код из приложения (2FA)')}</span>
              <input
                value={otp}
                onChange={(e) => setOtp(e.target.value)}
                inputMode="numeric"
                placeholder="123456"
              />
            </label>
            {error && <p className="form-error">{error}</p>}
            <div className="modal-actions">
              <button
                className="danger-solid"
                onClick={turnOff}
                disabled={busy || !otp.trim()}
              >
                {busy ? t('…') : t('Отключить 2FA')}
              </button>
            </div>
          </>
        ) : setup ? (
          <>
            <p className="muted small">
              {t(
                'Отсканируйте QR в приложении-аутентификаторе (Google Authenticator, Aegis, 1Password) или введите ключ вручную, затем подтвердите кодом.',
              )}
            </p>
            <div className="qr-wrap">
              {qr ? (
                <img src={qr} alt="2FA QR" width={200} height={200} />
              ) : (
                <span className="muted small">{t('генерация QR…')}</span>
              )}
            </div>
            <p className="muted small">
              {t('Ключ:')} <span className="mono">{setup.secret}</span>
            </p>
            <label className="field">
              <span>{t('Код из приложения (2FA)')}</span>
              <input
                value={otp}
                onChange={(e) => setOtp(e.target.value)}
                inputMode="numeric"
                placeholder="123456"
                autoFocus
              />
            </label>
            {error && <p className="form-error">{error}</p>}
            <div className="modal-actions">
              <button className="ghost" onClick={() => setSetup(null)}>
                {t('Отмена')}
              </button>
              <button onClick={confirmEnable} disabled={busy || !otp.trim()}>
                {busy ? t('…') : t('Включить')}
              </button>
            </div>
          </>
        ) : (
          <>
            <p className="muted small">
              {t(
                'Добавьте второй фактор к входу в панель — одноразовый код из приложения-аутентификатора (TOTP).',
              )}
            </p>
            {error && <p className="form-error">{error}</p>}
            <div className="modal-actions">
              <button onClick={startSetup} disabled={busy}>
                {busy ? t('…') : t('Включить 2FA')}
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  )
}
