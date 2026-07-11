import { useEffect, useState } from 'react'
import { getAlerts, putAlerts, testAlerts } from './api'
import { useI18n } from './i18n'
import { useModalDismiss } from './useModalDismiss'

type Props = {
  onClose: () => void
  onUnauthorized: () => void
}

export function AlertsModal({ onClose, onUnauthorized }: Props) {
  const { t } = useI18n()
  const dismiss = useModalDismiss(onClose)
  const [token, setToken] = useState('')
  const [chat, setChat] = useState('')
  const [webhook, setWebhook] = useState('')
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [testing, setTesting] = useState(false)
  const [msg, setMsg] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    getAlerts()
      .then((c) => {
        setToken(c.telegram_token)
        setChat(c.telegram_chat)
        setWebhook(c.webhook)
      })
      .catch(() => onUnauthorized())
      .finally(() => setLoading(false))
  }, [onUnauthorized])

  async function save() {
    setSaving(true)
    setError(null)
    setMsg(null)
    try {
      await putAlerts({
        telegram_token: token,
        telegram_chat: chat,
        webhook,
      })
      setMsg(t('Сохранено.'))
    } catch (err) {
      setError(err instanceof Error ? err.message : t('Ошибка'))
    } finally {
      setSaving(false)
    }
  }

  async function runTest() {
    setTesting(true)
    setError(null)
    setMsg(null)
    try {
      // сначала сохраняем, чтобы тест шёл по текущим полям
      await putAlerts({ telegram_token: token, telegram_chat: chat, webhook })
      const r = await testAlerts()
      if (r.sent) setMsg(t('Тестовый алерт отправлен — проверьте канал.'))
      else setError(t('Не отправлено: {err}', { err: r.errors.join('; ') }))
    } catch (err) {
      setError(err instanceof Error ? err.message : t('Ошибка'))
    } finally {
      setTesting(false)
    }
  }

  const canTest = Boolean((token && chat) || webhook)

  return (
    <div className="modal-backdrop" onClick={dismiss}>
      <div className="card modal" onClick={(e) => e.stopPropagation()}>
        <div className="clients-head">
          <h3>{t('Алерты о падении серверов')}</h3>
          <button className="ghost" onClick={onClose}>
            {t('Закрыть')}
          </button>
        </div>
        <p className="muted small">
          {t(
            'Панель следит за доступностью серверов и присылает уведомление, когда сервер пропадает или снова становится онлайн. Проверка идёт вместе со сбором метрик.',
          )}
        </p>

        {loading ? (
          <p className="muted">{t('загрузка…')}</p>
        ) : (
          <>
            <div className="settings-group">
              <h4>{t('Telegram')}</h4>
              <p className="muted small">
                {t(
                  'Создайте бота через @BotFather, вставьте его токен и chat_id (свой ID узнаете у @userinfobot).',
                )}
              </p>
              <label className="field">
                <span>{t('Токен бота')}</span>
                <input
                  value={token}
                  onChange={(e) => setToken(e.target.value)}
                  placeholder="123456:ABC-DEF…"
                />
              </label>
              <label className="field">
                <span>{t('Chat ID')}</span>
                <input
                  value={chat}
                  onChange={(e) => setChat(e.target.value)}
                  placeholder="123456789"
                />
              </label>
            </div>

            <div className="settings-group">
              <h4>{t('Вебхук')}</h4>
              <p className="muted small">
                {t('POST с JSON {"text": "…"} на указанный URL (Slack, Mattermost, свой сервис).')}
              </p>
              <label className="field">
                <span>URL</span>
                <input
                  value={webhook}
                  onChange={(e) => setWebhook(e.target.value)}
                  placeholder="https://…"
                />
              </label>
            </div>

            {error && <p className="form-error">{error}</p>}
            {msg && <p className="form-ok">{msg}</p>}

            <div className="modal-actions">
              <button
                className="ghost"
                onClick={runTest}
                disabled={testing || !canTest}
              >
                {testing ? t('Отправка…') : t('Проверить')}
              </button>
              <button onClick={save} disabled={saving}>
                {saving ? t('Сохранение…') : t('Сохранить')}
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  )
}
