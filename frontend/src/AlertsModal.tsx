import { useEffect, useRef, useState } from 'react'
import { ApiError, getAlerts, putAlerts, testAlerts } from './api'
import { useI18n } from './i18n'
import { StepUpModal } from './StepUpModal'
import { useModalDismiss } from './useModalDismiss'

type Props = {
  onClose: () => void
  onUnauthorized: () => void
}

function AlertSecretField({ label, placeholder, saved, value, onChange }: {
  label: string
  placeholder: string
  saved: boolean
  value: string | undefined
  onChange: (value: string | undefined) => void
}) {
  const { t } = useI18n()
  return (
    <div>
      <label className="field">
        <span>{label}</span>
        <input
          type="password"
          autoComplete="new-password"
          value={value ?? ''}
          onChange={(e) => onChange(e.target.value || undefined)}
          placeholder={saved && value === undefined ? t('Значение сохранено') : placeholder}
        />
      </label>
      {saved && (
        <button type="button" className="ghost small" onClick={() => onChange(value === '' ? undefined : '')}>
          {value === '' ? t('Отменить удаление') : t('Удалить при сохранении')}
        </button>
      )}
    </div>
  )
}

export function AlertsModal({ onClose, onUnauthorized }: Props) {
  const { t, lang } = useI18n()
  const dismiss = useModalDismiss(onClose)
  const [token, setToken] = useState<string>()
  const [tokenSet, setTokenSet] = useState(false)
  const [chat, setChat] = useState('')
  const [apiUrl, setApiUrl] = useState('')
  const [webhook, setWebhook] = useState<string>()
  const [webhookSet, setWebhookSet] = useState(false)
  const [alertLang, setAlertLang] = useState<'ru' | 'en'>(lang)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [testing, setTesting] = useState(false)
  const [msg, setMsg] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loadError, setLoadError] = useState<string | null>(null)
  // каналы сохраняются только с паролем (подменой адреса бота уводили бы
  // токен и security-алерты); тест без правок пароля не просит
  const [stepUp, setStepUp] = useState<'save' | 'test' | null>(null)
  const [saved, setSaved] = useState('')
  const callbacks = useRef({ onUnauthorized, t, lang })
  callbacks.current = { onUnauthorized, t, lang }

  useEffect(() => {
    let cancelled = false
    getAlerts()
      .then((c) => {
        if (cancelled) return
        setTokenSet(c.telegram_token_set)
        setChat(c.telegram_chat)
        setApiUrl(c.telegram_api)
        setWebhookSet(c.webhook_set)
        // язык еще не выбирали: настроенные раньше алерты шли по-русски
        const l = c.lang || (c.enabled ? 'ru' : callbacks.current.lang)
        setAlertLang(l)
        setSaved(JSON.stringify([undefined, c.telegram_chat, c.telegram_api, undefined, l]))
      })
      .catch((err) => {
        if (cancelled) return
        if (err instanceof ApiError && err.status === 401) callbacks.current.onUnauthorized()
        // форму не показываем: сохранение пустых полей стерло бы настройки
        else setLoadError(err instanceof Error ? err.message : callbacks.current.t('Ошибка'))
      })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [])

  const current = JSON.stringify([token, chat, apiUrl, webhook, alertLang])
  const dirty = current !== saved

  // ошибку пароля показывает окно подтверждения, остальное - само окно алертов
  async function put(password: string) {
    try {
      const cfg = await putAlerts({
        telegram_token: token,
        telegram_chat: chat,
        telegram_api: apiUrl,
        webhook,
        lang: alertLang,
        password,
      })
      setToken(undefined)
      setWebhook(undefined)
      setTokenSet(cfg.telegram_token_set)
      setWebhookSet(cfg.webhook_set)
      setChat(cfg.telegram_chat)
      setApiUrl(cfg.telegram_api)
      setSaved(JSON.stringify([undefined, cfg.telegram_chat, cfg.telegram_api, undefined, alertLang]))
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        onUnauthorized()
        return false
      }
      throw err
    }
    setStepUp(null)
    return true
  }

  async function save(password: string) {
    setSaving(true)
    setError(null)
    setMsg(null)
    try {
      if (await put(password)) setMsg(t('Сохранено.'))
    } finally {
      setSaving(false)
    }
  }

  async function runTest(password?: string) {
    if (dirty && password === undefined) {
      setStepUp('test')
      return
    }
    setTesting(true)
    setError(null)
    setMsg(null)
    try {
      // сначала сохраняем, чтобы тест шёл по текущим полям
      if (password !== undefined && !(await put(password))) {
        setTesting(false)
        return
      }
    } catch (err) {
      setTesting(false)
      throw err
    }
    try {
      const r = await testAlerts()
      if (r.sent) setMsg(t('Тестовый алерт отправлен — проверьте канал.'))
      else setError(t('Не отправлено: {err}', { err: r.errors.join('; ') }))
    } catch (err) {
      setError(err instanceof Error ? err.message : t('Ошибка'))
    } finally {
      setTesting(false)
    }
  }

  const canTest = Boolean(((token ?? tokenSet) && chat) || (webhook ?? webhookSet))

  return (
    <div className="modal-backdrop" onClick={dismiss}>
      <div className="card modal" onClick={(e) => e.stopPropagation()}>
        <div className="clients-head">
          <h3>{t('Алерты')}</h3>
          <button className="ghost" onClick={onClose}>
            {t('Закрыть')}
          </button>
        </div>
        <p className="muted small">
          {t(
            'Панель присылает короткие алерты: сервер пропал или вернулся, каскад не работает, пропали клиенты, мало места на диске, события безопасности.',
          )}
        </p>

        {loading ? (
          <p className="muted">{t('загрузка…')}</p>
        ) : loadError ? (
          <p className="form-error">{loadError}</p>
        ) : (
          <>
            <div className="settings-group">
              <h4>{t('Telegram')}</h4>
              <p className="muted small">
                {t(
                  'Создайте бота через @BotFather, вставьте его токен и chat_id (свой ID узнаете у @userinfobot).',
                )}
              </p>
              <AlertSecretField
                label={t('Токен бота')}
                placeholder="123456:ABC-DEF…"
                saved={tokenSet}
                value={token}
                onChange={setToken}
              />
              <label className="field">
                <span>{t('Chat ID')}</span>
                <input
                  value={chat}
                  onChange={(e) => setChat(e.target.value)}
                  placeholder="123456789"
                />
              </label>
              <label className="field">
                <span>{t('Адрес Bot API')}</span>
                <input
                  value={apiUrl}
                  onChange={(e) => setApiUrl(e.target.value)}
                  placeholder="https://api.telegram.org"
                />
                <span className="muted small">
                  {t(
                    'Оставьте пустым для api.telegram.org. Укажите зеркало/прокси, если Telegram заблокирован в регионе сервера (напр. https://api-tg.example.com).',
                  )}
                </span>
              </label>
            </div>

            <div className="settings-group">
              <h4>{t('Вебхук')}</h4>
              <p className="muted small">
                {t('POST с JSON {"text": "…"} на указанный URL (Slack, Mattermost, свой сервис).')}
              </p>
              <AlertSecretField
                label="URL"
                placeholder="https://…"
                saved={webhookSet}
                value={webhook}
                onChange={setWebhook}
              />
            </div>

            <div className="settings-group">
              <label className="field">
                <span>{t('Язык алертов')}</span>
                <select
                  value={alertLang}
                  onChange={(e) => setAlertLang(e.target.value as 'ru' | 'en')}
                >
                  <option value="ru">Русский</option>
                  <option value="en">English</option>
                </select>
              </label>
            </div>

            {error && <p className="form-error">{error}</p>}
            {msg && <p className="form-ok">{msg}</p>}

            <div className="modal-actions">
              <button
                className="ghost"
                onClick={() => void runTest()}
                disabled={testing || !canTest}
              >
                {testing ? t('Отправка…') : t('Проверить')}
              </button>
              <button onClick={() => setStepUp('save')} disabled={saving || !dirty}>
                {saving ? t('Сохранение…') : t('Сохранить')}
              </button>
            </div>
          </>
        )}
      </div>
      {stepUp && (
        <StepUpModal
          text={t('Каналы алертов получают и события безопасности. Введите пароль от панели, чтобы сохранить их.')}
          onSubmit={(pw) => (stepUp === 'save' ? save(pw) : runTest(pw))}
          onCancel={() => setStepUp(null)}
        />
      )}
    </div>
  )
}
