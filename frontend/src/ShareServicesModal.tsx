import { useEffect, useState } from 'react'
import {
  ApiError,
  addShareService,
  deleteShareService,
  getShareServices,
  type ShareService,
} from './api'
import { useI18n } from './i18n'
import { resetShareServices } from './ShareLink'
import { useModalDismiss } from './useModalDismiss'

type Props = {
  onClose: () => void
  onUnauthorized: () => void
}

const ENGINE_LABEL: Record<string, string> = {
  sup3rs3cret: 'sup3rS3cretMes5age',
  pwpush: 'Password Pusher',
}

/** Сервисы одноразовых ссылок: в окне конфига появляется кнопка «Ссылка». */
export function ShareServicesModal({ onClose, onUnauthorized }: Props) {
  const { t } = useI18n()
  const dismiss = useModalDismiss(onClose)
  const [services, setServices] = useState<ShareService[]>([])
  const [loading, setLoading] = useState(true)
  const [name, setName] = useState('')
  const [url, setUrl] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    getShareServices()
      .then(setServices)
      .catch((err) => {
        if (err instanceof ApiError && err.status === 401) onUnauthorized()
        else setError(err instanceof Error ? err.message : t('Ошибка'))
      })
      .finally(() => setLoading(false))
  }, [onUnauthorized, t])

  async function run(op: () => Promise<ShareService[]>) {
    setBusy(true)
    setError(null)
    try {
      setServices(await op())
      resetShareServices()
      return true
    } catch (err) {
      setError(err instanceof Error ? err.message : t('Ошибка'))
      return false
    } finally {
      setBusy(false)
    }
  }

  async function add() {
    if (await run(() => addShareService(name.trim(), url.trim()))) {
      setName('')
      setUrl('')
    }
  }

  return (
    <div className="modal-backdrop" onClick={dismiss}>
      <div className="card modal" onClick={(e) => e.stopPropagation()}>
        <div className="clients-head">
          <h3>{t('Ссылки на конфиги')}</h3>
          <button className="ghost" onClick={onClose}>
            {t('Закрыть')}
          </button>
        </div>
        <p className="muted small">
          {t(
            'Вместо файла в мессенджере - одноразовая ссылка: панель кладет конфиг в сервис секретов, ссылка открывается один раз и через 7 дней сгорит сама. Подходят sup3rS3cretMes5age и Password Pusher: поставьте любой у себя и укажите его адрес. В окне конфига появится кнопка «Ссылка».',
          )}
        </p>

        {loading ? (
          <p className="muted">{t('загрузка…')}</p>
        ) : (
          <>
            {services.length > 0 && (
              <div className="share-services">
                {services.map((s) => (
                  <div className="share-service" key={s.id}>
                    <div>
                      <b>{s.name}</b>
                      <div className="muted small mono">{s.url}</div>
                      <div className="muted small">{ENGINE_LABEL[s.engine] ?? s.engine}</div>
                    </div>
                    <button
                      className="ghost danger"
                      disabled={busy}
                      onClick={() => run(() => deleteShareService(s.id))}
                    >
                      {t('Удалить')}
                    </button>
                  </div>
                ))}
              </div>
            )}

            <div className="settings-group">
              <h4>{t('Добавить сервис')}</h4>
              <label className="field">
                <span>{t('Название')}</span>
                <input
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder={t('Например, как группа серверов')}
                />
              </label>
              <label className="field">
                <span>URL</span>
                <input
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder="https://secret.example.com"
                />
              </label>
              <p className="muted small">
                {t(
                  'Если название совпадает с группой сервера, этот сервис предлагается первым для его клиентов.',
                )}
              </p>
            </div>

            {error && <p className="form-error">{error}</p>}

            <div className="modal-actions">
              <button onClick={add} disabled={busy || !name.trim() || !url.trim()}>
                {busy ? t('Проверяю…') : t('Добавить')}
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  )
}
