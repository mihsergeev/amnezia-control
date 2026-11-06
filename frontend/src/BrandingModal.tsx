import { useRef, useState, type ChangeEvent } from 'react'
import { api, ApiError, logoUrl, type Branding } from './api'
import { useI18n } from './i18n'
import { LOGO_TYPES, logoThemes, MAX_LOGO_BYTES, prepareLogo, type LogoVariants } from './logoAdapt'
import { PanelLogo } from './PanelLogo'
import { useModalDismiss } from './useModalDismiss'

export function BrandingModal({ version, onChanged, onClose, onUnauthorized }: {
  version: string | null
  onChanged: (version: string | null) => void
  onClose: () => void
  onUnauthorized: () => void
}) {
  const { t } = useI18n()
  const [draft, setDraft] = useState<LogoVariants | null>(null)
  const [busy, setBusy] = useState<'prepare' | 'save' | 'reset' | null>(null)
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')
  const fileInput = useRef<HTMLInputElement>(null)
  const saving = busy === 'save' || busy === 'reset'
  const dismiss = useModalDismiss(() => { if (!saving) onClose() })

  async function selectFile(event: ChangeEvent<HTMLInputElement>) {
    const input = event.currentTarget
    const file = input.files?.[0]
    if (!file) return
    setMessage('')
    setError('')
    setDraft(null)
    if (file.size > MAX_LOGO_BYTES) {
      input.value = ''
      setError(t('Файл логотипа больше 5 МБ.'))
      return
    }
    if (!LOGO_TYPES.split(',').includes(file.type)) {
      input.value = ''
      setError(t('Выберите изображение PNG, JPEG, WebP или SVG.'))
      return
    }
    setBusy('prepare')
    try {
      setDraft(await prepareLogo(file))
    } catch {
      input.value = ''
      setError(t('Не удалось подготовить изображение. Проверьте файл и его размеры.'))
    } finally {
      setBusy(null)
    }
  }

  async function changeLogo(method: 'PUT' | 'DELETE') {
    setBusy(method === 'PUT' ? 'save' : 'reset')
    setMessage('')
    setError('')
    try {
      const next = await api<Branding>('/api/branding', {
        method,
        body: method === 'PUT' ? JSON.stringify(draft) : undefined,
      })
      onChanged(next.version)
      setDraft(null)
      if (fileInput.current) fileInput.current.value = ''
      setMessage(t('Сохранено.'))
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) onUnauthorized()
      else setError(t('Не удалось сохранить логотип.'))
    } finally {
      setBusy(null)
    }
  }

  return (
    <div className="modal-backdrop" onClick={dismiss}>
      <div className="card modal branding-modal" role="dialog" aria-modal="true" aria-labelledby="branding-title">
        <div className="clients-head">
          <h3 id="branding-title">{t('Логотип панели')}</h3>
          <button className="ghost" onClick={onClose} disabled={saving}>{t('Закрыть')}</button>
        </div>
        <p className="muted">{t('Логотип показывается в шапке и на странице входа. Панель сама подбирает контраст для каждой темы и сохраняет пропорции.')}</p>
        <label className="branding-file">
          {t('Файл логотипа')}
          <input ref={fileInput} type="file" accept={LOGO_TYPES} onChange={selectFile} disabled={Boolean(busy)} />
          <span className="muted small">{t('PNG, JPEG, WebP или SVG, до 5 МБ')}</span>
        </label>
        <div className="branding-previews" aria-busy={busy === 'prepare'}>
          {logoThemes.map((theme) => (
            <div className={`branding-preview branding-preview-${theme}`} key={theme}>
              <span>{theme === 'light' ? t('Светлая тема') : t('Темная тема')}</span>
              <PanelLogo
                className="branding-preview-logo"
                src={draft ? `data:image/png;base64,${draft[theme]}` : version ? logoUrl(version, theme) : undefined}
              />
            </div>
          ))}
        </div>
        {busy === 'prepare' && <p className="muted" role="status">{t('Подготавливаем логотип…')}</p>}
        {error && <p className="form-error" role="alert">{error}</p>}
        {message && <p className="muted" role="status">{message}</p>}
        <div className="modal-actions">
          {version && <button className="ghost" onClick={() => void changeLogo('DELETE')} disabled={Boolean(busy)}>
            {t('Вернуть стандартный логотип')}
          </button>}
          <button className="primary" onClick={() => void changeLogo('PUT')} disabled={!draft || Boolean(busy)}>
            {t('Сохранить')}
          </button>
        </div>
      </div>
    </div>
  )
}
