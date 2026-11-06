import { useRef, useState, type ChangeEvent } from 'react'
import { api, ApiError, DEFAULT_PANEL_TITLE, logoUrl, MAX_BRANDING_TITLE_LENGTH, type Branding, type LogoSize } from './api'
import { useI18n } from './i18n'
import { LOGO_TYPES, logoThemes, MAX_LOGO_BYTES, prepareLogo, type LogoVariants } from './logoAdapt'
import { PanelLogo } from './PanelLogo'
import { useModalDismiss } from './useModalDismiss'

export const PROJECT_URL = 'https://github.com/mihsergeev/amnezia-control'

const DEFAULT_SIZE: LogoSize = { desktop: 100, mobile: 100 }

export function AboutModal({ version, branding, logoSrc, onChanged, onClose, onUnauthorized }: {
  version: string | null
  branding: Branding | undefined
  logoSrc: string | null | undefined
  onChanged: (branding: Branding) => void
  onClose: () => void
  onUnauthorized: () => void
}) {
  const { t } = useI18n()
  const [section, setSection] = useState<'about' | 'logo'>('about')
  const [draft, setDraft] = useState<LogoVariants | null>(null)
  const [sizeDraft, setSizeDraft] = useState<LogoSize | null>(null)
  const [loginSizeDraft, setLoginSizeDraft] = useState<number | null>(null)
  const [headerTitleDraft, setHeaderTitleDraft] = useState<string | null>(null)
  const [hideHeaderTitleDraft, setHideHeaderTitleDraft] = useState<boolean | null>(null)
  const [tabTitleDraft, setTabTitleDraft] = useState<string | null>(null)
  const [screen, setScreen] = useState<keyof LogoSize | 'login'>(() =>
    window.matchMedia('(max-width: 680px)').matches ? 'mobile' : 'desktop',
  )
  const [busy, setBusy] = useState<'prepare' | 'save' | 'reset' | null>(null)
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')
  const fileInput = useRef<HTMLInputElement>(null)
  const saving = busy === 'save' || busy === 'reset'
  const dismiss = useModalDismiss(() => { if (!saving) onClose() })
  const logoVersion = branding?.version
  const savedSize = branding?.size ?? DEFAULT_SIZE
  const size = sizeDraft ?? savedSize
  const sizeChanged = size.desktop !== savedSize.desktop || size.mobile !== savedSize.mobile
  const savedLoginSize = branding?.login_size ?? 100
  const loginSize = loginSizeDraft ?? savedLoginSize
  const loginSizeChanged = loginSize !== savedLoginSize
  const savedHeaderTitle = branding?.header_title ?? ''
  const headerTitle = headerTitleDraft ?? savedHeaderTitle
  const savedHideHeaderTitle = branding?.hide_header_title ?? false
  const hideHeaderTitle = hideHeaderTitleDraft ?? savedHideHeaderTitle
  const savedTabTitle = branding?.tab_title ?? ''
  const tabTitle = tabTitleDraft ?? savedTabTitle
  const titlesChanged = headerTitle.trim() !== savedHeaderTitle ||
    hideHeaderTitle !== savedHideHeaderTitle || tabTitle.trim() !== savedTabTitle
  const previewTitle = headerTitle.trim() || DEFAULT_PANEL_TITLE
  const scale = screen === 'login' ? loginSize : size[screen]

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

  async function changeBranding(method: 'PUT' | 'DELETE') {
    setBusy(method === 'PUT' ? 'save' : 'reset')
    setMessage('')
    setError('')
    try {
      const next = await api<Branding>('/api/branding', {
        method,
        body: method === 'PUT' ? JSON.stringify({
          ...draft,
          ...(sizeChanged && { size }),
          ...(loginSizeChanged && { login_size: loginSize }),
          ...(headerTitle.trim() !== savedHeaderTitle && { header_title: headerTitle.trim() }),
          ...(hideHeaderTitle !== savedHideHeaderTitle && { hide_header_title: hideHeaderTitle }),
          ...(tabTitle.trim() !== savedTabTitle && { tab_title: tabTitle.trim() }),
        }) : undefined,
      })
      onChanged(next)
      setDraft(null)
      setSizeDraft(null)
      setLoginSizeDraft(null)
      setHeaderTitleDraft(null)
      setHideHeaderTitleDraft(null)
      setTabTitleDraft(null)
      if (fileInput.current) fileInput.current.value = ''
      setMessage(t('Сохранено.'))
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) onUnauthorized()
      else setError(t('Не удалось сохранить оформление.'))
    } finally {
      setBusy(null)
    }
  }

  return (
    <div className="modal-backdrop" onClick={dismiss}>
      <div className="card modal modal-wide about-modal" role="dialog" aria-modal="true" aria-labelledby="about-title">
        <div className="clients-head">
          <h3 id="about-title">{t('О панели Amnezia Control')}</h3>
          <button className="ghost" onClick={onClose} disabled={saving}>{t('Закрыть')}</button>
        </div>
        <div className="about-layout">
          <nav className="about-nav" aria-label={t('О панели')}>
            <button type="button" className="navlink" aria-pressed={section === 'about'} onClick={() => setSection('about')}>
              {t('О панели')}
            </button>
            <div className="about-nav-group">
              <div className="about-nav-label">{t('Оформление')}</div>
              <button type="button" className="navlink" aria-pressed={section === 'logo'} onClick={() => setSection('logo')}>
                {t('Логотип')}
              </button>
            </div>
          </nav>
          <section hidden={section !== 'about'} aria-labelledby="about-summary">
            <h4 id="about-summary">{t('О панели')}</h4>
            <div className="about-brand">
              <PanelLogo className="about-logo" src={logoSrc} />
              <div>
                <strong>Amnezia Control</strong>
                <div className="muted small">{version && `v${version} · `}AGPL-3.0</div>
              </div>
            </div>
            <p>{t('Панель для управления VPN-серверами, каскадами и клиентскими конфигурациями.')}</p>
            <div className="about-links">
              <a href={PROJECT_URL} target="_blank" rel="noreferrer">{t('Исходный код на GitHub')}</a>
              <a href={`${PROJECT_URL}/issues`} target="_blank" rel="noreferrer">{t('Сообщить о проблеме')}</a>
              <a href={`${PROJECT_URL}/blob/main/LICENSE`} target="_blank" rel="noreferrer">{t('Лицензия')}</a>
            </div>
          </section>
          <section hidden={section !== 'logo'} aria-labelledby="about-logo-settings">
            <h4 id="about-logo-settings">{t('Логотип панели')}</h4>
            <p className="muted">{t('Логотип показывается в шапке, на странице входа и во вкладке браузера. Панель подбирает контраст для каждой темы и сохраняет пропорции.')}</p>
            <label className="branding-file">
              {t('Файл логотипа')}
              <input ref={fileInput} type="file" accept={LOGO_TYPES} onChange={selectFile} disabled={Boolean(busy)} />
              <span className="muted small">{t('PNG, JPEG, WebP или SVG, до 5 МБ')}</span>
            </label>
            <div className="branding-titles">
              <label className="field">
                <span>{t('Подпись рядом с логотипом')}</span>
                <input
                  type="text"
                  dir="auto"
                  value={headerTitle}
                  placeholder={DEFAULT_PANEL_TITLE}
                  maxLength={MAX_BRANDING_TITLE_LENGTH}
                  onChange={(event) => setHeaderTitleDraft(event.currentTarget.value)}
                  disabled={hideHeaderTitle || Boolean(busy) || !branding}
                />
              </label>
              <label className="branding-hide-title">
                <input
                  type="checkbox"
                  checked={hideHeaderTitle}
                  onChange={(event) => setHideHeaderTitleDraft(event.currentTarget.checked)}
                  disabled={Boolean(busy) || !branding}
                />
                {t('Скрыть подпись')}
              </label>
              <label className="field">
                <span>{t('Название вкладки браузера')}</span>
                <input
                  type="text"
                  dir="auto"
                  value={tabTitle}
                  placeholder={DEFAULT_PANEL_TITLE}
                  maxLength={MAX_BRANDING_TITLE_LENGTH}
                  onChange={(event) => setTabTitleDraft(event.currentTarget.value)}
                  disabled={Boolean(busy) || !branding}
                />
              </label>
              <p className="muted small">{t('Пустое поле использует стандартное название. На телефоне в шапке виден только логотип.')}</p>
            </div>
            <div className="branding-size">
              <div className="branding-screens" role="group" aria-label={t('Предпросмотр логотипа')}>
                <button type="button" className="ghost" aria-pressed={screen === 'desktop'} onClick={() => setScreen('desktop')}>
                  {t('Компьютер')}
                </button>
                <button type="button" className="ghost" aria-pressed={screen === 'mobile'} onClick={() => setScreen('mobile')}>
                  {t('Телефон')}
                </button>
                <button type="button" className="ghost" aria-pressed={screen === 'login'} onClick={() => setScreen('login')}>
                  {t('Страница входа')}
                </button>
              </div>
              <label className="branding-scale">
                <span>{screen === 'login' ? t('Размер логотипа на странице входа') : t('Размер логотипа в шапке')}</span>
                <span className="muted" aria-hidden="true">{scale}%</span>
                <input
                  type="range"
                  min={60}
                  max={screen === 'mobile' ? 130 : 140}
                  value={scale}
                  aria-valuetext={`${scale}%`}
                  onChange={(event) => {
                    const value = event.currentTarget.valueAsNumber
                    if (screen === 'login') setLoginSizeDraft(value)
                    else setSizeDraft({ ...size, [screen]: value })
                  }}
                  disabled={Boolean(busy) || !branding}
                />
              </label>
            </div>
            <div className={`branding-previews branding-previews-${screen}`} aria-busy={busy === 'prepare'}>
              {logoThemes.map((theme) => (
                <div className={`branding-preview branding-preview-${theme}`} key={theme}>
                  <span>{theme === 'light' ? t('Светлая тема') : t('Темная тема')}</span>
                  <div className={screen === 'login' ? 'branding-preview-login' : 'brand'}>
                    <PanelLogo
                      className={screen === 'login' ? 'login-logo' : 'brand-logo'}
                      headerSize={screen === 'login' ? undefined : size}
                      loginSize={screen === 'login' ? loginSize : undefined}
                      src={draft ? `data:image/png;base64,${draft[theme]}` : logoVersion ? logoUrl(logoVersion, theme) : logoVersion}
                    />
                    {screen === 'desktop' && !hideHeaderTitle && (
                      <strong className="brand-title" dir="auto" title={previewTitle}>{previewTitle}</strong>
                    )}
                    {screen === 'login' && <strong>{t('Вход в панель')}</strong>}
                  </div>
                </div>
              ))}
            </div>
            {busy === 'prepare' && <p className="muted" role="status">{t('Подготавливаем логотип…')}</p>}
            {error && <p className="form-error" role="alert">{error}</p>}
            {message && <p className="muted" role="status">{message}</p>}
            <div className="modal-actions">
              {(logoVersion || branding?.size || branding?.login_size || savedHeaderTitle || savedHideHeaderTitle || savedTabTitle) && <button className="ghost" onClick={() => void changeBranding('DELETE')} disabled={Boolean(busy)}>
                {t('Вернуть стандартное оформление')}
              </button>}
              <button className="primary" onClick={() => void changeBranding('PUT')} disabled={(!draft && !sizeChanged && !loginSizeChanged && !titlesChanged) || Boolean(busy) || !branding}>
                {t('Сохранить')}
              </button>
            </div>
          </section>
        </div>
      </div>
    </div>
  )
}
