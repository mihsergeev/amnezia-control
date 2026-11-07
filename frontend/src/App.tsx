import { useCallback, useEffect, useRef, useState } from 'react'
import {
  ApiError,
  api,
  DEFAULT_PANEL_TITLE,
  downloadBackup,
  getToken,
  logoUrl,
  logoutServer,
  panelTabTitle,
  restoreBackup,
  setToken,
  type Branding,
} from './api'
import { LoginPage } from './LoginPage'
import { AboutModal, PROJECT_URL } from './AboutModal'
import { PanelLogo } from './PanelLogo'
import { ServersPage } from './ServersPage'
import { Dashboard } from './Dashboard'
import { ApiKeysPage } from './ApiKeysPage'
import { ClientSearchPage } from './ClientSearchPage'
import { AuditPage } from './AuditPage'
import { Menu } from './Menu'
import { BackupsModal } from './BackupsModal'
import { AlertsModal } from './AlertsModal'
import { ShareServicesModal } from './ShareServicesModal'
import { TwoFAModal } from './TwoFAModal'
import { PasswordModal } from './PasswordModal'
import { StepUpModal } from './StepUpModal'
import { useI18n } from './i18n'
import './App.css'

type View = 'servers' | 'overview' | 'search' | 'audit' | 'apikeys'

function App() {
  const { t, lang, setLang } = useI18n()
  const [authed, setAuthed] = useState(() => getToken() !== null)
  const [view, setView] = useState<View>('servers')
  const [version, setVersion] = useState<string | null>(null)
  // подтверждение паролем перед скачиванием бэкапа или восстановлением
  const [stepUp, setStepUp] = useState<
    { kind: 'backup' } | { kind: 'restore'; file: File } | null
  >(null)
  const [backupsOpen, setBackupsOpen] = useState(false)
  const [alertsOpen, setAlertsOpen] = useState(false)
  const [shareOpen, setShareOpen] = useState(false)
  const [twoFaOpen, setTwoFaOpen] = useState(false)
  const [pwOpen, setPwOpen] = useState(false)
  const [aboutOpen, setAboutOpen] = useState(false)
  // Undefined while loading. A null version uses the standard logo.
  const [branding, setBranding] = useState<Branding>()
  const [theme, setTheme] = useState<'dark' | 'light'>(() =>
    document.documentElement.getAttribute('data-theme') === 'light'
      ? 'light'
      : 'dark',
  )
  const fileRef = useRef<HTMLInputElement>(null)
  const logoVersion = branding?.version
  const logoSrc = logoVersion ? logoUrl(logoVersion, theme) : logoVersion
  const headerTitle = branding && !branding.hide_header_title
    ? branding.header_title || DEFAULT_PANEL_TITLE
    : null
  const tabTitle = branding && panelTabTitle(branding)

  useEffect(() => {
    const controller = new AbortController()
    api<Branding>('/api/branding', { signal: controller.signal })
      .then((next) => {
        if (!controller.signal.aborted) setBranding((current) => current ?? next ?? { version: null })
      })
      .catch(() => {
        if (!controller.signal.aborted) setBranding((current) => current ?? { version: null })
      })
    return () => controller.abort()
  }, [])

  useEffect(() => {
    if (tabTitle !== undefined) document.title = tabTitle
  }, [tabTitle])

  useEffect(() => {
    const icon = document.querySelector<HTMLLinkElement>('link[rel="icon"]')
    if (!icon || logoSrc === undefined) return
    if (logoSrc === null) {
      icon.href = '/favicon.png'
      return
    }

    // Wide and tall logos need transparent padding in the square tab icon.
    const image = new Image()
    image.onload = () => {
      const canvas = document.createElement('canvas')
      canvas.width = canvas.height = 64
      const ctx = canvas.getContext('2d')
      if (!ctx) return
      const scale = 60 / Math.max(image.naturalWidth, image.naturalHeight)
      const width = image.naturalWidth * scale
      const height = image.naturalHeight * scale
      ctx.drawImage(image, (64 - width) / 2, (64 - height) / 2, width, height)
      icon.href = canvas.toDataURL('image/png')
    }
    image.onerror = () => { icon.href = '/favicon.png' }
    image.src = logoSrc
    return () => { image.onload = image.onerror = null }
  }, [logoSrc])

  function toggleTheme() {
    const next = theme === 'dark' ? 'light' : 'dark'
    setTheme(next)
    if (next === 'light') {
      document.documentElement.setAttribute('data-theme', 'light')
    } else {
      document.documentElement.removeAttribute('data-theme')
    }
    localStorage.setItem('acontrol_theme', next)
  }

  async function backup(password: string) {
    try {
      await downloadBackup(password)
      setStepUp(null)
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        logout()
        return
      }
      // неверный пароль и прочее покажет окно подтверждения
      throw new Error(
        t('Не удалось скачать бэкап: {msg}', {
          msg: err instanceof Error ? err.message : t('неизвестно'),
        }),
      )
    }
  }

  async function restore(file: File, password: string) {
    let total: number
    try {
      const r = await restoreBackup(file, password)
      total = Object.values(r.restored).reduce((a, b) => a + b, 0)
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        logout()
        return
      }
      throw new Error(
        t('Ошибка восстановления: {msg}', {
          msg: err instanceof Error ? err.message : t('неизвестно'),
        }),
      )
    }
    setStepUp(null)
    window.alert(t('Восстановлено записей: {n}. Страница перезагрузится.', { n: total }))
    window.location.reload()
  }

  async function onRestoreFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    e.target.value = ''
    if (!file) return
    if (
      !window.confirm(
        t(
          'Восстановить панель из «{name}»?\n\nВСЕ текущие серверы, конфиги, заметки и SSH-ключ панели будут ЗАМЕНЕНЫ данными из архива. Действие необратимо.',
          { name: file.name },
        ),
      )
    )
      return
    setStepUp({ kind: 'restore', file })
  }

  // версию отдает только /api/config после входа: health без авторизации ее
  // больше не показывает
  useEffect(() => {
    if (!authed) {
      setVersion(null)
      return
    }
    api<{ version?: string }>('/api/config')
      .then((body) => setVersion(body?.version || null))
      .catch(() => setVersion(null))
  }, [authed])

  // Локальный выход (токен истек или отозван). Окна закрываем, иначе они
  // оставались висеть поверх формы входа.
  // useCallback: logout уходит детям как onUnauthorized и сидит в зависимостях
  // их загрузок - новая функция на каждую перерисовку (тема, язык) заново
  // запрашивала все открытые списки и обрывала опрос установки
  const logout = useCallback(() => {
    setToken(null)
    setAuthed(false)
    setStepUp(null)
    setBackupsOpen(false)
    setAlertsOpen(false)
    setTwoFaOpen(false)
    setPwOpen(false)
    setShareOpen(false)
    setAboutOpen(false)
  }, [])

  // Выход по кнопке: токен отзывается и на сервере
  async function logoutClick() {
    await logoutServer()
    logout()
  }

  return (
    <main className="page">
      <header className="header">
        {/* на экране входа лого уже есть в карточке — в шапке не дублируем */}
        {authed && (
          <a className="brand" href="/" aria-label={t('На главную')}>
            <PanelLogo src={logoSrc} className="brand-logo" headerSize={branding?.size} />
            {headerTitle && <h1 className="brand-title" dir="auto" title={headerTitle}>{headerTitle}</h1>}
          </a>
        )}
        {authed && (
          <nav className="topnav">
            <button
              className={view === 'servers' ? 'navlink navlink-active' : 'navlink'}
              onClick={() => setView('servers')}
            >
              {t('Серверы')}
            </button>
            <button
              className={view === 'overview' ? 'navlink navlink-active' : 'navlink'}
              onClick={() => setView('overview')}
            >
              {t('Обзор')}
            </button>
            <button
              className={view === 'search' ? 'navlink navlink-active' : 'navlink'}
              onClick={() => setView('search')}
            >
              {t('Поиск')}
            </button>
            <button
              className={view === 'audit' ? 'navlink navlink-active' : 'navlink'}
              onClick={() => setView('audit')}
            >
              {t('Журнал')}
            </button>
            <button
              className={view === 'apikeys' ? 'navlink navlink-active' : 'navlink'}
              onClick={() => setView('apikeys')}
            >
              {t('API-ключи')}
            </button>
          </nav>
        )}
        <span className="header-right">
          {version && (
            <a
              className="muted source-link"
              href={PROJECT_URL}
              target="_blank"
              rel="noopener noreferrer"
              title={t('Исходный код (AGPL-3.0)')}
            >
              v{version}
            </a>
          )}
          <button
            className="ghost icon-btn"
            onClick={toggleTheme}
            title={t('Тема')}
          >
            {theme === 'dark' ? '☀' : '☾'}
          </button>
          <button
            className="ghost icon-btn"
            onClick={() => setLang(lang === 'ru' ? 'en' : 'ru')}
            title={t('Язык')}
          >
            {lang === 'ru' ? 'EN' : 'RU'}
          </button>
          {authed && (
            <>
              <input
                ref={fileRef}
                type="file"
                accept=".gz,.tar.gz,application/gzip"
                style={{ display: 'none' }}
                onChange={onRestoreFile}
              />
              <Menu
                className="ghost icon-btn"
                caret={false}
                title={t('Меню')}
                label={<span className="menu-gear">⚙</span>}
                items={[
                  { label: t('О панели'), onClick: () => setAboutOpen(true) },
                  { label: t('Алерты'), onClick: () => setAlertsOpen(true) },
                  { label: t('Ссылки на конфиги'), onClick: () => setShareOpen(true) },
                  {
                    label: t('Двухфакторная аутентификация'),
                    onClick: () => setTwoFaOpen(true),
                  },
                  { label: t('Сменить пароль'), onClick: () => setPwOpen(true) },
                  { divider: true },
                  {
                    label: t('Скачать бэкап'),
                    onClick: () => setStepUp({ kind: 'backup' }),
                  },
                  { label: t('Авто-бэкапы…'), onClick: () => setBackupsOpen(true) },
                  {
                    label: t('Восстановить из файла…'),
                    onClick: () => fileRef.current?.click(),
                  },
                  { divider: true },
                  { label: t('Выйти'), danger: true, onClick: logoutClick },
                ]}
              />
            </>
          )}
        </span>
      </header>

      {authed ? (
        view === 'overview' ? (
          <Dashboard onUnauthorized={logout} />
        ) : view === 'search' ? (
          <ClientSearchPage onUnauthorized={logout} />
        ) : view === 'audit' ? (
          <AuditPage onUnauthorized={logout} />
        ) : view === 'apikeys' ? (
          <ApiKeysPage onUnauthorized={logout} />
        ) : (
          <ServersPage onUnauthorized={logout} />
        )
      ) : (
        <LoginPage logoSrc={logoSrc} logoSize={branding?.login_size} onLogin={() => setAuthed(true)} />
      )}

      {aboutOpen && (
        <AboutModal
          version={version}
          branding={branding}
          logoSrc={logoSrc}
          onChanged={setBranding}
          onClose={() => setAboutOpen(false)}
          onUnauthorized={logout}
        />
      )}
      {backupsOpen && (
        <BackupsModal
          onClose={() => setBackupsOpen(false)}
          onUnauthorized={logout}
        />
      )}

      {alertsOpen && (
        <AlertsModal
          onClose={() => setAlertsOpen(false)}
          onUnauthorized={logout}
        />
      )}

      {shareOpen && (
        <ShareServicesModal
          onClose={() => setShareOpen(false)}
          onUnauthorized={logout}
        />
      )}

      {twoFaOpen && (
        <TwoFAModal
          onClose={() => setTwoFaOpen(false)}
          onUnauthorized={logout}
        />
      )}

      {stepUp && (
        <StepUpModal
          text={
            stepUp.kind === 'backup'
              ? t('В бэкапе SSH-ключ панели ко всем нодам, секрет 2FA и ключи клиентов. Введите пароль от панели, чтобы скачать его.')
              : t('Восстановление заменит все данные панели, включая учетную запись администратора. Введите пароль от панели, чтобы продолжить.')
          }
          onSubmit={(pw) =>
            stepUp.kind === 'backup' ? backup(pw) : restore(stepUp.file, pw)
          }
          onCancel={() => setStepUp(null)}
        />
      )}

      {pwOpen && (
        <PasswordModal onClose={() => setPwOpen(false)} onUnauthorized={logout} />
      )}
    </main>
  )
}

export default App
