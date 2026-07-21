import { useEffect, useRef, useState } from 'react'
import { ApiError, downloadBackup, getToken, restoreBackup, setToken } from './api'
import { LoginPage } from './LoginPage'
import { ServersPage } from './ServersPage'
import { Dashboard } from './Dashboard'
import { ApiKeysPage } from './ApiKeysPage'
import { AuditPage } from './AuditPage'
import { Menu } from './Menu'
import { BackupsModal } from './BackupsModal'
import { AlertsModal } from './AlertsModal'
import { TwoFAModal } from './TwoFAModal'
import { PasswordModal } from './PasswordModal'
import { useI18n } from './i18n'
import './App.css'

type View = 'servers' | 'overview' | 'audit' | 'apikeys'

function App() {
  const { t, lang, setLang } = useI18n()
  const [authed, setAuthed] = useState(() => getToken() !== null)
  const [view, setView] = useState<View>('servers')
  const [version, setVersion] = useState<string | null>(null)
  const [backingUp, setBackingUp] = useState(false)
  const [backupsOpen, setBackupsOpen] = useState(false)
  const [alertsOpen, setAlertsOpen] = useState(false)
  const [twoFaOpen, setTwoFaOpen] = useState(false)
  const [pwOpen, setPwOpen] = useState(false)
  const [theme, setTheme] = useState<'dark' | 'light'>(() =>
    document.documentElement.getAttribute('data-theme') === 'light'
      ? 'light'
      : 'dark',
  )
  const fileRef = useRef<HTMLInputElement>(null)

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

  async function backup() {
    setBackingUp(true)
    try {
      await downloadBackup()
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        logout()
      } else {
        window.alert(
          t('Не удалось скачать бэкап: {msg}', {
            msg: err instanceof Error ? err.message : t('неизвестно'),
          }),
        )
      }
    } finally {
      setBackingUp(false)
    }
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
    try {
      const r = await restoreBackup(file)
      const total = Object.values(r.restored).reduce((a, b) => a + b, 0)
      window.alert(
        t('Восстановлено записей: {n}. Страница перезагрузится.', { n: total }),
      )
      window.location.reload()
    } catch (err) {
      window.alert(
        t('Ошибка восстановления: {msg}', {
          msg: err instanceof Error ? err.message : t('неизвестно'),
        }),
      )
    }
  }

  useEffect(() => {
    fetch('/api/health')
      .then((res) => (res.ok ? res.json() : null))
      .then((body) => setVersion(body?.version ?? null))
      .catch(() => setVersion(null))
  }, [])

  function logout() {
    setToken(null)
    setAuthed(false)
  }

  return (
    <main className="page">
      <header className="header">
        {/* на экране входа лого уже есть в карточке — в шапке не дублируем */}
        {authed && (
          <a className="brand" href="/" title={t('На главную')}>
            <img src="/logo.png" className="brand-logo" alt="" />
            <h1>Amnezia Control</h1>
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
              href="https://github.com/mihsergeev/amnezia-control"
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
                  { label: t('Алерты'), onClick: () => setAlertsOpen(true) },
                  {
                    label: t('Двухфакторная аутентификация'),
                    onClick: () => setTwoFaOpen(true),
                  },
                  { label: t('Сменить пароль'), onClick: () => setPwOpen(true) },
                  { divider: true },
                  {
                    label: backingUp ? t('Бэкап…') : t('Скачать бэкап'),
                    onClick: backup,
                  },
                  { label: t('Авто-бэкапы…'), onClick: () => setBackupsOpen(true) },
                  {
                    label: t('Восстановить из файла…'),
                    onClick: () => fileRef.current?.click(),
                  },
                  { divider: true },
                  { label: t('Выйти'), danger: true, onClick: logout },
                ]}
              />
            </>
          )}
        </span>
      </header>

      {authed ? (
        view === 'overview' ? (
          <Dashboard onUnauthorized={logout} />
        ) : view === 'audit' ? (
          <AuditPage onUnauthorized={logout} />
        ) : view === 'apikeys' ? (
          <ApiKeysPage onUnauthorized={logout} />
        ) : (
          <ServersPage onUnauthorized={logout} />
        )
      ) : (
        <LoginPage onLogin={() => setAuthed(true)} />
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

      {twoFaOpen && (
        <TwoFAModal
          onClose={() => setTwoFaOpen(false)}
          onUnauthorized={logout}
        />
      )}

      {pwOpen && (
        <PasswordModal onClose={() => setPwOpen(false)} onUnauthorized={logout} />
      )}
    </main>
  )
}

export default App
