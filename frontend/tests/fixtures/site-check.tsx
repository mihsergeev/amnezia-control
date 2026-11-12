import { useEffect, useState } from 'react'
import { createRoot } from 'react-dom/client'
import { SiteCheckModal } from '../../src/SiteCheck'
import { ServersPage } from '../../src/ServersPage'
import { I18nProvider } from '../../src/i18n'
import type { Server } from '../../src/api'
import '../../src/index.css'
import '../../src/App.css'
document.documentElement.dataset.theme = localStorage.getItem('acontrol_theme') || 'dark'
const seed = { id: 1, name: 'Test server', host: '192.0.2.10', country: 'RU', ssh_port: 22, ssh_user: 'service' } as Server
export function Fixture() {
  const [server, setServer] = useState(seed)
  const [open, setOpen] = useState(true)
  const [unauthorized, setUnauthorized] = useState(0)
  useEffect(() => {
    const switchServer = () => setServer({ ...seed, id: 2, name: 'Other server', host: '198.51.100.20' })
    const migrate = () => setServer((prev) => ({ ...prev, host: '203.0.113.30', ssh_port: 2222 }))
    const poll = () => setServer((prev) => ({ ...prev, last_check_ok: true, last_check_at: new Date().toISOString() }))
    window.addEventListener('switch-server', switchServer)
    window.addEventListener('migrate-server', migrate)
    window.addEventListener('poll-server', poll)
    return () => { window.removeEventListener('switch-server', switchServer); window.removeEventListener('migrate-server', migrate); window.removeEventListener('poll-server', poll) }
  }, [])
  return <I18nProvider><output data-unauthorized={unauthorized} />
    {new URLSearchParams(location.search).has('page') ? <ServersPage onUnauthorized={() => setUnauthorized((n) => n + 1)} /> : open && <SiteCheckModal server={server} onClose={() => setOpen(false)} onUnauthorized={() => setUnauthorized((n) => n + 1)} />}
  </I18nProvider>
}
createRoot(document.getElementById('root')!).render(<Fixture />)
