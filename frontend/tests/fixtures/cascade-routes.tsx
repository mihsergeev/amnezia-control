import { useEffect, useState } from 'react'
import { createRoot } from 'react-dom/client'
import { CascadeRoutesModal } from '../../src/CascadeRoutes'
import { I18nProvider } from '../../src/i18n'
import type { Cascade, Server } from '../../src/api'
import '../../src/index.css'
import '../../src/App.css'
const count = Number(new URLSearchParams(location.search).get('count') || 16)
const seed = (id = 1) => ({ id, entry_server_id: 1, exit_server_id: 2, entry_ip: '192.0.2.10', exit_ip: '198.51.100.20', entry_country: 'RU', routes: Array.from({ length: count }, (_, i) => ({ destination: `r${i + 1}.example.com`, via: i % 2 ? 'exit' : 'entry' })) }) as Cascade
document.documentElement.dataset.theme = localStorage.getItem('acontrol_theme') || 'dark'
export function Fixture() {
  const [cascade, setCascade] = useState(seed)
  const [open, setOpen] = useState(true)
  const [saved, setSaved] = useState(0)
  const [unauthorized, setUnauthorized] = useState(0)
  useEffect(() => {
    const switchCascade = () => setCascade(seed(2))
    window.addEventListener('switch-cascade', switchCascade)
    const switchEndpoint = () => setCascade((prev) => ({ ...seed(prev.id), entry_ip: '203.0.113.10', transport: 'vless' }))
    const pollRoutes = () => setCascade((prev) => ({ ...prev, routes: [{ destination: 'polled.example', via: 'entry' }] }))
    window.addEventListener('switch-endpoint', switchEndpoint)
    window.addEventListener('poll-routes', pollRoutes)
    return () => {
      window.removeEventListener('switch-cascade', switchCascade)
      window.removeEventListener('switch-endpoint', switchEndpoint)
      window.removeEventListener('poll-routes', pollRoutes)
    }
  }, [])
  return <I18nProvider>
    <output data-saved={saved} data-unauthorized={unauthorized} data-cascade={cascade.id} />
    {open && <CascadeRoutesModal cascade={cascade} entry={{ id: 1, name: 'Entry server', host: 'entry.example.com', country: 'RU' } as Server} exit={{ id: 2, name: 'Exit server', host: 'exit.example.com', country: 'FI' } as Server}
      onClose={() => setOpen(false)} onSaved={(next) => { setSaved((n) => n + 1); setCascade(next) }} onUnauthorized={() => setUnauthorized((n) => n + 1)} />}
  </I18nProvider>
}
createRoot(document.getElementById('root')!).render(<Fixture />)
