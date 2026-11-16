import React from 'react'
import { createRoot } from 'react-dom/client'
import { CascadeRoutesModal } from '../../src/CascadeRoutes'
import { I18nProvider } from '../../src/i18n'
import type { Cascade, Server } from '../../src/api'
import '../../src/index.css'
import '../../src/App.css'

const cascade = {
  id: 1, entry_server_id: 1, exit_server_id: 2, transport: 'gre', status: 'ready', error: '',
  entry_ip: '192.0.2.10', exit_ip: '203.0.113.20', entry_country: 'RU',
  entry_country_override: '', desired_entry_country: 'FI', routes: [], result: {}, probe: {},
} as unknown as Cascade
const entry = { id: 1, name: 'Entry', host: '192.0.2.10', country: 'FI' } as Server
const exit = { id: 2, name: 'Exit', host: '203.0.113.20', country: 'DE' } as Server
const close = () => { document.body.dataset.closed = 'yes' }
const saved = (value: Cascade) => { document.body.dataset.savedCountry = value.entry_country }
createRoot(document.getElementById('root')!).render(
  <I18nProvider><CascadeRoutesModal cascade={cascade} entry={entry} exit={exit}
    onClose={close} onSaved={saved} onUnauthorized={() => { throw new Error('Unexpected authentication failure') }} /></I18nProvider>,
)
