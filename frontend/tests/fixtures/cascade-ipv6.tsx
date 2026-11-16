import React from 'react'
import { createRoot } from 'react-dom/client'
import { CascadeWizard } from '../../src/CascadeWizard'
import { I18nProvider } from '../../src/i18n'
import type { Server } from '../../src/api'
import '../../src/index.css'
import '../../src/App.css'

const servers = [{ id: 1, name: 'Entry', host: '192.0.2.10', country: 'FI', last_check_ok: true },
  { id: 2, name: 'Exit', host: '203.0.113.20', country: 'DE', last_check_ok: true }] as Server[]
createRoot(document.getElementById('root')!).render(
  <I18nProvider><CascadeWizard servers={servers} cascades={[]} defaultUser="panel"
    onClose={() => {}} onRemove={() => {}} onChanged={() => {}}
    onUnauthorized={() => { throw new Error('Unexpected authentication failure') }} /></I18nProvider>,
)
