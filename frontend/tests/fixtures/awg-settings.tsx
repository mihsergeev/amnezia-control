import { useState } from 'react'
import { createRoot } from 'react-dom/client'
import { AwgSettingsModal } from '../../src/AwgSettings'
import { DeployModal } from '../../src/DeployModal'
import { I18nProvider } from '../../src/i18n'
import '../../src/index.css'
import '../../src/App.css'

export function Fixture() {
  const query = new URLSearchParams(location.search)
  const protocol = query.get('protocol') === 'awg' ? 'awg' : 'awg3'
  const [saved, setSaved] = useState(0)
  return <I18nProvider><output id="saved">{saved}</output>
    {query.get('mode') === 'deploy'
      ? <DeployModal serverId={1} serverName="Synthetic node" protocol={protocol} mode="deploy" onClose={() => {}} onDone={() => setSaved(n => n + 1)} onUnauthorized={() => { throw new Error('Unauthorized') }} />
      : <AwgSettingsModal serverId={1} protocol={protocol} onClose={() => {}} onSaved={() => setSaved(n => n + 1)} onUnauthorized={() => { throw new Error('Unauthorized') }} />}
  </I18nProvider>
}
createRoot(document.getElementById('root')!).render(<Fixture />)
