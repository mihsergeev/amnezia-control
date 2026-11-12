import { useState } from 'react'
import { createRoot } from 'react-dom/client'
import { ClientsModal } from '../../src/ClientsModal'
import { I18nProvider } from '../../src/i18n'
import type { Server, Protocol } from '../../src/api'
import '../../src/index.css'
import '../../src/App.css'

const protocols = [
  ['awg', 'AmneziaWG 2.0'], ['awg3', 'AmneziaWG 3.1'], ['awglegacy', 'AmneziaWG Legacy'],
  ['wireguard', 'WireGuard'], ['xray', 'Xray'], ['openvpn', 'OpenVPN + Cloak'], ['openvpn-native', 'OpenVPN'],
].map(([key, label]) => ({ key, label })) as Protocol[]
const server = { id: 1, name: 'Test server', group_name: '', host: '192.0.2.1' } as Server
const initial = new URLSearchParams(location.search).get('protocol') as Protocol['key'] || 'awg'
export function Fixture() {
  const [serverId, setServerId] = useState(1)
  return <I18nProvider>
    {new URLSearchParams(location.search).has('controls') && <button style={{ position: 'fixed', zIndex: 9999, top: 0 }}
      onClick={() => setServerId(2)}>Switch test server</button>}
    <ClientsModal server={{ ...server, id: serverId }} protocols={protocols} initialProtocol={initial}
      onClose={() => {}} onUnauthorized={() => { throw new Error('Unexpected unauthorized response') }} />
  </I18nProvider>
}
createRoot(document.getElementById('root')!).render(<Fixture />)
