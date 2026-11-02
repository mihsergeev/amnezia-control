import type { CascadeEncryption, CascadeTransport } from './api'

export const DEFAULT_CASCADE_TRANSPORT: CascadeTransport = 'awg'

// Blank means auto. Invalid numeric syntax must not silently turn into auto.
export function cascadePort(value: string): number | null | undefined {
  const text = value.trim()
  if (!text) return null
  if (!/^\d+$/.test(text)) return undefined
  const port = Number(text)
  return Number.isInteger(port) && port >= 1 && port <= 65535 ? port : undefined
}

export function cascadeSecurityState(value: { encrypted?: boolean | null; encryption?: CascadeEncryption }): 'confirmed' | 'plain' | 'unknown' {
  if (value.encrypted === true && (value.encryption === 'awg' || value.encryption === 'reality')) return 'confirmed'
  return value.encrypted === false && value.encryption === 'none' ? 'plain' : 'unknown'
}

export function cascadeTransportLabel(transport: CascadeTransport): string {
  return transport === 'awg' ? 'AWG 3.1' : transport === 'gre' ? 'GRE' : 'VLESS'
}
