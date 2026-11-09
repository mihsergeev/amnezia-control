import type { Cascade, CascadeEncryption, CascadeImageTransport, CascadeRoute, CascadeTransport, CascadeTransportProbe, Server } from './api'

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

export function latestCascadeHealth({ health, manual_check }: Cascade['result']) {
  const time = (value: typeof health) => {
    const at = Date.parse(value?.checked_at ?? '')
    return Number.isFinite(at) ? at : -Infinity
  }
  const automatic = time(health)
  const manual = time(manual_check)
  if (manual === -Infinity && automatic === -Infinity) return undefined
  return manual >= automatic ? manual_check : health
}

export function cascadeLocalRoute(result: { ru?: string; direct?: string; egress?: string }): 'entry' | 'exit' | 'unknown' {
  const { ru, direct, egress } = result
  if (!ru || !direct || !egress || direct === egress) return 'unknown'
  if (ru === direct) return 'entry'
  return ru === egress ? 'exit' : 'unknown'
}

export function cascadeEntryCountry(cascade: Pick<Cascade, 'entry_country'>, entry?: Pick<Server, 'country'> | null): string {
  return (cascade.entry_country || entry?.country || '').toUpperCase()
}

export function cascadeLocalExpected(routes: CascadeRoute[] = []): CascadeRoute['via'] {
  const host = 'ip.nic.ru'
  // Saved domain rules use Xray's domain: matcher in their original order.
  return routes.find(({ destination }) => host === destination || host.endsWith(`.${destination}`))?.via ?? 'entry'
}

export function cascadeRequestId(): string {
  // Web Crypto's randomUUID is unavailable on panels served over plain HTTP.
  const bytes = crypto.getRandomValues(new Uint8Array(16))
  bytes[6] = (bytes[6] & 0x0f) | 0x40
  bytes[8] = (bytes[8] & 0x3f) | 0x80
  const hex = Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('')
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`
}

export function cascadeClientExitConfirmed({ client, direct, egress }: { client?: string; direct?: string; egress?: string }): boolean {
  return Boolean(direct && egress && direct !== egress && client === egress)
}

export function cascadeTransportLabel(transport: CascadeTransport): string {
  return transport === 'awg' ? 'AWG 3.1' : transport === 'gre' ? 'GRE' : 'VLESS'
}

export function formatProbeMetric(value: number, lang: string, kind: 'secs' | 'mbps'): string {
  const floor = kind === 'secs' ? 0.001 : 0.1
  const format = new Intl.NumberFormat(lang, kind === 'secs' ? { maximumFractionDigits: 3 } : { maximumSignificantDigits: 3 })
  return value > 0 && value < floor ? '<' + format.format(floor) : format.format(value)
}

export const PROBE_TRANSPORTS = ['awg', 'vless', 'gre'] as const
export type TransportProbeRow = {
  state: 'queued' | 'running' | 'preparing' | 'done' | 'error' | 'unavailable'
  result: CascadeTransportProbe | null
  error: string
}
export type TransportProbeRows = Record<CascadeTransport, TransportProbeRow>

export function queuedProbeRows(): TransportProbeRows {
  return Object.fromEntries(PROBE_TRANSPORTS.map(k => [k, { state: 'queued', result: null, error: '' }])) as TransportProbeRows
}

export function probeRowTone(row: TransportProbeRow): 'ok' | 'bad' | 'run' | 'muted' {
  if (row.state === 'running' || row.state === 'preparing') return 'run'
  if (row.state === 'unavailable' || row.state === 'queued') return 'muted'
  if (row.state === 'error') return 'bad'
  return row.result?.status === 'ok' && row.result.ok === true ? 'ok' : 'bad'
}

// Each response is committed before the next request starts. Aborted requests
// cannot publish a late response or start another transport.
export async function runTransportProbes(
  request: (transport: CascadeTransport, signal: AbortSignal) => Promise<CascadeTransportProbe>,
  update: (transport: CascadeTransport, row: TransportProbeRow) => void,
  signal: AbortSignal,
  errorText: (error: unknown) => string,
  prepareTransport?: CascadeImageTransport,
): Promise<void> {
  for (const transport of prepareTransport ? [prepareTransport] : PROBE_TRANSPORTS) {
    if (signal.aborted) return
    update(transport, { state: prepareTransport ? 'preparing' : 'running', result: null, error: '' })
    try {
      const result = await request(transport, signal)
      if (signal.aborted) return
      if (result.transport !== transport || result.measurement !== transport) {
        update(transport, { state: 'error', result: null, error: errorText(null) })
      } else {
        update(transport, { state: result.status === 'unavailable' ? 'unavailable' : 'done', result, error: '' })
      }
    } catch (error) {
      if (signal.aborted) return
      update(transport, { state: 'error', result: null, error: errorText(error) })
    }
  }
}

export function testedAwgPorts(
  requested: { entry_port: number | null; exit_port: number | null },
  result: CascadeTransportProbe | null,
): { entry_port: number | null; exit_port: number | null } {
  const valid = (port: number | null | undefined) => port != null && Number.isInteger(port) && port >= 1 && port <= 65535 ? port : null
  const measured = result?.transport === 'awg' && result.measurement === 'awg' && result.status === 'ok' && result.ok === true
  return {
    entry_port: requested.entry_port ?? (measured ? valid(result.entry_port) : null),
    exit_port: requested.exit_port ?? (measured ? valid(result.exit_port) : null),
  }
}

export function cascadeMeasurement(cascade: Pick<Cascade, 'transport' | 'probe'>): { label: string; mbps: number } | null {
  const measured = cascade.probe[cascade.transport]
  if (measured && 'measurement' in measured) {
    return measured.measurement === cascade.transport && measured.ok === true && measured.mbps != null
      ? { label: cascadeTransportLabel(cascade.transport), mbps: measured.mbps } : null
  }
  const legacy = cascade.transport === 'vless' ? cascade.probe.tcp : cascade.transport === 'gre' ? cascade.probe.gre : null
  return legacy?.ok && legacy.mbps != null ? { label: cascade.transport === 'vless' ? 'TCP' : 'GRE', mbps: legacy.mbps } : null
}
