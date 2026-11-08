import type { Cascade, CheckInfo, Server, ServerStat } from './api'
import { cascadeEntryCountry } from './cascadeUi.ts'

export type ServerRouteNode = { name: string; host: string; country: string }
export type ServerListRoute = { entry: ServerRouteNode; exit: ServerRouteNode; manual: boolean }

function checkedInfo(server?: Server): CheckInfo | null {
  try {
    const value: unknown = JSON.parse(server?.last_check_info || 'null')
    return value && typeof value === 'object' && !Array.isArray(value) ? value as CheckInfo : null
  } catch { return null }
}

// Descriptive suffixes give up space before the actual hostname. Keep the full
// original name for tooltips, search and accessibility, without editing data.
export function cascadeNameParts(name: string): { primary: string; suffix: string } {
  const match = /^([a-z\d][a-z\d._-]*)(\s+(?:[-–—]\s+|\().*)$/i.exec(name)
  return match && /[.-]/.test(match[1])
    ? { primary: match[1], suffix: match[2] }
    : { primary: name, suffix: '' }
}

// An unchanged alias must not accompany an unrelated address edit: aliases are
// bound to the configured endpoint and the backend invalidates them on host change.
export function manualExitNameChange(value: string | null | undefined, original: string): string | undefined {
  const name = value?.trim() || ''
  return name === original.trim() ? undefined : name
}

export function serverListRoute(item: ServerListItem, servers: Server[]): ServerListRoute | null {
  const c = item.cascade
  const node = (server: Server | undefined, host: string): ServerRouteNode => ({ name: server?.name || host, host: server?.host || host, country: server?.country || '' })
  if (c) return { entry: { ...node(item.entry, c.entry_ip), country: cascadeEntryCountry(c, item.entry) }, exit: node(item.exit, c.exit_ip), manual: false }
  if (item.sharedExitCount > 1) return null
  const entry = item.anchor
  if (!entry) return null
  const info = checkedInfo(entry)
  const manual = info?.manual_cascade
  const peer = typeof manual?.exit_host === 'string' ? manual.exit_host.trim() : ''
  const gre = Array.isArray(info?.tunnels) && info.tunnels.some(t => t && t.kind === 'gre')
  const abroad = !!entry.egress_ip && !!entry.egress_country && !!entry.country && entry.egress_country !== entry.country
  if (!peer && !gre && !abroad) return null
  const host = peer || entry.egress_ip
  if (!host) return null
  const exit = servers.find(s => s.id !== entry.id && s.host.toLowerCase() === host.toLowerCase())
  return { entry: node(entry, entry.host), exit: {
    name: exit?.name || (typeof manual?.exit_name === 'string' && manual.exit_name.trim()) || host,
    host, country: exit?.country || (typeof manual?.exit_country === 'string' ? manual.exit_country : '') || (!peer || host === entry.egress_ip ? entry.egress_country : ''),
  }, manual: true }
}

export function greLinkLabel(server?: Server): string {
  const link = checkedInfo(server)?.cascade_link
  return link?.transport === 'awg' && link.encrypted === true ? 'GRE + AWG' : 'GRE'
}

export type ServerListItem = {
  key: string
  anchor?: Server
  cascade?: Cascade
  entry?: Server
  exit?: Server
  members: Server[]
  countedMembers: Server[]
  sharedExitCount: number
  group_name: string
  position: number
}

export type ServerSelection = { key: string | null; serverId: number | null }

export function serverListItems(servers: Server[], cascades: Cascade[]): ServerListItem[] {
  const byId = new Map(servers.map((server) => [server.id, server]))
  const participants = new Set(cascades.flatMap((cascade) => [cascade.entry_server_id, cascade.exit_server_id]))
  const entryIds = new Set(cascades.map(c => c.entry_server_id))
  const exitUses = new Map<number, number>()
  for (const c of cascades) exitUses.set(c.exit_server_id, (exitUses.get(c.exit_server_id) ?? 0) + 1)
  const sharedExits = new Set([...exitUses].filter(([id, count]) => count > 1 && !entryIds.has(id)).map(([id]) => id))
  const items: ServerListItem[] = cascades.map((cascade) => {
    const entry = byId.get(cascade.entry_server_id)
    const exit = byId.get(cascade.exit_server_id)
    const anchor = entry ?? exit
    return {
      key: `cascade:${cascade.id}`, cascade, entry, exit, anchor,
      members: [...new Set([entry, exit].filter((server): server is Server => !!server))],
      countedMembers: [entry, ...(sharedExits.has(cascade.exit_server_id) ? [] : [exit])].filter((server): server is Server => !!server),
      sharedExitCount: 0,
      group_name: anchor?.group_name ?? '',
      position: anchor?.position ?? Number.MAX_SAFE_INTEGER,
    }
  })
  for (const server of servers) {
    if (!participants.has(server.id) || sharedExits.has(server.id)) {
      items.push({ key: `server:${server.id}`, anchor: server, members: [server],
        countedMembers: [server], sharedExitCount: sharedExits.has(server.id) ? exitUses.get(server.id)! : 0,
        group_name: server.group_name, position: server.position })
    }
  }
  return items.sort((a, b) => a.position - b.position || (a.anchor?.id ?? Infinity) - (b.anchor?.id ?? Infinity) || a.key.localeCompare(b.key))
}

export function groupServerList(items: ServerListItem[]) {
  const grouped = new Map<string, ServerListItem[]>()
  for (const item of items) grouped.set(item.group_name, [...(grouped.get(item.group_name) ?? []), item])
  const names = [...grouped.keys()].filter(Boolean)
  if (grouped.has('')) names.push('')
  return names.map((name) => ({ name, items: grouped.get(name)! }))
}

export function serverListMembers(items: ServerListItem[]): Server[] {
  return [...new Map(items.flatMap((item) => item.members).map((server) => [server.id, server])).values()]
}

// A server position belongs to the server, so a shared anchor cannot have two
// independent drag positions. Persist each anchor once and keep all node records.
export function serverListAnchors(items: ServerListItem[]): Server[] {
  return [...new Map(items.flatMap((item) => item.anchor ? [[item.anchor.id, item.anchor] as const] : [])).values()]
}

export function serverListProblem(item: ServerListItem, problem: (server: Server) => boolean): boolean {
  if (item.cascade && (item.cascade.status !== 'ready' || !item.entry || !item.exit || item.cascade.result.health?.ok === false)) return true
  return item.members.some(problem)
}

export function serverListMatches(item: ServerListItem, query: string, text: (server: Server) => string, servers: Server[] = []): boolean {
  const cascade = item.cascade
  const route = serverListRoute(item, servers)
  return [cascade?.entry_ip, cascade?.exit_ip, cascade?.transport, route?.exit.name, route?.exit.host, ...item.members.map(text)]
    .join(' ').toLowerCase().includes(query.trim().toLowerCase())
}

export function serverListClients(items: ServerListItem[], stats: Record<number, ServerStat>) {
  const counted = [...new Map(items.flatMap(item => item.countedMembers.map(server => [server.id, server] as const))).values()]
  const rows = counted.flatMap((server) => stats[server.id] ? [stats[server.id]] : [])
  return { available: rows.length > 0, online: rows.reduce((sum, row) => sum + row.clients_online, 0),
    total: rows.reduce((sum, row) => sum + row.clients_total, 0) }
}

export function cascadeServerEligible(server: Server, cascades: Cascade[], role: 'entry' | 'exit'): boolean {
  if (cascades.some(c => c.entry_server_id === server.id)) return false
  if (role === 'exit') return true
  if (cascades.some(c => c.exit_server_id === server.id)) return false
  const info = checkedInfo(server)
  const manual = typeof info?.manual_cascade?.exit_host === 'string' && !!info.manual_cascade.exit_host.trim()
  const gre = Array.isArray(info?.tunnels) && info.tunnels.some(t => t.kind === 'gre')
  const abroad = !!server.egress_ip && !!server.egress_country && !!server.country && server.egress_country !== server.country
  return !manual && !gre && !abroad
}

export function resolveServerSelection(items: ServerListItem[], selection: ServerSelection) {
  const item = items.find((row) => row.key === selection.key)
    ?? items.find((row) => row.members.some((server) => server.id === selection.serverId))
    ?? items[0]
  const server = item?.members.find((node) => node.id === selection.serverId) ?? item?.anchor
  return { item, server }
}

function positiveId(value: string | null): number | null {
  return value && /^\d+$/.test(value) && Number.isSafeInteger(Number(value)) && Number(value) > 0 ? Number(value) : null
}

export function serverSelectionFromParams(params: URLSearchParams): ServerSelection {
  const serverId = positiveId(params.get('server'))
  const cascadeId = positiveId(params.get('cascade'))
  return { key: cascadeId ? `cascade:${cascadeId}` : serverId ? `server:${serverId}` : null, serverId }
}

export function serverSelectionFromHistory(params: URLSearchParams, state: unknown): ServerSelection {
  const fromUrl = serverSelectionFromParams(params)
  if (fromUrl.key || fromUrl.serverId) return fromUrl
  if (!state || typeof state !== 'object' || !('acontrolServerSelection' in state)) return fromUrl
  const saved = state.acontrolServerSelection
  if (!saved || typeof saved !== 'object' || !('key' in saved) || !('serverId' in saved)) return fromUrl
  const key = typeof saved.key === 'string' && /^(server|cascade):[1-9]\d*$/.test(saved.key) ? saved.key : null
  const serverId = typeof saved.serverId === 'number' ? positiveId(String(saved.serverId)) : null
  return { key, serverId }
}

export function serverSelectionParams(params: URLSearchParams, item: ServerListItem, server?: Server) {
  const next = new URLSearchParams(params)
  if (server) next.set('server', String(server.id))
  else next.delete('server')
  if (item.cascade) next.set('cascade', String(item.cascade.id))
  else next.delete('cascade')
  return next
}
