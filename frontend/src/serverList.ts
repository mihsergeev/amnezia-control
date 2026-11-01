import type { Cascade, Server, ServerStat } from './api'

export type ServerListItem = {
  key: string
  anchor?: Server
  cascade?: Cascade
  entry?: Server
  exit?: Server
  members: Server[]
  group_name: string
  position: number
}

export type ServerSelection = { key: string | null; serverId: number | null }

export function serverListItems(servers: Server[], cascades: Cascade[]): ServerListItem[] {
  const byId = new Map(servers.map((server) => [server.id, server]))
  const participants = new Set(cascades.flatMap((cascade) => [cascade.entry_server_id, cascade.exit_server_id]))
  const items: ServerListItem[] = cascades.map((cascade) => {
    const entry = byId.get(cascade.entry_server_id)
    const exit = byId.get(cascade.exit_server_id)
    const anchor = entry ?? exit
    return {
      key: `cascade:${cascade.id}`, cascade, entry, exit, anchor,
      members: [...new Set([entry, exit].filter((server): server is Server => !!server))],
      group_name: anchor?.group_name ?? '',
      position: anchor?.position ?? Number.MAX_SAFE_INTEGER,
    }
  })
  for (const server of servers) {
    if (!participants.has(server.id)) {
      items.push({ key: `server:${server.id}`, anchor: server, members: [server],
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

export function serverListMatches(item: ServerListItem, query: string, text: (server: Server) => string): boolean {
  const cascade = item.cascade
  return [cascade?.entry_ip, cascade?.exit_ip, cascade?.transport, ...item.members.map(text)]
    .join(' ').toLowerCase().includes(query.trim().toLowerCase())
}

export function serverListClients(items: ServerListItem[], stats: Record<number, ServerStat>) {
  const rows = serverListMembers(items).flatMap((server) => stats[server.id] ? [stats[server.id]] : [])
  return { available: rows.length > 0, online: rows.reduce((sum, row) => sum + row.clients_online, 0),
    total: rows.reduce((sum, row) => sum + row.clients_total, 0) }
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
