export type ClientMetadata = { group_name?: string; device_name?: string }
export type PersonClient = ClientMetadata & { id: string; name: string }

/** Группы меняют только порядок строк. Идентификаторы/ключи остаются у клиента. */
export function groupClients<T extends ClientMetadata>(clients: readonly T[], enabled: boolean): T[] {
  if (!enabled) return [...clients]
  // Точное имя группы: регистр сохраняет различие явно введенных имен.
  const groups = new Map<string, T[]>()
  for (const client of clients) {
    const key = client.group_name?.trim() ?? ''
    const rows = groups.get(key) ?? []
    rows.push(client)
    groups.set(key, rows)
  }
  return [...groups.entries()]
    .sort(([a], [b]) => !a ? 1 : !b ? -1 : a.localeCompare(b, 'ru'))
    .flatMap(([, rows]) => rows)
}

export function clientGroupNames(clients: readonly ClientMetadata[]): string[] {
  return [...new Set(clients.map((client) => client.group_name ?? '').filter(Boolean))]
    .sort((a, b) => a.localeCompare(b, 'ru'))
}

// The displayed count uses the same filter as selection; total uses the full list.
export function clientGroupHeader<T extends ClientMetadata>(rows: readonly T[], index: number, all: readonly T[]) {
  const name = rows[index]?.group_name ?? ''
  if (index > 0 && (rows[index - 1]?.group_name ?? '') === name) return null
  if (!name && !all.some((client) => client.group_name)) return null
  return { name, visible: rows.filter((client) => (client.group_name ?? '') === name).length,
    total: all.filter((client) => (client.group_name ?? '') === name).length }
}
