export type ClientMetadata = { group_name?: string; device_name?: string }

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
