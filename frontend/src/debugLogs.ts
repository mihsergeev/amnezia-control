export type DebugLogLevel = 'error' | 'warning' | 'info'

export type DebugLogEvent = {
  id: string
  timestamp: string
  level: DebugLogLevel
  operation: string
  code: string
  summary: string
  protocol?: string
  stage?: string
  server_id?: number
  correlation_id?: string
  locations?: Array<{ module: string; function: string; line: number }>
}

export type DebugLogsResponse = {
  events: DebugLogEvent[]
  retention_days: number
  max_bytes: number
}

export type DebugLogFilters = { level?: DebugLogLevel | ''; operation?: string }

export const DEBUG_OPERATIONS: Record<string, string> = {
  request: 'Запросы панели',
  ssh: 'SSH',
  deploy: 'Установка протокола',
  cascade: 'Каскады',
  probe: 'Проверка подключения',
  clients: 'Клиенты',
  backup: 'Резервное копирование',
  import: 'Импорт',
  alerts: 'Алерты',
  system: 'Система',
}

export function debugLogsPath(filters: DebugLogFilters = {}, download = false) {
  const query = new URLSearchParams()
  if (!download) query.set('limit', '200')
  if (filters.level) query.set('level', filters.level)
  if (filters.operation) query.set('operation', filters.operation)
  return `/api/debug-logs${download ? '/download' : ''}${query.size ? `?${query}` : ''}`
}
