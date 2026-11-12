import type { CascadeRoute, CascadeRouteDestinationResult } from './api'

export const MAX_CASCADE_ROUTES = 100
function ipv4(value: string): number | null {
  const parts = value.split('.')
  if (parts.length !== 4 || !parts.every((part) => /^(0|[1-9]\d{0,2})$/.test(part) && Number(part) <= 255)) return null
  return parts.reduce((result, part) => result * 256 + Number(part), 0)
}

function ipRange(destination: string): [number, number] | null {
  const [host, bits] = destination.split('/')
  const ip = ipv4(host)
  return ip === null ? null : [ip, ip + 2 ** (32 - (bits === undefined ? 32 : Number(bits))) - 1]
}

export function routeDestinationsOverlap(a: string, b: string): boolean {
  const left = ipRange(a)
  const right = ipRange(b)
  if (left || right) return !!left && !!right && left[0] <= right[1] && right[0] <= left[1]
  return a === b || a.endsWith(`.${b}`) || b.endsWith(`.${a}`)
}

export type RouteOverlap = { priority: number; destination: string }
export function routeOverlap(destination: string, routes: readonly CascadeRoute[], exclude = -1): RouteOverlap | undefined {
  const index = routes.findIndex((route, i) => i !== exclude && routeDestinationsOverlap(destination, route.destination))
  return index < 0 ? undefined : { priority: index + 1, destination: routes[index].destination }
}

export type BatchRouteLine = { line: number; raw: string; destination?: string; status: 'valid' | 'duplicate' | 'invalid' | 'reserved'; overlap?: RouteOverlap }
export function routeBatchInput(text: string): { line: number; raw: string }[] {
  return text.split(/\r?\n/).flatMap((raw, index) => raw.trim() ? [{ line: index + 1, raw }] : [])
}

/** Normalization belongs to the server's existing Route validator, including IDNA. */
export function previewRouteBatch(text: string, existing: readonly CascadeRoute[], results: readonly CascadeRouteDestinationResult[]): BatchRouteLine[] {
  const seen = new Set(existing.map((route) => route.destination))
  const lines: BatchRouteLine[] = routeBatchInput(text).map(({ raw, line }, index) => {
    const result = results[index]
    if (!result || !result.valid) return { line, raw, status: result?.error === 'reserved_destination' ? 'reserved' : 'invalid' }
    const status = seen.has(result.destination) ? 'duplicate' : 'valid'
    seen.add(result.destination)
    return { line, raw, destination: result.destination, status }
  })
  const combined = [...existing, ...lines.filter((line) => line.status === 'valid').map((line) => ({ destination: line.destination!, via: 'entry' as const }))]
  let next = existing.length
  return lines.map((line) => line.status === 'valid' ? { ...line, overlap: routeOverlap(line.destination!, combined, next++) } : line)
}

/** Never truncate a batch: the caller must resolve the limit before adding it. */
export function appendRouteBatch(existing: readonly CascadeRoute[], lines: readonly BatchRouteLine[], via: CascadeRoute['via']): CascadeRoute[] | null {
  const added = lines.filter((line) => line.status === 'valid').map((line) => ({ destination: line.destination!, via }))
  return existing.length + added.length > MAX_CASCADE_ROUTES ? null : [...existing, ...added]
}

export function moveRoute<T>(routes: readonly T[], from: number, to: number): T[] {
  const copy = [...routes]
  if (from < 0 || from >= copy.length || to < 0 || to >= copy.length) return copy
  const [route] = copy.splice(from, 1)
  copy.splice(to, 0, route)
  return copy
}

export function routeSignature(routes: readonly CascadeRoute[]): string {
  return JSON.stringify(routes.map(({ destination, via }) => ({ destination, via })))
}

/** Probe each canonical address once; duplicate rows share the informational result. */
export function routeHttpDestinations(lines: readonly BatchRouteLine[]): string[] {
  return [...new Set(lines.filter((line) => line.destination && (line.status === 'valid' || line.status === 'duplicate')).map((line) => line.destination!))]
}
