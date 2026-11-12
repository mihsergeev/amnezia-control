import type { CascadeRouteHttpResult } from './api'

export function siteCheckTone(result: CascadeRouteHttpResult | undefined): 'pending' | 'success' | 'warning' | 'error' | 'muted' {
  if (!result) return 'pending'
  if (result.status === 'not_applicable' || result.status === 'not_checked') return 'muted'
  if (result.status !== 'response' || !Number.isInteger(result.http_status)) return 'error'
  return result.http_status! >= 200 && result.http_status! < 300 ? 'success'
    : result.http_status! >= 300 && result.http_status! < 400 ? 'warning' : 'error'
}

export function siteTimingValue(value: number | null | undefined): string | null {
  return value == null || !Number.isFinite(value) || value < 0 ? null : String(Math.round(value * 10) / 10)
}


export function siteCheckRetryDestinations(results: Readonly<Record<string, CascadeRouteHttpResult>>): string[] {
  return Object.entries(results).filter(([, result]) => result.status === 'not_checked').map(([destination]) => destination)
}

export const MAX_SITE_CHECK_LINES = 100
export type SiteCheckRow = { line: number; raw: string; result?: CascadeRouteHttpResult; duplicateOf?: number }

/** Keep input line identity; only the server performs URL and IDNA normalization. */
export function siteCheckInputRows(text: string): SiteCheckRow[] {
  return text.split(/\r?\n/).flatMap((raw, index) => raw.trim() ? [{ line: index + 1, raw: raw.trim(), ...(raw.trim().length > 1024 ? { result: { status: 'invalid' as const, reason: 'input_too_long' } } : {}) }] : [])
}

export function siteCheckResultKey(result?: CascadeRouteHttpResult): string | null {
  return result?.destination && (result.scheme === 'https' || result.scheme === 'http') ? `${result.scheme}://${result.destination}` : null
}

/** Canonical host + scheme identify a target; HTTP and HTTPS stay independent. */
export function siteCheckMarkDuplicates(rows: readonly SiteCheckRow[]): SiteCheckRow[] {
  const seen = new Map<string, number>()
  return rows.map(({ duplicateOf: _duplicate, ...row }) => {
    const key = siteCheckResultKey(row.result)
    if (!key) return row
    const first = seen.get(key)
    if (first !== undefined) return { ...row, duplicateOf: first }
    seen.set(key, row.line)
    return row
  })
}

export function siteCheckRetryUrls(rows: readonly SiteCheckRow[]): string[] {
  return [...new Set(rows.filter((row) => row.result?.status === 'not_checked').flatMap((row) => {
    const key = siteCheckResultKey(row.result)
    return key ? [key] : []
  }))]
}

export function siteCheckMergeRetry(rows: readonly SiteCheckRow[], urls: readonly string[], results: readonly CascadeRouteHttpResult[]): SiteCheckRow[] {
  const replacements = new Map(urls.map((url, index) => [url, results[index]]))
  return siteCheckMarkDuplicates(rows.map((row) => {
    const key = siteCheckResultKey(row.result)
    const replacement = key ? replacements.get(key) : undefined
    return replacement && siteCheckResultKey(replacement) === key ? { ...row, result: replacement } : row
  }))
}

export function siteCheckDuration(result?: CascadeRouteHttpResult): string | null {
  return result && ['response', 'error', 'timeout'].includes(result.status) ? siteTimingValue(result.timings_ms?.total) : null
}
