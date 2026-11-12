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
