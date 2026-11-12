import assert from 'node:assert/strict'
import test from 'node:test'
import { siteCheckTone, siteTimingValue, siteCheckRetryDestinations, siteCheckInputRows, siteCheckMarkDuplicates, siteCheckRetryUrls, siteCheckMergeRetry, siteCheckDuration, MAX_SITE_CHECK_LINES } from '../src/siteCheckUi.ts'
import { routeHttpDestinations, previewRouteBatch, appendRouteBatch } from '../src/cascadeRouteDraft.ts'

test('HTTP colors reflect actual response codes and never turn transport errors into success', () => {
  for (const code of [200, 204, 299]) assert.equal(siteCheckTone({ status: 'response', http_status: code }), 'success')
  for (const code of [301, 302, 399]) assert.equal(siteCheckTone({ status: 'response', http_status: code }), 'warning')
  for (const code of [403, 404, 500, 503]) assert.equal(siteCheckTone({ status: 'response', http_status: code }), 'error')
  for (const status of ['timeout', 'error', 'node_unreachable', 'unavailable', 'blocked', 'invalid'] as const) assert.equal(siteCheckTone({ status }), 'error')
  assert.equal(siteCheckTone({ status: 'response' }), 'error')
  assert.equal(siteCheckTone({ status: 'not_applicable' }), 'muted')
  assert.equal(siteCheckTone({ status: 'not_checked' }), 'muted')
  assert.equal(siteCheckTone(undefined), 'pending')
})

test('canonical unique HTTP candidates include existing duplicates and CIDR without invalid input', () => {
  const lines = previewRouteBatch('ONE.example\none.example\nexisting.example\nbad\n192.0.2.0/24', [{ destination: 'existing.example', via: 'entry' }], [
    { valid: true, destination: 'one.example' }, { valid: true, destination: 'one.example' }, { valid: true, destination: 'existing.example' }, { valid: false, error: 'invalid_destination' }, { valid: true, destination: '192.0.2.0/24' },
  ])
  assert.deepEqual(routeHttpDestinations(lines), ['one.example', 'existing.example', '192.0.2.0/24'])
  assert.deepEqual(appendRouteBatch([], lines, 'exit'), [{ destination: 'one.example', via: 'exit' }, { destination: '192.0.2.0/24', via: 'exit' }], 'HTTP diagnostics do not participate in add eligibility')
})

test('stage timings retain useful precision and do not invent missing measurements', () => {
  assert.equal(siteTimingValue(undefined), null)
  assert.equal(siteTimingValue(null), null, 'nullable backend measurements remain unknown rather than zero')
  assert.equal(siteTimingValue(Number.NaN), null)
  assert.equal(siteTimingValue(-1), null)
  assert.equal(siteTimingValue(0), '0')
  assert.equal(siteTimingValue(12.345), '12.3')
  assert.equal(siteTimingValue(0.26), '0.3')
})

test('deadline retry selects only unchecked destinations, retaining actual responses', () => {
  assert.deepEqual(siteCheckRetryDestinations({ 'ok.example': { status: 'response', http_status: 200 }, 'denied.example': { status: 'response', http_status: 403 }, 'queued.example': { status: 'not_checked', reason: 'batch_deadline' }, 'slow.example': { status: 'timeout' } }), ['queued.example'])
})

test('multiline input keeps original line numbers and raw origins without discarding URL parts', () => {
  const rows = siteCheckInputRows('\n example.com \r\n\r\nhttp://example.com/\nhttps://reader@example.com/path?private=fixture#part\n' + 'a'.repeat(1025))
  assert.deepEqual(rows.slice(0, 3), [{ line: 2, raw: 'example.com' }, { line: 4, raw: 'http://example.com/' }, { line: 5, raw: 'https://reader@example.com/path?private=fixture#part' }])
  assert.equal(rows[3].result?.status, 'invalid')
  assert.equal(rows[3].raw.length, 1025)
  assert.equal(siteCheckInputRows(Array.from({ length: 101 }, (_, n) => `site${n}.example`).join('\n')).length, MAX_SITE_CHECK_LINES + 1, 'overflow is retained and rejected by the caller, never truncated')
})

test('canonical server results deduplicate by host and protocol while retaining every input row', () => {
  const rows = siteCheckMarkDuplicates([
    { line: 1, raw: 'FAẞ.example', result: { destination: 'fass.example', scheme: 'https', status: 'response', http_status: 200 } },
    { line: 3, raw: 'https://fass.example/', result: { destination: 'fass.example', scheme: 'https', status: 'response', http_status: 200 } },
    { line: 4, raw: 'http://fass.example', result: { destination: 'fass.example', scheme: 'http', status: 'response', http_status: 403 } },
    { line: 5, raw: 'https://reader@example.com', result: { destination: null, scheme: null, status: 'invalid' } },
  ])
  assert.equal(rows.length, 4)
  assert.equal(rows[1].duplicateOf, 1)
  assert.equal(rows[2].duplicateOf, undefined)
  assert.equal(rows[3].duplicateOf, undefined)
  assert.equal(rows[0].raw, 'FAẞ.example', 'browser URL normalization never replaces the original input')
})

test('mixed-protocol retry includes only unchecked canonical origins and preserves completed and duplicate rows', () => {
  const rows = siteCheckMarkDuplicates([
    { line: 1, raw: 'ok.example', result: { destination: 'ok.example', scheme: 'https', status: 'response', http_status: 200 } },
    { line: 2, raw: 'http://ok.example', result: { destination: 'ok.example', scheme: 'http', status: 'response', http_status: 403 } },
    { line: 3, raw: 'queued.example', result: { destination: 'queued.example', scheme: 'https', status: 'not_checked' } },
    { line: 4, raw: 'https://QUEUED.example/', result: { destination: 'queued.example', scheme: 'https', status: 'not_checked' } },
    { line: 5, raw: 'http://queued.example', result: { destination: 'queued.example', scheme: 'http', status: 'not_checked' } },
  ])
  const urls = siteCheckRetryUrls(rows)
  assert.deepEqual(urls, ['https://queued.example', 'http://queued.example'])
  const merged = siteCheckMergeRetry(rows, urls, [{ destination: 'queued.example', scheme: 'https', status: 'response', http_status: 204 }, { destination: 'wrong.example', scheme: 'http', status: 'response', http_status: 200 }])
  assert.deepEqual(merged.slice(0, 2), rows.slice(0, 2))
  assert.equal(merged[2].result?.http_status, 204)
  assert.equal(merged[3].result?.http_status, 204)
  assert.equal(merged[3].duplicateOf, 3)
  assert.equal(merged[4].result?.status, 'not_checked', 'a mismatched target cannot replace the requested result')
  assert.deepEqual(siteCheckRetryUrls(merged), ['http://queued.example'])
})

test('compact row duration never invents a network measurement for invalid or unchecked rows', () => {
  assert.equal(siteCheckDuration({ status: 'response', timings_ms: { total: 0 } }), '0')
  assert.equal(siteCheckDuration({ status: 'timeout', timings_ms: { total: 3000 } }), '3000')
  assert.equal(siteCheckDuration({ status: 'invalid', timings_ms: { total: 0 } }), null)
  assert.equal(siteCheckDuration({ status: 'not_checked', timings_ms: { total: 0 } }), null)
  assert.equal(siteCheckDuration({ status: 'node_unreachable', timings_ms: { total: 0 } }), null)
})
