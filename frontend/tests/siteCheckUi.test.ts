import assert from 'node:assert/strict'
import test from 'node:test'
import { siteCheckTone, siteTimingValue, siteCheckRetryDestinations } from '../src/siteCheckUi.ts'
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
