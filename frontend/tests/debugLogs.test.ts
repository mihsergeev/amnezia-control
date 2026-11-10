import assert from 'node:assert/strict'
import test from 'node:test'
import { debugLogsPath } from '../src/debugLogs.ts'

test('debug event list has a bounded request and omits empty filters', () => {
  assert.equal(debugLogsPath(), '/api/debug-logs?limit=200')
  assert.equal(debugLogsPath({ level: '', operation: '' }), '/api/debug-logs?limit=200')
})

test('list and support archive preserve the same encoded filters', () => {
  const filters = { level: 'error' as const, operation: 'install / retry?&' }
  const list = new URL(debugLogsPath(filters), 'https://example.invalid')
  const archive = new URL(debugLogsPath(filters, true), 'https://example.invalid')
  assert.equal(list.searchParams.get('level'), 'error')
  assert.equal(list.searchParams.get('operation'), filters.operation)
  assert.equal(archive.pathname, '/api/debug-logs/download')
  assert.equal(archive.searchParams.get('level'), 'error')
  assert.equal(archive.searchParams.get('operation'), filters.operation)
  assert.equal(archive.searchParams.has('limit'), false)
  assert.equal(debugLogsPath({}, true), '/api/debug-logs/download')
})
