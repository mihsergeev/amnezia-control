import assert from 'node:assert/strict'
import test from 'node:test'
import { appendRouteBatch, moveRoute, previewRouteBatch, routeBatchInput, routeDestinationsOverlap, routeSignature } from '../src/cascadeRouteDraft.ts'
import type { CascadeRoute, CascadeRouteDestinationResult } from '../src/api.ts'
const ok = (destination: string): CascadeRouteDestinationResult => ({ valid: true, destination })
const route = (destination: string, via: 'entry' | 'exit' = 'entry'): CascadeRoute => ({ destination, via })

test('canonical server results identify existing and batch duplicates including IDNA', () => {
  const lines = previewRouteBatch('FAß.example\nfass.example\nBÜCHER.example.\nother.example', [route('xn--bcher-kva.example')], [ok('fass.example'), ok('fass.example'), ok('xn--bcher-kva.example'), ok('other.example')])
  assert.deepEqual(lines.map(({ status }) => status), ['valid', 'duplicate', 'duplicate', 'valid'])
  assert.deepEqual(lines.filter(({ status }) => status === 'valid').map(({ destination }) => destination), ['fass.example', 'other.example'])
})

test('blank lines are ignored without losing original line numbers and raw invalid input', () => {
  assert.deepEqual(routeBatchInput('\n example.com \r\n\ninvalid input\n'), [{ line: 2, raw: ' example.com ' }, { line: 4, raw: 'invalid input' }])
  const lines = previewRouteBatch('\nexample.com\n\nbad\napi.ipify.org', [], [ok('example.com'), { valid: false, error: 'invalid_destination' }, { valid: false, error: 'reserved_destination' }])
  assert.deepEqual(lines.map(({ line, status }) => [line, status]), [[2, 'valid'], [4, 'invalid'], [5, 'reserved']])
})

test('missing validation never makes an address addable', () => {
  assert.equal(previewRouteBatch('unknown.example', [], [])[0].status, 'invalid')
})

test('domain overlap respects label boundaries in either priority order', () => {
  assert.equal(routeDestinationsOverlap('a.example.com', 'example.com'), true)
  assert.equal(routeDestinationsOverlap('example.com', 'a.example.com'), true)
  assert.equal(routeDestinationsOverlap('notexample.com', 'example.com'), false)
  assert.equal(routeDestinationsOverlap('a.example.com', 'b.example.com'), false)
  const lines = previewRouteBatch('a.example.com\nexample.com', [], [ok('a.example.com'), ok('example.com')])
  assert.deepEqual(lines[0].overlap, { priority: 2, destination: 'example.com' })
  assert.deepEqual(lines[1].overlap, { priority: 1, destination: 'a.example.com' })
})

test('IPv4 host/subnet intersections warn across nested networks and /0, never unrelated domains', () => {
  for (const [a, b] of [['192.0.2.1', '192.0.2.0/24'], ['192.0.2.0/25', '192.0.2.0/24'], ['0.0.0.0/0', '203.0.113.1']]) assert.equal(routeDestinationsOverlap(a, b), true)
  assert.equal(routeDestinationsOverlap('192.0.2.0/25', '192.0.2.128/25'), false)
  assert.equal(routeDestinationsOverlap('192.0.2.1', 'host.example'), false)
  const lines = previewRouteBatch('192.0.2.9', [route('192.0.2.0/24')], [ok('192.0.2.9')])
  assert.equal(lines[0].overlap?.priority, 1)
})

test('append keeps original order and chosen direction, skips invalid/duplicate and refuses overflow atomically', () => {
  const original = Array.from({ length: 98 }, (_, i) => route(`r${i}.example.com`))
  const lines = previewRouteBatch('one.example\nr0.example.com\nbad\ntwo.example', original, [ok('one.example'), ok('r0.example.com'), { valid: false, error: 'invalid_destination' }, ok('two.example')])
  const appended = appendRouteBatch(original, lines, 'exit')!
  assert.equal(appended.length, 100)
  assert.deepEqual(appended.slice(0, 98), original)
  assert.deepEqual(appended.slice(98), [route('one.example', 'exit'), route('two.example', 'exit')])
  assert.equal(appendRouteBatch(appended, previewRouteBatch('more.example', appended, [ok('more.example')]), 'entry'), null)
  assert.equal(original.length, 98)
})

test('explicit reorder preserves all stable identities and never mutates the source', () => {
  const original = [{ id: 1 }, { id: 2 }, { id: 3 }]
  assert.deepEqual(moveRoute(original, 2, 0).map(({ id }) => id), [3, 1, 2])
  assert.deepEqual(moveRoute(original, 0, 2).map(({ id }) => id), [2, 3, 1])
  assert.deepEqual(moveRoute(original, -1, 1), original)
  assert.deepEqual(original.map(({ id }) => id), [1, 2, 3])
})

test('dirty comparison includes route order and direction, excludes UI identities', () => {
  const original = [route('one.example'), route('two.example', 'exit')]
  assert.equal(routeSignature(original), routeSignature(original.map((item, id) => ({ ...item, id }))))
  assert.notEqual(routeSignature(original), routeSignature([...original].reverse()))
  assert.notEqual(routeSignature(original), routeSignature([route('one.example', 'exit'), original[1]]))
})
