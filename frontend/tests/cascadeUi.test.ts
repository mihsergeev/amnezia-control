import assert from 'node:assert/strict'
import test from 'node:test'
import { cascadeClientExitConfirmed, cascadeEntryOwnershipError, cascadeLocalExpected, cascadeLocalRoute, cascadePort, cascadeRequestId, cascadeSecurityState, DEFAULT_CASCADE_TRANSPORT, latestCascadeHealth } from '../src/cascadeUi.ts'

test('the new default is AWG, not an unencrypted transport recommendation', () => {
  assert.equal(DEFAULT_CASCADE_TRANSPORT, 'awg')
})

test('wizard recovery is offered only for a failed entry ownership check', () => {
  const current = { status: 'error', phase: 'entry', error: 'Install failed', result: { error_code: 'cascade_entry_ownership' } } as const
  const legacy = { ...current, error: 'вход «Entry»: gateway ownership', result: {} }
  assert.equal(cascadeEntryOwnershipError(current), true)
  assert.equal(cascadeEntryOwnershipError(legacy), true)
  assert.equal(cascadeEntryOwnershipError({ ...legacy, error: 'SSH: connection refused' }), false)
  assert.equal(cascadeEntryOwnershipError({ ...legacy, phase: 'exit' }), false)
  assert.equal(cascadeEntryOwnershipError({ ...current, status: 'installing' }), false)
})

test('blank UDP ports mean auto; explicit ports retain exact asymmetric values', () => {
  assert.equal(cascadePort(''), null)
  assert.equal(cascadePort('  '), null)
  assert.equal(cascadePort(' 12345 '), 12345)
  assert.equal(cascadePort('23456'), 23456)
  for (const value of ['0', '65536', '-1', '1.2', '1e3', 'hello']) assert.equal(cascadePort(value), undefined)
})

test('encryption status requires explicit crypto runtime proof, independently of connectivity', () => {
  assert.equal(cascadeSecurityState({}), 'unknown')
  assert.equal(cascadeSecurityState({ encryption: 'awg', encrypted: null }), 'unknown')
  assert.equal(cascadeSecurityState({ encryption: 'awg', encrypted: false }), 'unknown')
  assert.equal(cascadeSecurityState({ encryption: 'unknown', encrypted: true }), 'unknown')
  assert.equal(cascadeSecurityState({ encryption: 'none', encrypted: false }), 'plain')
  assert.equal(cascadeSecurityState({ encryption: 'awg', encrypted: true }), 'confirmed')
  assert.equal(cascadeSecurityState({ encryption: 'reality', encrypted: true }), 'confirmed')
})

test('a responding local site only confirms a direct route if the entry and exit addresses differ', () => {
  const direct = '192.0.2.10'
  const egress = '198.51.100.20'
  assert.equal(cascadeLocalRoute({ ru: direct, direct, egress }), 'entry')
  assert.equal(cascadeLocalRoute({ ru: egress, direct, egress }), 'exit')
  assert.equal(cascadeLocalRoute({ ru: '203.0.113.30', direct, egress }), 'unknown')
  assert.equal(cascadeLocalRoute({ ru: direct, direct, egress: direct }), 'unknown')
  assert.equal(cascadeLocalRoute({ ru: direct, direct }), 'unknown')
  assert.equal(cascadeLocalRoute({ ru: egress, egress }), 'unknown')
  assert.equal(cascadeLocalRoute({ direct, egress }), 'unknown')
})

test('the first matching saved domain rule determines the expected path of ip.nic.ru', () => {
  assert.equal(cascadeLocalExpected(), 'entry')
  assert.equal(cascadeLocalExpected([{ destination: 'ic.ru', via: 'exit' }, { destination: '192.0.2.0/24', via: 'exit' }]), 'entry')
  assert.equal(cascadeLocalExpected([{ destination: 'ip.nic.ru', via: 'exit' }]), 'exit')
  assert.equal(cascadeLocalExpected([{ destination: 'nic.ru', via: 'exit' }, { destination: 'ip.nic.ru', via: 'entry' }]), 'exit')
  assert.equal(cascadeLocalExpected([{ destination: 'nic.ru', via: 'entry' }, { destination: 'ip.nic.ru', via: 'exit' }]), 'entry')
})

test('cascade request IDs are valid v4 UUIDs using Web Crypto on HTTP', () => {
  const first = cascadeRequestId()
  assert.match(first, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)
  assert.notEqual(cascadeRequestId(), first)
})

test('client egress needs a matching exit address distinct from the entry', () => {
  const direct = '192.0.2.10'
  const egress = '198.51.100.20'
  assert.equal(cascadeClientExitConfirmed({ client: egress, direct, egress }), true)
  assert.equal(cascadeClientExitConfirmed({ client: direct, direct, egress }), false)
  assert.equal(cascadeClientExitConfirmed({ client: direct, direct, egress: direct }), false)
  assert.equal(cascadeClientExitConfirmed({ client: egress, egress }), false)
  assert.equal(cascadeClientExitConfirmed({ direct, egress }), false)
})

test('a manual result overrides the older watchdog result in either direction', () => {
  const old = '2026-11-10T11:58:00Z'
  const recent = '2026-11-10T11:59:00Z'
  for (const ok of [true, false]) {
    const manual = { ok, checked_at: recent }
    const health = { ok: !ok, checked_at: old }
    assert.equal(latestCascadeHealth({ manual_check: manual, health }), manual)
    const nextHealth = { ok: !ok, checked_at: '2026-11-10T11:59:30Z' }
    assert.equal(latestCascadeHealth({ manual_check: manual, health: nextHealth }), nextHealth)
  }
})

test('only dated observations determine the last known cascade status', () => {
  assert.equal(latestCascadeHealth({}), undefined)
  assert.equal(latestCascadeHealth({ health: { ok: true } }), undefined)
  assert.equal(latestCascadeHealth({ manual_check: { ok: false, checked_at: 'bad date' } }), undefined)
  const health = { ok: false, checked_at: '2000-01-01T00:00:00Z' }
  assert.equal(latestCascadeHealth({ health }), health)
})
