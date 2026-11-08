import assert from 'node:assert/strict'
import test from 'node:test'
import { cascadeLocalRoute, cascadePort, cascadeSecurityState, DEFAULT_CASCADE_TRANSPORT } from '../src/cascadeUi.ts'

test('the new default is AWG, not an unencrypted transport recommendation', () => {
  assert.equal(DEFAULT_CASCADE_TRANSPORT, 'awg')
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
