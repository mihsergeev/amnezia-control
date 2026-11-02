import assert from 'node:assert/strict'
import test from 'node:test'
import { cascadePort, cascadeSecurityState, DEFAULT_CASCADE_TRANSPORT } from '../src/cascadeUi.ts'

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
