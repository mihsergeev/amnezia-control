import assert from 'node:assert/strict'
import test from 'node:test'
import { configFilename } from '../src/clientExports.ts'

test('native exports retain a safe server filename and the selected native extension', () => {
  assert.equal(configFilename('Client name', 'conf', 'client-phone.conf'), 'client-phone.conf')
  assert.equal(configFilename('Client name', 'ovpn', 'client-phone.ovpn'), 'client-phone.ovpn')
  assert.equal(configFilename('Legacy', 'txt'), 'Legacy.txt')
})

test('suggested paths and mismatched formats cannot change the native download type', () => {
  assert.equal(configFilename('Client name', 'ovpn', '../../another.ovpn'), 'Client_name.ovpn')
  assert.equal(configFilename('Client name', 'conf', 'another.ovpn'), 'Client_name.conf')
  assert.equal(configFilename('...', 'conf', '.hidden.conf'), 'client.conf')
})
