import assert from 'node:assert/strict'
import test from 'node:test'
import { accessChanged, accessPolicy } from '../src/sshAccess.ts'

test('legacy nodes retain direct access and missing fields do not trigger an apply', () => {
  assert.equal(accessChanged({}, { ssh_jump_server_id: null, ssh_source_mode: 'panel', ssh_source_ips: [], ssh_firewall_mode: 'add' }), false)
})

test('only SSH policy fields are sent to preview and unrestricted is always explicit', () => {
  const node = { ssh_source_mode: 'custom' as const, ssh_source_ips: ['192.0.2.1'], name: 'node', host: '192.0.2.2', password: 'fixture' }
  const payload = accessPolicy(node)
  assert.deepEqual(Object.keys(payload).sort(), ['ssh_firewall_mode', 'ssh_jump_server_id', 'ssh_source_ips', 'ssh_source_mode'])
  assert.equal(payload.ssh_source_mode, 'custom')
  assert.equal(accessChanged(payload, { ...payload, ssh_source_mode: 'any' }), true)
})
