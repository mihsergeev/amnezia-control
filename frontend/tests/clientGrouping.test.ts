import assert from 'node:assert/strict'
import test from 'node:test'
import { groupClients } from '../src/clientGrouping.ts'

test('optional grouping retains client objects, duplicate names, devices and stable identities', () => {
  const clients = [
    { id: 'key-a', name: 'same', group_name: 'Person B', device_name: 'Laptop' },
    { id: 'key-b', name: 'same', group_name: '', device_name: '' },
    { id: 'key-c', name: 'same', group_name: 'Person A', device_name: 'Work' },
    { id: 'key-d', name: 'same', group_name: 'Person B', device_name: 'Phone' },
  ]
  assert.deepEqual(groupClients(clients, false), clients)
  const grouped = groupClients(clients, true)
  assert.deepEqual(grouped.map((client) => client.id), ['key-c', 'key-a', 'key-d', 'key-b'])
  assert.equal(grouped[1], clients[0])
  assert.deepEqual(clients.map((client) => client.id), ['key-a', 'key-b', 'key-c', 'key-d'])
})

test('empty metadata keeps the existing flat order', () => {
  const clients = [{ id: 'a' }, { id: 'b', group_name: '' }, { id: 'c', group_name: '  ' }]
  assert.deepEqual(groupClients(clients, true), clients)
})
