import assert from 'node:assert/strict'
import test from 'node:test'
import { groupClients, clientGroupNames, clientGroupHeader } from '../src/clientGrouping.ts'

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


test('group headers distinguish exact client names and count filtered devices without counting headers as configs', () => {
  const clients = [
    { id: 'a', group_name: 'Alex', device_name: 'Phone' },
    { id: 'b', group_name: 'alex', device_name: 'Phone' },
    { id: 'c', group_name: 'Alex', device_name: 'Laptop' },
    { id: 'd', group_name: '', device_name: 'Tablet' },
  ]
  assert.deepEqual(new Set(clientGroupNames(clients)), new Set(['Alex', 'alex']))
  const visible = groupClients([clients[0], clients[3]], true)
  assert.deepEqual(clientGroupHeader(visible, 0, clients), { name: 'Alex', visible: 1, total: 2 })
  assert.deepEqual(clientGroupHeader(visible, 1, clients), { name: '', visible: 1, total: 1 })
  assert.equal(clientGroupHeader([clients[0], clients[2]], 1, clients), null)
  assert.equal(clientGroupHeader([clients[3]], 0, [clients[3]]), null)
  assert.deepEqual(clients.map((client) => client.device_name), ['Phone', 'Phone', 'Laptop', 'Tablet'])
})
