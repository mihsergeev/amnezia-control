import assert from 'node:assert/strict'
import test from 'node:test'
import type { Cascade, Server, ServerStat } from '../src/api.ts'
import {
  groupServerList, resolveServerSelection, serverListAnchors, serverListClients,
  serverListItems, serverListMatches, serverListMembers, serverListProblem,
  serverSelectionFromHistory, serverSelectionFromParams, serverSelectionParams,
} from '../src/serverList.ts'

function node(id: number, extra: Partial<Server> = {}): Server {
  return { id, name: `Node ${id}`, host: `192.0.2.${id}`, group_name: '', position: id,
    note: '', last_check_ok: true, ...extra } as Server
}

function cascade(id = 1, entry = 1, exit = 2, extra: Partial<Cascade> = {}): Cascade {
  return { id, entry_server_id: entry, exit_server_id: exit, entry_ip: `192.0.2.${entry}`,
    exit_ip: `192.0.2.${exit}`, transport: 'gre', status: 'ready', result: {}, ...extra } as Cascade
}

const text = (server: Server) => [server.name, server.host, server.group_name, server.note].join(' ')

test('a cascade has one row even when its exit has direct clients and protocols', () => {
  const servers = [node(1), node(2, { last_check_info: '{"amnezia_containers":["amnezia-awg3"]}' }), node(3)]
  const snapshot = JSON.stringify(servers)
  const rows = serverListItems(servers, [cascade()])
  assert.deepEqual(rows.map((row) => row.key), ['cascade:1', 'server:3'])
  assert.deepEqual(serverListMembers(rows).map((server) => server.id), [1, 2, 3])
  assert.equal(JSON.stringify(servers), snapshot)
})

test('the selected exit retains the cascade row and its own details', () => {
  const rows = serverListItems([node(1), node(2)], [cascade()])
  const selected = resolveServerSelection(rows, { key: 'cascade:1', serverId: 2 })
  assert.equal(selected.item?.key, 'cascade:1')
  assert.equal(selected.server?.id, 2)
  assert.equal(resolveServerSelection(rows, { key: null, serverId: 2 }).server?.id, 2)
})

test('search finds either node, its note, group and address without changing exit selection', () => {
  const servers = [node(1, { name: 'Entry example', group_name: 'Group A' }), node(2, { name: 'Exit example', note: 'direct clients', group_name: 'Group B' })]
  const rows = serverListItems(servers, [cascade()])
  for (const query of ['entry example', 'exit example', 'direct clients', 'group b', '192.0.2.2', 'GRE']) {
    const filtered = rows.filter((row) => serverListMatches(row, query, text))
    assert.equal(filtered.length, 1)
    assert.equal(resolveServerSelection(filtered, { key: 'cascade:1', serverId: 2 }).server?.id, 2)
  }
  assert.equal(resolveServerSelection([], { key: 'cascade:1', serverId: 2 }).server, undefined)
})

test('shared nodes keep distinct cascade contexts, including reverse and shared entries', () => {
  const rows = serverListItems([node(1), node(2), node(3)], [cascade(1, 1, 2), cascade(2, 2, 3), cascade(3, 1, 3)])
  assert.equal(rows.length, 3)
  assert.equal(resolveServerSelection(rows, { key: 'cascade:2', serverId: 2 }).item?.cascade?.id, 2)
  assert.equal(resolveServerSelection(rows, { key: 'cascade:1', serverId: 2 }).item?.cascade?.id, 1)
  assert.deepEqual(serverListAnchors(rows).map((server) => server.id), [1, 2])
})

test('counts are logical rows, clients are deduplicated by node within a group', () => {
  const rows = serverListItems([node(1), node(2), node(3)], [cascade(1, 1, 2), cascade(2, 3, 2)])
  const stats = { 1: { clients_online: 0, clients_total: 0 }, 2: { clients_online: 4, clients_total: 45 }, 3: { clients_online: 0, clients_total: 0 } } as Record<number, ServerStat>
  assert.equal(groupServerList(rows)[0].items.length, 2)
  assert.deepEqual(serverListClients(rows, stats), { available: true, online: 4, total: 45 })
  assert.equal(serverListClients([rows[0]], stats).total, 45)
})

test('problems include either node, cascade errors, installing and health failures', () => {
  for (const extra of [{ status: 'error' as const }, { status: 'installing' as const }, { result: { health: { ok: false } } }]) {
    assert.equal(serverListProblem(serverListItems([node(1), node(2)], [cascade(1, 1, 2, extra)])[0], () => false), true)
  }
  const row = serverListItems([node(1), node(2)], [cascade()])[0]
  assert.equal(serverListProblem(row, (server) => server.id === 2), true)
  assert.equal(serverListProblem(row, () => false), false)
})

test('missing nodes retain the remaining node and completely orphaned cascade is still visible', () => {
  const partial = serverListItems([node(2)], [cascade()])
  assert.equal(partial.length, 1)
  assert.equal(resolveServerSelection(partial, { key: 'cascade:1', serverId: 1 }).server?.id, 2)
  assert.equal(serverListProblem(partial[0], () => false), true)
  const orphaned = serverListItems([], [cascade()])
  assert.equal(orphaned.length, 1)
  assert.equal(resolveServerSelection(orphaned, { key: 'cascade:1', serverId: 1 }).server, undefined)
})

test('deleting a cascade restores both standalone rows and preserves selected exit', () => {
  const rows = serverListItems([node(1), node(2)], [])
  const selected = resolveServerSelection(rows, { key: 'cascade:1', serverId: 2 })
  assert.equal(rows.length, 2)
  assert.equal(selected.item?.key, 'server:2')
  assert.equal(selected.server?.id, 2)
})

test('a standalone node with a manually configured egress is never auto-grouped', () => {
  assert.equal(serverListItems([node(1, { egress_ip: '198.51.100.10' }), node(2)], []).length, 2)
})

test('direct links retain exact node and cascade; unrelated query parameters survive', () => {
  const row = serverListItems([node(1), node(2)], [cascade()])[0]
  const params = serverSelectionParams(new URLSearchParams('theme=light&other=example'), row, node(2))
  assert.equal(params.get('other'), 'example')
  assert.deepEqual(serverSelectionFromParams(params), { key: 'cascade:1', serverId: 2 })
  assert.deepEqual(serverSelectionFromParams(new URLSearchParams('server=-1&cascade=invalid')), { key: null, serverId: null })
  assert.equal(resolveServerSelection([row], { key: 'cascade:999', serverId: 2 }).server?.id, 2)
})

test('Back to the original URL without query restores the original saved exit, not the entry', () => {
  const original = { acontrolServerSelection: { key: null, serverId: 2 }, unrelated: 'example' }
  const rows = serverListItems([node(1), node(2)], [cascade()])
  assert.equal(resolveServerSelection(rows, serverSelectionFromHistory(new URLSearchParams(), original)).server?.id, 2)
  assert.equal(serverSelectionFromHistory(new URLSearchParams('server=1&cascade=1'), original).serverId, 1)
  assert.deepEqual(serverSelectionFromHistory(new URLSearchParams(), { acontrolServerSelection: '<invalid>' }), { key: null, serverId: null })
})
