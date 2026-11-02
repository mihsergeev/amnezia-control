import assert from 'node:assert/strict'
import test from 'node:test'
import type { Cascade, Server, ServerStat } from '../src/api.ts'
import {
  groupServerList, resolveServerSelection, serverListAnchors, serverListClients,
  serverListItems, serverListMatches, serverListMembers, serverListProblem,
  serverSelectionFromHistory, serverSelectionFromParams, serverSelectionParams,
  cascadeNameParts, greLinkLabel, manualExitNameChange, serverListRoute,
  cascadeServerEligible,
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

test('two entries sharing one exit retain exact cascade contexts and one explicit exit row', () => {
  const rows = serverListItems([node(1), node(2), node(3)], [cascade(1, 1, 3), cascade(2, 2, 3)])
  assert.equal(rows.length, 3)
  assert.equal(resolveServerSelection(rows, { key: 'cascade:2', serverId: 3 }).item?.cascade?.id, 2)
  assert.equal(resolveServerSelection(rows, { key: 'cascade:1', serverId: 3 }).item?.cascade?.id, 1)
  assert.equal(resolveServerSelection(rows, { key: 'server:3', serverId: 3 }).item?.cascade, undefined)
  assert.equal(rows.find(r => r.key === 'server:3')?.sharedExitCount, 2)
  assert.deepEqual(serverListAnchors(rows).map((server) => server.id), [1, 2, 3])
})

test('counts are logical rows, clients are deduplicated by node within a group', () => {
  const rows = serverListItems([node(1), node(2), node(3)], [cascade(1, 1, 2), cascade(2, 3, 2)])
  const stats = { 1: { clients_online: 0, clients_total: 0 }, 2: { clients_online: 4, clients_total: 45 }, 3: { clients_online: 0, clients_total: 0 } } as Record<number, ServerStat>
  assert.equal(groupServerList(rows)[0].items.length, 3)
  assert.deepEqual(serverListClients(rows, stats), { available: true, online: 4, total: 45 })
  assert.equal(serverListClients([rows.find(r => r.key === 'cascade:1')!], stats).total, 0)
  assert.equal(serverListClients([rows.find(r => r.key === 'server:2')!], stats).total, 45)
})

test('shared exit counters belong only to its own group, including direct clients', () => {
  const servers = [node(1, { group_name: 'Entry A' }), node(2, { group_name: 'Exit group' }), node(3, { group_name: 'Entry B' })]
  const rows = serverListItems(servers, [cascade(1, 1, 2), cascade(2, 3, 2)])
  const stats = { 1: { clients_online: 1, clients_total: 3 }, 2: { clients_online: 4, clients_total: 45 }, 3: { clients_online: 2, clients_total: 5 } } as Record<number, ServerStat>
  assert.deepEqual(Object.fromEntries(groupServerList(rows).map(g => [g.name, serverListClients(g.items, stats).total])), { 'Entry A': 3, 'Exit group': 45, 'Entry B': 5 })
  assert.deepEqual(serverListClients(rows, stats), { available: true, online: 7, total: 53 })
})

test('incoming GRE interfaces do not turn the shared exit node into a fake manual cascade', () => {
  const servers = [node(1), node(2, { egress_ip: '192.0.2.2', country: 'FI', egress_country: 'FI', last_check_info: '{"tunnels":[{"kind":"gre","name":"incoming"}]}' }), node(3)]
  const rows = serverListItems(servers, [cascade(1, 1, 2), cascade(2, 3, 2)])
  assert.equal(serverListRoute(rows.find(r => r.key === 'server:2')!, servers), null)
})

test('cascade roles permit repeated exits, but exclude entries and manual entry carriers', () => {
  const cs = [cascade(1, 1, 2)]
  assert.equal(cascadeServerEligible(node(1), cs, 'entry'), false)
  assert.equal(cascadeServerEligible(node(1), cs, 'exit'), false)
  assert.equal(cascadeServerEligible(node(2), cs, 'entry'), false)
  assert.equal(cascadeServerEligible(node(2), cs, 'exit'), true)
  const manual = node(4, { last_check_info: '{"manual_cascade":{"transport":"vless","exit_host":"198.51.100.4"}}' })
  assert.equal(cascadeServerEligible(manual, cs, 'entry'), false)
  assert.equal(cascadeServerEligible(manual, cs, 'exit'), true)
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

test('manual cascade names use the configured peer rather than a NAT egress address', () => {
  const entry = node(1, { name: 'entry-one', country: 'RU', egress_ip: '203.0.113.10', egress_country: 'FI',
    last_check_info: JSON.stringify({ manual_cascade: { transport: 'vless', exit_host: '198.51.100.2', exit_name: 'checked-exit', exit_country: 'FI' } }) })
  const exit = node(2, { host: '198.51.100.2', name: 'exit-two', country: 'FI' })
  const rows = serverListItems([entry, exit], [])
  const route = serverListRoute(rows[0], [entry, exit])!
  assert.equal(route.entry.name, 'entry-one')
  assert.equal(route.exit.name, 'exit-two')
  assert.equal(route.exit.host, '198.51.100.2')
  assert.equal(serverListMatches(rows[0], 'exit-two', text, [entry, exit]), true)
  assert.equal(rows.length, 2) // Display metadata does not regroup or merge clients.
})

test('manual external peer uses a checked name or the actual endpoint, never its country/org', () => {
  const entry = node(1, { country: 'RU', egress_ip: '203.0.113.10', egress_country: 'FI', egress_org: 'Example operator',
    last_check_info: JSON.stringify({ manual_cascade: { transport: 'vless', exit_host: '198.51.100.10' } }) })
  let row = serverListItems([entry], [])[0]
  assert.deepEqual(serverListRoute(row, [entry])!.exit, { name: '198.51.100.10', host: '198.51.100.10', country: '' })
  entry.last_check_info = JSON.stringify({ manual_cascade: { transport: 'vless', exit_host: '198.51.100.10', exit_name: 'exit-external', exit_country: 'FI' } })
  row = serverListItems([entry], [])[0]
  assert.equal(serverListRoute(row, [entry])!.exit.name, 'exit-external')
})

test('standalone labels remain standalone; ambiguous same-country NAT is not promoted to a route', () => {
  const server = node(1, { country: 'RU', egress_ip: '198.51.100.1', egress_country: 'RU' })
  const row = serverListItems([server], [])[0]
  assert.equal(serverListRoute(row, [server]), null)
  server.last_check_info = '<invalid JSON>'
  assert.equal(serverListRoute(row, [server]), null)
})

test('descriptive suffixes yield space while simple and multiword labels stay complete', () => {
  assert.deepEqual(cascadeNameParts('entry-one - Country description'), { primary: 'entry-one', suffix: ' - Country description' })
  assert.deepEqual(cascadeNameParts('exit-two (clients)'), { primary: 'exit-two', suffix: ' (clients)' })
  assert.deepEqual(cascadeNameParts('Office West - Main'), { primary: 'Office West - Main', suffix: '' })
  assert.deepEqual(cascadeNameParts('entry-one'), { primary: 'entry-one', suffix: '' })
})

test('GRE plus AWG requires explicit runtime proof, not a configured label or a truthy value', () => {
  const server = node(1)
  assert.equal(greLinkLabel(server), 'GRE')
  for (const encrypted of [false, 'true', null]) {
    server.last_check_info = JSON.stringify({ cascade_link: { transport: 'awg', encrypted } })
    assert.equal(greLinkLabel(server), 'GRE')
  }
  server.last_check_info = JSON.stringify({ cascade_link: { transport: 'awg', encrypted: true } })
  assert.equal(greLinkLabel(server), 'GRE + AWG')
  server.last_check_info = JSON.stringify({ cascade_link: { transport: 'awg', encrypted: true, healthy: false, handshake_age: 900 } })
  assert.equal(greLinkLabel(server), 'GRE + AWG') // Availability does not relabel a bound crypto path as plaintext.
})

test('host-only edits omit unchanged nonempty exit aliases; changes and explicit clear still persist', () => {
  assert.equal(manualExitNameChange('exit-saved', 'exit-saved'), undefined)
  assert.equal(manualExitNameChange('  exit-saved  ', 'exit-saved'), undefined)
  assert.equal(manualExitNameChange('', ''), undefined)
  assert.equal(manualExitNameChange('exit-new', 'exit-saved'), 'exit-new')
  assert.equal(manualExitNameChange('', 'exit-saved'), '')
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
