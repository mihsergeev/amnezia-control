import assert from 'node:assert/strict'
import test from 'node:test'
import type { CascadeTransport, CascadeTransportProbe } from '../src/api.ts'
import { cascadeMeasurement, formatProbeMetric, probeRowTone, queuedProbeRows, runTransportProbes, testedAwgPorts } from '../src/cascadeUi.ts'

function result(transport: CascadeTransport, status: CascadeTransportProbe['status'] = 'ok'): CascadeTransportProbe {
  return { transport, measurement: transport, run_id: '0'.repeat(32), requested_bytes: 20971520,
    status, ok: status === 'unavailable' ? null : status === 'ok', bytes: status === 'ok' ? 20971520 : 0,
    secs: status === 'unavailable' ? null : 1, mbps: status === 'ok' ? 168 : null, error: '',
    entry_ip: '192.0.2.10', exit_ip: '198.51.100.20', exit_country: '', exit_org: '',
    entry_nat: false, exit_nat: false, checked_at: '', entry_port: 41001, exit_port: 41002 }
}
const errorText = (e: unknown) => e instanceof Error ? e.message : 'invalid response'
const tick = () => new Promise(resolve => setTimeout(resolve, 0))

test('short measurements retain useful precision without exposing raw float tails', () => {
  assert.equal(formatProbeMetric(0.123456789, 'en', 'secs'), '0.123')
  assert.equal(formatProbeMetric(23.139583593, 'en', 'mbps'), '23.1')
  assert.equal(formatProbeMetric(1364.0195, 'en', 'mbps'), '1,360')
  assert.equal(formatProbeMetric(0.0002, 'en', 'secs'), '<0.001')
  assert.equal(formatProbeMetric(0.03, 'en', 'mbps'), '<0.1')
  assert.equal(formatProbeMetric(0.123456789, 'ru', 'secs'), '0,123')
})

test('each transport result is published while later requests are still pending', async () => {
  const rows = queuedProbeRows(), calls: CascadeTransport[] = []
  const resolve: Partial<Record<CascadeTransport, (value: CascadeTransportProbe) => void>> = {}
  const run = runTransportProbes(kind => {
    calls.push(kind)
    return new Promise(done => { resolve[kind] = done })
  }, (kind, row) => { rows[kind] = row }, new AbortController().signal, errorText)
  assert.deepEqual(calls, ['awg']); assert.equal(rows.awg.state, 'running'); assert.equal(rows.vless.state, 'queued')
  resolve.awg!(result('awg')); await tick()
  assert.equal(rows.awg.state, 'done'); assert.equal(rows.vless.state, 'running'); assert.equal(rows.gre.state, 'queued')
  assert.deepEqual(calls, ['awg', 'vless'])
  resolve.vless!(result('vless')); await tick()
  assert.equal(rows.vless.state, 'done'); assert.equal(rows.gre.state, 'running')
  resolve.gre!(result('gre')); await run
  assert.deepEqual(calls, ['awg', 'vless', 'gre']); assert.equal(rows.gre.state, 'done')
})

test('unavailable stays neutral, measured failure is red, and another transport continues after HTTP failure', async () => {
  const rows = queuedProbeRows()
  await runTransportProbes(async kind => {
    if (kind === 'vless') throw new Error('network response unavailable')
    return result(kind, kind === 'awg' ? 'unavailable' : 'failed')
  }, (kind, row) => { rows[kind] = row }, new AbortController().signal, errorText)
  assert.equal(rows.awg.state, 'unavailable'); assert.equal(probeRowTone(rows.awg), 'muted')
  assert.equal(rows.vless.state, 'error'); assert.equal(rows.vless.error, 'network response unavailable')
  assert.equal(rows.gre.state, 'done'); assert.equal(probeRowTone(rows.gre), 'bad')
})

test('explicit image preparation reruns only its transport and keeps other results', async () => {
  const rows = queuedProbeRows()
  const awg = result('awg')
  const gre = result('gre', 'failed')
  rows.awg = { state: 'done', result: awg, error: '' }
  rows.vless = { state: 'unavailable', result: { ...result('vless', 'unavailable'), reason: 'local_image_missing' }, error: '' }
  rows.gre = { state: 'done', result: gre, error: '' }
  const calls: CascadeTransport[] = []
  let finish!: (value: CascadeTransportProbe) => void
  const run = runTransportProbes(kind => {
    calls.push(kind)
    return new Promise(resolve => { finish = resolve })
  }, (kind, row) => { rows[kind] = row }, new AbortController().signal, errorText, 'vless')

  assert.equal(rows.vless.state, 'preparing')
  assert.equal(rows.vless.result, null)
  assert.equal(probeRowTone(rows.vless), 'run')
  finish(result('vless'))
  await run

  assert.deepEqual(calls, ['vless'])
  assert.equal(probeRowTone(rows.vless), 'ok')
  assert.equal(rows.awg.result, awg)
  assert.equal(rows.gre.result, gre)
})

test('abort ignores a late response and prevents all subsequent requests', async () => {
  const controller = new AbortController(), events: string[] = [], calls: string[] = []
  let finish!: (value: CascadeTransportProbe) => void
  const run = runTransportProbes(kind => {
    calls.push(kind); return new Promise(resolve => { finish = resolve })
  }, (kind, row) => events.push(kind + ':' + row.state), controller.signal, errorText)
  controller.abort(); finish(result('awg')); await run
  assert.deepEqual(events, ['awg:running']); assert.deepEqual(calls, ['awg'])
})

test('a response for another measurement cannot turn the requested transport green', async () => {
  const rows = queuedProbeRows()
  await runTransportProbes(async kind => kind === 'awg' ? result('vless') : result(kind),
    (kind, row) => { rows[kind] = row }, new AbortController().signal, errorText)
  assert.equal(rows.awg.state, 'error'); assert.equal(rows.awg.result, null)
  assert.equal(probeRowTone(rows.vless), 'ok')
})

test('successful auto AWG ports are reused exactly; edits, failure and missing proof cannot reuse them', () => {
  const auto = { entry_port: null, exit_port: null }
  assert.deepEqual(testedAwgPorts(auto, result('awg')), { entry_port: 41001, exit_port: 41002 })
  assert.deepEqual(testedAwgPorts({ entry_port: 42001, exit_port: 42002 }, result('awg')), { entry_port: 42001, exit_port: 42002 })
  assert.deepEqual(testedAwgPorts(auto, null), auto)
  assert.deepEqual(testedAwgPorts(auto, result('awg', 'failed')), auto)
  assert.deepEqual(testedAwgPorts(auto, result('vless')), auto)
})

test('only the selected transport result controls its own connection color', () => {
  const rows = queuedProbeRows(); rows.vless = { state: 'done', result: result('vless'), error: '' }
  rows.gre = { state: 'done', result: result('gre', 'failed'), error: '' }
  assert.equal(probeRowTone(rows.awg), 'muted'); assert.equal(probeRowTone(rows.vless), 'ok'); assert.equal(probeRowTone(rows.gre), 'bad')
})

test('legacy TCP speed is labelled TCP, while a new VLESS measurement has its own provenance', () => {
  const tcp = { ok: true, bytes: 20971520, secs: 1, mbps: 168, error: '' }
  assert.deepEqual(cascadeMeasurement({ transport: 'vless', probe: { tcp } }), { label: 'TCP', mbps: 168 })
  assert.deepEqual(cascadeMeasurement({ transport: 'vless', probe: { tcp, vless: result('vless') } }), { label: 'VLESS', mbps: 168 })
  assert.equal(cascadeMeasurement({ transport: 'vless', probe: { tcp, vless: result('vless', 'failed') } }), null)
  assert.equal(cascadeMeasurement({ transport: 'awg', probe: { tcp } }), null)
})
