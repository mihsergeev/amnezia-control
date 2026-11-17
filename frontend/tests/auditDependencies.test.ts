import assert from 'node:assert/strict'
import test from 'node:test'
import { evaluateNpmAudit } from '../scripts/audit-dependencies.mjs'

const advisory = {
  source: 1247710,
  url: 'https://github.com/advisories/GHSA-fc5q-39xc-vjpf',
  name: 'picomatch',
  dependency: 'picomatch',
  severity: 'high',
  range: '<=4.0.7',
}

const finding = (name: string, via: (string | typeof advisory)[], isDirect = false, severity = 'high') => ({
  name, severity, via, isDirect, range: '*', nodes: [`node_modules/${name}`],
})

const findings = [
  finding('picomatch', [advisory]),
  finding('fdir', ['picomatch']),
  finding('tinyglobby', ['fdir', 'picomatch']),
  finding('vite', ['tinyglobby', 'picomatch'], true),
  finding('@vitejs/plugin-react', ['vite'], true),
]

const lockfile = {
  lockfileVersion: 3,
  packages: {
    '': { devDependencies: { vite: '*', '@vitejs/plugin-react': '*' } },
    ...Object.fromEntries(findings.map(({ nodes: [node] }) => [node, { dev: true }])),
  },
}

function auditReport(entries: ReturnType<typeof finding>[] = []) {
  const counts = { info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: entries.length }
  for (const { severity } of entries) counts[severity as keyof typeof counts]++
  return {
    auditReportVersion: 2,
    vulnerabilities: Object.fromEntries(entries.map((entry) => [entry.name, entry])),
    metadata: { vulnerabilities: counts, dependencies: { total: 10 } },
  }
}

const audit = (entries: ReturnType<typeof finding>[] = []) => ({
  status: Number(entries.length > 0),
  stdout: JSON.stringify(auditReport(entries)),
})

test('clean audits pass without an exception', () => {
  assert.deepEqual(evaluateNpmAudit(audit(), audit(), lockfile), {
    fullExitCode: 0, productionExitCode: 0, fullVulnerabilities: 0, productionVulnerabilities: 0,
    acceptedAdvisory: null, exceptionDevOnly: null,
  })
})

test('the exact picomatch advisory and its build-only dependents pass with a visible exception', () => {
  assert.deepEqual(evaluateNpmAudit(audit(findings), audit(), lockfile), {
    fullExitCode: 1, productionExitCode: 0, fullVulnerabilities: 5, productionVulnerabilities: 0,
    acceptedAdvisory: 'GHSA-fc5q-39xc-vjpf', exceptionDevOnly: true,
  })
})

test('additional direct advisories on picomatch or a build dependent block the audit', () => {
  const other = { ...advisory, source: 1, url: 'https://example.com/advisory' }
  assert.throws(() => evaluateNpmAudit(audit([finding('picomatch', [advisory, other])]), audit(), lockfile),
    /Unexpected direct picomatch advisory/)
  assert.throws(() => evaluateNpmAudit(audit([...findings.slice(0, -1), finding('@vitejs/plugin-react', ['vite', other], true)]), audit(), lockfile),
    /outside the approved advisory chain/)
})

test('a changed advisory identity or affected range requires a fresh review', () => {
  for (const change of [{ source: 1 }, { url: 'https://example.com/advisory' }, { range: '<=4.1.0' }]) {
    assert.throws(() => evaluateNpmAudit(audit([finding('picomatch', [{ ...advisory, ...change }])]), audit(), lockfile),
      /Unexpected direct picomatch advisory/)
  }
})

test('another dependency or severity still fails, even when it mentions picomatch', () => {
  assert.throws(() => evaluateNpmAudit(audit([...findings, finding('example-tool', ['picomatch'], false, 'low')]), audit(), lockfile),
    /outside the build-only advisory exception/)
  assert.throws(() => evaluateNpmAudit(audit([finding('picomatch', [advisory], false, 'critical')]), audit(), lockfile),
    /outside the build-only advisory exception/)
})

test('missing and unapproved indirect causes cannot authorize a finding', () => {
  assert.throws(() => evaluateNpmAudit(audit(findings.slice(1)), audit(), lockfile), /outside the approved advisory chain/)
  assert.throws(() => evaluateNpmAudit(audit([findings[0], finding('fdir', ['fdir', 'picomatch'])]), audit(), lockfile),
    /outside the approved advisory chain/)
})

test('production findings block the audit even when they match the approved advisory', () => {
  assert.throws(() => evaluateNpmAudit(audit(findings), audit([findings[0]]), lockfile), /production dependencies/)
})

test('a runtime lock entry or another installed copy cannot use the exception', () => {
  const mixedLock = structuredClone(lockfile)
  mixedLock.packages['node_modules/picomatch'].dev = false
  assert.throws(() => evaluateNpmAudit(audit(findings), audit(), mixedLock), /outside the build-only advisory exception/)
  const nestedCopy = { ...findings[0], nodes: [...findings[0].nodes, 'node_modules/example-tool/node_modules/picomatch'] }
  assert.throws(() => evaluateNpmAudit(audit([nestedCopy, ...findings.slice(1)]), audit(), lockfile),
    /outside the build-only advisory exception/)
})

test('invalid JSON, incomplete reports and inconsistent counts or exits fail closed', () => {
  const badCounts = auditReport(findings)
  badCounts.metadata.vulnerabilities.high = 4
  for (const badResult of [
    { status: 0, stdout: '' },
    { status: 1, stdout: '{"auditReportVersion":2,' },
    { status: 0, stdout: '{}' },
    { status: 1, stdout: JSON.stringify(badCounts) },
    { ...audit(findings), status: 0 },
    { ...audit(), status: 1 },
  ]) {
    assert.throws(() => evaluateNpmAudit(badResult, audit(), lockfile), /npm audit full/)
  }
})

test('a registry error, process failure or timeout fails either audit', () => {
  for (const failure of [
    { status: 1, stdout: '{"error":{"code":"ECONNREFUSED"}}' },
    { ...audit(), status: 2 },
    { ...audit(), status: null, signal: 'SIGTERM' },
    { ...audit(), error: new Error('ETIMEDOUT') },
  ]) {
    assert.throws(() => evaluateNpmAudit(failure, audit(), lockfile), /npm audit full/)
    assert.throws(() => evaluateNpmAudit(audit(findings), failure, lockfile), /npm audit production/)
  }
})
