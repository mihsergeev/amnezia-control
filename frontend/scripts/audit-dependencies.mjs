import { spawnSync } from 'node:child_process'
import { readFileSync } from 'node:fs'

const advisory = 'GHSA-fc5q-39xc-vjpf'
const advisoryUrl = `https://github.com/advisories/${advisory}`

// The listed edges all terminate at the single approved picomatch advisory.
const buildCauses = new Map([
  ['picomatch', []],
  ['fdir', ['picomatch']],
  ['tinyglobby', ['fdir', 'picomatch']],
  ['vite', ['picomatch', 'tinyglobby']],
  ['@vitejs/plugin-react', ['vite']],
])
const severities = ['info', 'low', 'moderate', 'high', 'critical']
const isRecord = (value) => value !== null && typeof value === 'object' && !Array.isArray(value)

function readAudit(result, scope) {
  if (result.error || result.signal || ![0, 1].includes(result.status)) {
    throw new Error(`npm audit ${scope} did not complete successfully`)
  }

  let report
  try {
    report = JSON.parse(result.stdout)
  } catch {
    throw new Error(`npm audit ${scope} returned invalid JSON`)
  }
  if (!isRecord(report) || Object.hasOwn(report, 'error') || report.auditReportVersion !== 2 ||
      !isRecord(report.vulnerabilities) || !isRecord(report.metadata?.vulnerabilities) ||
      !Number.isSafeInteger(report.metadata?.dependencies?.total) || report.metadata.dependencies.total <= 0) {
    throw new Error(`npm audit ${scope} returned an invalid report`)
  }

  const findings = new Map(Object.entries(report.vulnerabilities))
  const counts = Object.fromEntries(severities.map((severity) => [severity, 0]))
  for (const [name, finding] of findings) {
    if (finding?.name !== name || !Object.hasOwn(counts, finding.severity) ||
        typeof finding.isDirect !== 'boolean' || typeof finding.range !== 'string' || !finding.range ||
        !Array.isArray(finding.nodes) || finding.nodes.length === 0 ||
        !Array.isArray(finding.via) || finding.via.length === 0) {
      throw new Error(`npm audit ${scope} returned an invalid finding`)
    }
    counts[finding.severity]++
  }
  if (report.metadata.vulnerabilities.total !== findings.size ||
      severities.some((severity) => report.metadata.vulnerabilities[severity] !== counts[severity]) ||
      result.status !== Number(findings.size > 0)) {
    throw new Error(`npm audit ${scope} exit code and finding counts are inconsistent`)
  }
  return findings
}

function checkBuildException(findings, lockfile) {
  // Each audited occurrence must be the expected top-level lockfile path and dev-only.
  const packages = lockfile?.packages
  const devDependencies = packages?.['']?.devDependencies
  if (lockfile?.lockfileVersion !== 3 || !isRecord(packages) || !isRecord(devDependencies)) {
    throw new Error('Cannot verify the build-only npm advisory against the lockfile')
  }

  for (const [name, finding] of findings) {
    const allowedCauses = buildCauses.get(name)
    const node = `node_modules/${name}`
    if (!allowedCauses || finding.severity !== 'high' || finding.nodes.length !== 1 ||
        finding.nodes[0] !== node || packages[node]?.dev !== true ||
        finding.isDirect !== Object.hasOwn(devDependencies, name)) {
      throw new Error(`npm finding outside the build-only advisory exception: ${name}`)
    }

    if (name === 'picomatch') {
      const [cause] = finding.via
      if (finding.isDirect || finding.via.length !== 1 || !isRecord(cause) ||
          cause.source !== 1247710 || cause.url !== advisoryUrl || cause.name !== name ||
          cause.dependency !== name || cause.severity !== 'high' || cause.range !== '<=4.0.7') {
        throw new Error('Unexpected direct picomatch advisory')
      }
    } else if (new Set(finding.via).size !== finding.via.length ||
        !finding.via.every((cause) => allowedCauses.includes(cause) && findings.has(cause))) {
      throw new Error(`npm finding has a cause outside the approved advisory chain: ${name}`)
    }
  }
}

export function evaluateNpmAudit(full, production, lockfile) {
  const fullFindings = readAudit(full, 'full')
  const productionFindings = readAudit(production, 'production')
  if (productionFindings.size > 0) {
    throw new Error('npm audit found vulnerabilities in production dependencies')
  }
  const hasException = fullFindings.size > 0
  if (hasException) checkBuildException(fullFindings, lockfile)

  return {
    fullExitCode: full.status,
    productionExitCode: production.status,
    fullVulnerabilities: fullFindings.size,
    productionVulnerabilities: productionFindings.size,
    acceptedAdvisory: hasException ? advisory : null,
    exceptionDevOnly: hasException ? true : null,
  }
}

function runAudit(npmPath, scope, devFlag) {
  const result = spawnSync(process.execPath, [npmPath, 'audit', '--json', '--audit-level=info',
    '--include=prod', '--include=optional', '--include=peer', devFlag], {
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
    timeout: 180_000,
  })
  if (result.stderr) process.stderr.write(result.stderr)
  console.log(`npm audit ${scope} report (exit ${result.status})`)
  if (result.stdout) process.stdout.write(result.stdout.endsWith('\n') ? result.stdout : `${result.stdout}\n`)
  console.log(`End npm audit ${scope} report`)
  return result
}

if (import.meta.main) {
  try {
    const npmPath = process.env.npm_execpath
    if (!npmPath) throw new Error('Run this check with npm run audit:ci')
    const lockfile = JSON.parse(readFileSync('package-lock.json', 'utf8'))
    const full = runAudit(npmPath, 'full', '--include=dev')
    const production = runAudit(npmPath, 'production', '--omit=dev')
    const summary = evaluateNpmAudit(full, production, lockfile)
    if (summary.acceptedAdvisory) {
      console.warn(`Warning: accepted build-only npm advisory ${advisory} (CVE-2026-112366). ${advisoryUrl}`)
    }
    console.log(`NPM_AUDIT_GATE ${JSON.stringify(summary)}`)
  } catch (error) {
    console.error(error.message)
    process.exitCode = 1
  }
}
