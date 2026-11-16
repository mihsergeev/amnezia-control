import assert from 'node:assert/strict'
import { existsSync } from 'node:fs'
import { createServer } from 'vite'
import { chromium } from 'playwright'

const server = await createServer({ server: { host: '127.0.0.1', port: 0 } })
await server.listen()
const executablePath = process.env.CHROME_PATH || ['C:/Program Files/Google/Chrome/Application/chrome.exe', '/usr/bin/chromium', '/usr/bin/google-chrome'].find(existsSync)
const browser = await chromium.launch({ headless: true, ...(executablePath ? { executablePath } : {}) })
const errors = []
async function fixture(protocol, mode = 'settings', lang = 'ru', width = 1100) {
  const page = await browser.newPage({ viewport: { width, height: 1000 } })
  page.on('pageerror', err => errors.push(err.message))
  await page.addInitScript(lang => localStorage.setItem('acontrol_lang', lang), lang)
  const params = { Jc: 5, Jmin: 10, Jmax: 50, S1: 16, S2: 16, S3: 16, S4: 16,
    H1: '10-20', H2: '30-40', H3: '50-60', H4: '70-80', I1: '<r 20>', I2: '', I3: '', I4: '', I5: '',
    ...(protocol === 'awg3' ? { HeaderProtectionKey: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', RandomTrailers: 'on', DisableCookies: 'on' } : {}) }
  const calls = [], controls = { fail: false }
  await page.route('**/api/**', async route => {
    const req = route.request(), path = new URL(req.url()).pathname
    calls.push({ path, method: req.method(), body: req.postDataJSON() })
    const fulfill = (value, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(value) })
    if (path.endsWith('/defaults')) return fulfill({ version: protocol === 'awg3' ? '3.1' : '2.0', params, supported_params: Object.keys(params) })
    if (path.endsWith('/deploy/status')) return fulfill({ state: 'done', log: 'Synthetic deployment completed' })
    if (req.method() === 'PUT' || req.method() === 'POST') {
      if (controls.fail) return fulfill({ detail: 'Настройки изменились; перечитайте их перед сохранением' }, 409)
      return fulfill({ changed: true }, mode === 'deploy' ? 202 : 200)
    }
    return fulfill({ version: protocol === 'awg3' ? '3.1' : '2.0', params, supported_params: Object.keys(params),
      port: 47300, subnet: '10.73.1.0/24', server_address: '10.73.1.1/24', revision: 'a'.repeat(64) })
  })
  await page.goto(`${server.resolvedUrls.local[0]}tests/fixtures/awg-settings.html?protocol=${protocol}&mode=${mode}`)
  return { page, calls, controls }
}
try {
  {
    const { page, calls } = await fixture('awg3', 'deploy')
    await page.getByRole('button', { name: 'Развернуть', exact: true }).waitFor()
    assert.equal(calls.length, 0, 'opening deployment must not mutate or generate advanced parameters')
    await page.getByRole('button', { name: 'Развернуть', exact: true }).click()
    await page.getByText('Synthetic deployment completed').waitFor()
    const body = calls.find(c => c.method === 'POST').body
    assert.equal(body.port, null); assert.equal(body.subnet, null); assert.equal(body.params, null)
    await page.close()
  }
  for (const protocol of ['awg', 'awg3']) {
    const { page, calls, controls } = await fixture(protocol, 'settings', 'en', 390)
    const apply = page.getByRole('button', { name: 'Apply settings', exact: true })
    await apply.waitFor(); assert.equal(await apply.isEnabled(), false)
    await page.getByText('Advanced AmneziaWG settings', { exact: true }).click()
    await page.getByLabel('Jc', { exact: true }).fill('7')
    assert.equal(await page.getByLabel('HeaderProtectionKey', { exact: true }).count(), protocol === 'awg3' ? 1 : 0)
    await page.getByLabel('UDP port', { exact: true }).fill('47500')
    await page.getByRole('checkbox').check()
    controls.fail = true; await apply.click()
    await page.getByText('Settings have changed; reload them before saving', { exact: true }).waitFor()
    assert.equal(await page.getByLabel('UDP port', { exact: true }).inputValue(), '47500')
    assert.equal(await page.getByLabel('Jc', { exact: true }).inputValue(), '7')
    controls.fail = false; await apply.click()
    await page.getByText('Settings saved. Download the existing profiles again; client keys have been preserved.').waitFor()
    const puts = calls.filter(c => c.method === 'PUT')
    assert.equal(puts.length, 2); assert.equal(puts[1].body.acknowledge_disconnect, true)
    assert.equal(puts[1].body.params.Jc, '7'); assert.equal(puts[1].body.port, 47500)
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true)
    await page.close()
  }
  assert.deepEqual(errors, [])
  console.log('PASS AWG settings: explicit auto deploy, version-specific advanced fields, acknowledgment, conflict retry, EN/mobile and key-preservation guidance')
} finally { await browser.close(); await server.close() }
