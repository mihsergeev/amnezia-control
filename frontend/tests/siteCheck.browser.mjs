// Real standalone modal and server menu, with synthetic API responses only.
import assert from 'node:assert/strict'
import { existsSync } from 'node:fs'
import { mkdir, writeFile } from 'node:fs/promises'
import { createServer } from 'vite'
import { chromium } from 'playwright'
const artifacts = process.env.CASCADE_TEST_ARTIFACTS || 'C:/tmp/acontrol-site-check-08447'
await mkdir(artifacts, { recursive: true })
const vite = await createServer({ server: { host: '127.0.0.1', port: 0 } })
await vite.listen()
const executablePath = process.env.CHROME_PATH || ['C:/Program Files/Google/Chrome/Application/chrome.exe', '/usr/bin/chromium', '/usr/bin/google-chrome'].find(existsSync)
const browser = await chromium.launch({ headless: true, ...(executablePath ? { executablePath } : {}) })
const errors = [], checks = []
const server = { id: 1, name: 'Test server', host: '192.0.2.10', country: 'RU', ssh_port: 22, ssh_user: 'service', note: '', group_name: '', position: 0, last_check_ok: true, last_check_info: '{}', last_check_at: '2026-01-01T00:00:00Z', alerts_enabled: false, torrent_block: false, torrent_autopause: false }
async function fixture(width = 1100, theme = 'dark', options = {}) {
  const page = await browser.newPage({ viewport: { width, height: 900 }, colorScheme: theme })
  page.setDefaultTimeout(10000)
  page.on('pageerror', (error) => errors.push(error.message))
  await page.addInitScript(({ theme, lang }) => { localStorage.setItem('acontrol_theme', theme); localStorage.setItem('acontrol_lang', lang) }, { theme, lang: options.lang || 'ru' })
  const calls = []
  const control = { delay: 0, status: 200, result: { status: 'response', http_status: 200 }, source: null }
  await page.route('**/api/**', async (route) => {
    const request = route.request(), path = new URL(request.url()).pathname, body = request.postDataJSON()
    calls.push({ method: request.method(), path, body })
    const fulfill = (data, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(data) }).catch((error) => { if (!page.isClosed()) throw error })
    if (path.endsWith('/site-check')) {
      const status = control.status, delay = control.delay
      const data = { source: control.source || { server_id: Number(path.split('/')[3]) }, results: [{ destination: body.destinations[0].toLowerCase(), scheme: body.scheme, timings_ms: { dns: 1.23, tcp: 4.56, tls: 8.9, total: 17.23 }, ...structuredClone(control.result) }], timeout_seconds: 3, budget_seconds: 12 }
      if (delay) await new Promise((resolve) => setTimeout(resolve, delay))
      if (page.isClosed()) return
      return fulfill(status === 200 ? data : { detail: 'Synthetic check failure' }, status)
    }
    if (path === '/api/servers') return fulfill([server])
    if (path === '/api/stats/overview') return fulfill({ per_server: [] })
    if (path === '/api/config') return fulfill({ default_ssh_user: 'service' })
    if (path.endsWith('/check')) return fulfill(server)
    return fulfill([])
  })
  await page.goto(`${vite.resolvedUrls.local[0]}tests/fixtures/site-check.html${options.menu ? '?page=1' : ''}`)
  if (!options.menu) await page.getByRole('dialog').waitFor()
  return { page, control, calls }
}
const input = (page) => page.getByRole('textbox', { name: 'Домен или IPv4', exact: true })
const submit = (page) => page.getByRole('button', { name: 'Проверить сайт', exact: true })
async function run(page, destination = 'example.com') { await input(page).fill(destination); await submit(page).click(); await page.locator('.site-check-output [data-http-status]').waitFor() }
try {
  {
    const { page, calls } = await fixture(1100, 'dark', { menu: true })
    await page.getByRole('button', { name: 'Проверить', exact: true }).waitFor()
    await page.getByRole('button', { name: 'Проверить', exact: true }).click()
    assert.equal(calls.filter(({ path }) => path === '/api/servers/1/check').length, 1, 'existing health action retains its original endpoint')
    await page.getByRole('button', { name: /^Ещё/ }).click()
    await page.getByRole('button', { name: 'Проверить сайт', exact: true }).click()
    await page.getByRole('dialog', { name: 'Проверить сайт' }).waitFor()
    await run(page)
    await page.locator('.cascade-route-http-success').waitFor()
    assert.equal(calls.filter(({ path }) => path.endsWith('/site-check')).length, 1)
    assert.equal(calls.filter(({ method, path }) => method !== 'GET' && !path.endsWith('/site-check') && !path.endsWith('/check')).length, 0)
    checks.push('actual ServersPage menu opens standalone check; existing health button endpoint preserved; no client or configuration mutations')
    await page.close()
  }
  {
    const { page, control, calls } = await fixture()
    control.delay = 180
    await input(page).fill('Example.com')
    await page.locator('form').evaluate((form) => { form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })); form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })) })
    await page.locator('.cascade-route-http-success').waitFor()
    assert.equal(calls.filter(({ path }) => path.endsWith('/site-check')).length, 1)
    assert.match(await page.locator('.site-check-result').textContent(), /HTTP 200HTTPS/)
    assert.match(await page.locator('.site-check-timings').textContent(), /DNS1.2 мсTCP4.6 мсTLS8.9 мсВсего17.2 мс/)
    assert.match(await page.locator('.site-check-source').textContent(), /Test server/)
    control.delay = 0
    for (const [result, expected] of [
      [{ status: 'response', http_status: 403 }, 'HTTP 403'],
      [{ status: 'timeout', reason: 'target_timeout' }, 'Таймаут ответа сайта'],
      [{ status: 'error', reason: 'dns_failed' }, 'Не удалось разрешить DNS-имя'],
      [{ status: 'error', reason: 'tls_error' }, 'Ошибка TLS'],
      [{ status: 'error', reason: 'connect_error' }, 'Не удалось установить TCP-соединение'],
      [{ status: 'node_unreachable', reason: 'node_unreachable' }, 'Сервер проверки недоступен по SSH'],
    ]) {
      control.result = result
      await submit(page).click()
      await page.locator('.cascade-route-http-error').filter({ hasText: expected }).waitFor()
    }
    assert.equal(calls.filter(({ path }) => path.endsWith('/site-check')).every(({ body }) => body.scheme === 'https'), true, 'TLS error never silently falls back to HTTP')
    await page.getByRole('combobox', { name: 'Протокол HTTP-проверки', exact: true }).selectOption('http')
    control.result = { status: 'response', http_status: 204 }
    await submit(page).click()
    await page.locator('.cascade-route-http-success').filter({ hasText: 'HTTP 204HTTP' }).waitFor()
    assert.equal(calls.filter(({ path }) => path.endsWith('/site-check')).at(-1).body.scheme, 'http')
    checks.push('exact status and stage timings; double-submit guard; HTTP403/timeouts/DNS/TLS/TCP/SSH distinct; protocol explicit without fallback')
    await page.close()
  }
  {
    const { page, control } = await fixture()
    control.delay = 650
    control.result = { status: 'response', http_status: 201 }
    await run(page, 'old.example')
    await input(page).fill('new.example')
    control.delay = 0
    control.result = { status: 'response', http_status: 403 }
    await submit(page).click()
    await page.locator('.cascade-route-http-error').filter({ hasText: 'HTTP 403' }).waitFor()
    await page.waitForTimeout(700)
    assert.doesNotMatch(await page.locator('.site-check-result').textContent(), /201/)
    await input(page).fill('keep.example')
    await page.evaluate(() => window.dispatchEvent(new Event('poll-server')))
    assert.equal(await input(page).inputValue(), 'keep.example', 'unrelated server polling preserves the input')
    control.delay = 600
    await submit(page).click()
    await page.evaluate(() => window.dispatchEvent(new Event('migrate-server')))
    assert.equal(await input(page).inputValue(), '')
    await page.waitForTimeout(650)
    assert.equal(await page.locator('.site-check-output').count(), 0, 'same-ID host/port migration rejects old source results')
    await input(page).fill('other.example')
    await submit(page).click()
    await page.evaluate(() => window.dispatchEvent(new Event('switch-server')))
    await page.waitForTimeout(650)
    assert.equal(await page.locator('.site-check-output').count(), 0)
    assert.match(await page.locator('.site-check-source').textContent(), /Other server/)
    checks.push('input, same-ID host/port migration and server switch invalidate stale checks; ordinary polling preserves input')
    await page.close()
  }
  {
    const { page, control } = await fixture()
    control.status = 401
    await run(page)
    await page.waitForFunction(() => document.querySelector('output').getAttribute('data-unauthorized') === '1')
    assert.equal(await input(page).inputValue(), 'example.com')
    control.status = 429
    await submit(page).click()
    await page.getByRole('alert').filter({ hasText: 'уже выполняется' }).waitFor()
    control.status = 200
    control.delay = 600
    await submit(page).click()
    await page.getByRole('button', { name: 'Закрыть', exact: true }).click()
    assert.equal(await page.getByRole('dialog').count(), 0)
    await page.waitForTimeout(650)
    checks.push('401 delegated; 429 readable and input preserved; pending readonly check can be closed')
    await page.close()
  }
  {
    const { page, control } = await fixture()
    control.source = { server_id: 999 }
    await input(page).fill('example.com')
    await submit(page).click()
    await page.getByRole('alert').filter({ hasText: 'Контекст HTTP-проверки изменился' }).waitFor()
    assert.equal(await page.locator('.cascade-route-http-success').count(), 0)
    control.source = null
    await submit(page).click()
    await page.locator('.cascade-route-http-success').waitFor()
    checks.push('standalone rejects mismatched server identity and allows a fresh check')
    await page.close()
  }
  {
    const { page } = await fixture(390, 'light', { lang: 'en' })
    await page.getByRole('textbox', { name: 'Domain or IPv4 address', exact: true }).fill('example.com')
    await page.getByRole('button', { name: 'Check website', exact: true }).click()
    await page.locator('.cascade-route-http-success').waitFor()
    assert.doesNotMatch(await page.getByRole('dialog').textContent(), /[а-яА-ЯёЁ]/)
    checks.push('standalone labels, explanation, result and timing units translated into English')
    await page.close()
  }
  for (const width of [320, 390, 1100]) for (const theme of ['light', 'dark']) {
    const { page, control } = await fixture(width, theme)
    control.result = { status: 'response', http_status: 403 }
    await run(page)
    await page.locator('.cascade-route-http-error').filter({ hasText: 'HTTP 403' }).waitFor()
    const layout = await page.evaluate(() => {
      const modal = document.querySelector('.site-check-modal'), rect = modal.getBoundingClientRect(), actions = modal.querySelector('.modal-actions').getBoundingClientRect()
      return { scroll: document.documentElement.scrollWidth, modalScroll: modal.scrollWidth, modalWidth: modal.clientWidth, top: rect.top, bottom: rect.bottom, actionsBottom: actions.bottom }
    })
    assert.ok(layout.scroll <= width && layout.modalScroll <= layout.modalWidth + 1 && layout.top >= 0 && layout.bottom <= 900 && layout.actionsBottom <= 900, `responsive ${width}/${theme}: ${JSON.stringify(layout)}`)
    await page.screenshot({ path: `${artifacts}/site-check-${width}-${theme}.png` })
    checks.push(`standalone ${width}px ${theme}: result, timings and actions fit viewport`)
    await page.close()
  }
  assert.deepEqual(errors, [])
  await writeFile(`${artifacts}/standalone-browser-results.json`, JSON.stringify({ checks, errors }, null, 2))
  console.log(`Website check browser tests passed (${checks.length}). Artifacts: ${artifacts}`)
} finally { await browser.close(); await vite.close() }
