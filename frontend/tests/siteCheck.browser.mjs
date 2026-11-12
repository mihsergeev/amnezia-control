// Actual standalone modal and server menu; all API responses use synthetic fixtures.
import assert from 'node:assert/strict'
import { existsSync } from 'node:fs'
import { mkdir, writeFile } from 'node:fs/promises'
import { domainToASCII } from 'node:url'
import { createServer } from 'vite'
import { chromium } from 'playwright'
const artifacts = process.env.CASCADE_TEST_ARTIFACTS || 'C:/tmp/acontrol-site-check-08448'
await mkdir(artifacts, { recursive: true })
const vite = await createServer({ server: { host: '127.0.0.1', port: 0 } })
await vite.listen()
const executablePath = process.env.CHROME_PATH || ['C:/Program Files/Google/Chrome/Application/chrome.exe', '/usr/bin/chromium', '/usr/bin/google-chrome'].find(existsSync)
const browser = await chromium.launch({ headless: true, ...(executablePath ? { executablePath } : {}) })
const errors = [], checks = []
const server = { id: 1, name: 'Test server', host: '192.0.2.10', country: 'RU', ssh_port: 22, ssh_user: 'service', note: '', group_name: '', position: 0, last_check_ok: true, last_check_info: '{}', last_check_at: '2026-01-01T00:00:00Z', alerts_enabled: false, torrent_block: false, torrent_autopause: false }
// Fixture responses model server-owned canonicalization; browser URL is never used by the UI.
function canonical(raw) {
  const value = raw.trim(), match = value.match(/^([a-z][a-z0-9+.-]*):\/\//i)
  const scheme = match ? match[1].toLowerCase() : 'https'
  let host = match ? value.slice(match[0].length) : value
  if (host.endsWith('/')) host = host.slice(0, -1)
  if (!['https', 'http'].includes(scheme) || /[\s/@?#:\\]/u.test(host)) return { destination: null, scheme: null, status: 'invalid', reason: 'invalid_destination' }
  host = domainToASCII(host.toLowerCase().replaceAll('ß', 'ss').replaceAll('ς', 'σ')).replace(/\.+$/, '')
  if (!host || !host.includes('.') || !/^[a-z0-9.-]+$/.test(host)) return { destination: null, scheme: null, status: 'invalid', reason: 'invalid_destination' }
  return { destination: host, scheme }
}
async function fixture(width = 1100, theme = 'dark', options = {}) {
  const page = await browser.newPage({ viewport: { width, height: options.height || 900 }, colorScheme: theme })
  page.setDefaultTimeout(10000)
  page.on('pageerror', (error) => errors.push(error.message))
  await page.addInitScript(({ theme, lang }) => { localStorage.setItem('acontrol_theme', theme); localStorage.setItem('acontrol_lang', lang) }, { theme, lang: options.lang || 'ru' })
  const calls = []
  const control = { delay: 0, status: 200, result: { status: 'response', http_status: 200 }, results: {}, source: null }
  await page.route('**/api/**', async (route) => {
    const request = route.request(), path = new URL(request.url()).pathname, body = request.postDataJSON()
    calls.push({ method: request.method(), path, body })
    const fulfill = (data, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(data) }).catch((error) => { if (!page.isClosed()) throw error })
    if (path.endsWith('/site-check')) {
      const status = control.status, delay = control.delay
      const data = { source: control.source || { server_id: Number(path.split('/')[3]), via: null }, results: body.destinations.map((raw) => {
        const target = canonical(raw)
        return target.status === 'invalid' ? target : { ...target, timings_ms: { dns: 1.23, tcp: 4.56, tls: target.scheme === 'https' ? 8.9 : null, total: 17.23 }, ...structuredClone(control.results[`${target.scheme}://${target.destination}`] || control.result) }
      }), timeout_seconds: 3, budget_seconds: 12 }
      if (delay) await new Promise((resolve) => setTimeout(resolve, delay))
      if (page.isClosed()) return
      return fulfill(status === 200 ? data : { detail: 'Synthetic check failure' }, status)
    }
    if (path === '/api/servers') return fulfill([{ ...server, name: options.serverName || server.name }])
    if (path === '/api/stats/overview') return fulfill({ per_server: [] })
    if (path === '/api/config') return fulfill({ default_ssh_user: 'service' })
    if (path.endsWith('/check')) return fulfill(server)
    return fulfill([])
  })
  await page.goto(`${vite.resolvedUrls.local[0]}tests/fixtures/site-check.html${options.menu ? '?page=1' : ''}`)
  if (!options.menu) await page.getByRole('dialog').waitFor()
  return { page, control, calls }
}
const input = (page) => page.getByRole('textbox', { name: 'Адреса сайтов', exact: true })
const submit = (page) => page.locator('.site-check-footer button[type="submit"]')
const row = (page, line) => page.locator(`.site-check-row[data-line="${line}"]`)
const siteCalls = (calls) => calls.filter(({ path }) => path.endsWith('/site-check'))
async function run(page, text = 'example.com') { await input(page).fill(text); await submit(page).click(); await page.locator('.site-check-output').waitFor() }
async function finished(page) { await page.getByRole('status').filter({ hasText: 'Обработано:' }).waitFor() }
try {
  {
    const { page, calls } = await fixture(1100, 'dark', { menu: true })
    await page.getByRole('button', { name: 'Проверить', exact: true }).click()
    assert.equal(calls.filter(({ path }) => path === '/api/servers/1/check').length, 1, 'existing health action retains its original endpoint')
    await page.getByRole('button', { name: /^Ещё/ }).click()
    await page.getByRole('button', { name: 'Проверить сайты', exact: true }).click()
    await page.getByRole('dialog', { name: 'Проверка сайтов' }).waitFor()
    await run(page)
    await finished(page)
    assert.equal(await page.getByRole('combobox').count(), 0, 'no separate protocol selector')
    assert.equal(siteCalls(calls).length, 1)
    assert.equal('scheme' in siteCalls(calls)[0].body, false, 'mixed requests rely on per-line protocol and automatic HTTPS')
    assert.equal(calls.filter(({ method, path }) => method !== 'GET' && !path.endsWith('/site-check') && !path.endsWith('/check')).length, 0)
    checks.push('actual server menu opens plural batch check; health action unchanged; no selector or client/configuration mutations')
    await page.close()
  }
  {
    const { page, control, calls } = await fixture()
    control.results = { 'http://example.com': { status: 'response', http_status: 403 }, 'https://xn--bcher-kva.example': { status: 'response', http_status: 302 }, 'https://slow.example': { status: 'timeout', reason: 'target_timeout', timings_ms: { dns: 2, total: 3000 } } }
    const text = 'Example.com\nhttp://example.com/\nhttps://EXAMPLE.com/\nBÜCHER.example\nxn--bcher-kva.example\n\nbad.example/path\nhttps://reader@example.com\nhttps://example.com:443\n//example.com\nftp://example.com\nhttps://example.com?q=1\nhttps://example.com#part\nslow.example\nhttpſ://example.com'
    await run(page, text)
    await finished(page)
    assert.equal(await page.locator('.site-check-row').count(), 14)
    assert.equal(await row(page, 1).locator('.site-check-address').textContent(), 'https://example.com')
    assert.match(await row(page, 2).textContent(), /http:\/\/example.comHTTP 403/)
    assert.match(await row(page, 3).textContent(), /Повтор строки 1/)
    assert.match(await row(page, 5).textContent(), /Повтор строки 4/)
    assert.match(await row(page, 4).textContent(), /https:\/\/xn--bcher-kva.exampleHTTP 302/)
    for (const line of [7, 8, 9, 10, 11, 12, 13, 15]) assert.equal(await row(page, line).locator('[data-http-status]').getAttribute('data-http-status'), 'invalid')
    assert.equal(await input(page).inputValue(), text, 'checking retains the complete input and protocol order')
    assert.deepEqual(siteCalls(calls)[0].body.destinations, text.split('\n').filter(Boolean), 'one ordered request retains every original nonblank line')
    assert.equal(siteCalls(calls)[0].body.destinations.includes('https://reader@example.com'), true, 'invalid URL parts reach the server unchanged rather than silently disappearing')
    assert.equal(await page.locator('.site-check-timings:visible').count(), 0, 'details are collapsed initially')
    await page.screenshot({ path: `${artifacts}/batch-1100-dark-preview.png` })
    await row(page, 1).getByRole('button').count().then((n) => assert.equal(n, 0))
    await row(page, 1).locator('summary').click()
    assert.match(await row(page, 1).locator('.site-check-timings').textContent(), /DNS1.2 мсTCP4.6 мсTLS8.9 мсВсего17.2 мс/)
    assert.match(await row(page, 14).textContent(), /Таймаут ответа сайта/)
    checks.push('mixed HTTP/HTTPS, automatic HTTPS, server canonical IDNA duplicates, per-line rejected URL parts, original blank-line mapping and expandable timings')
    await page.close()
  }
  {
    const { page, control, calls } = await fixture()
    control.delay = 180
    await input(page).fill('Example.com')
    await page.locator('form').evaluate((form) => { form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })); form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })) })
    await finished(page)
    assert.equal(siteCalls(calls).length, 1)
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
      await row(page, 1).locator('.cascade-route-http-error').filter({ hasText: expected }).waitFor()
    }
    assert.equal(siteCalls(calls).every(({ body }) => body.destinations[0] === 'Example.com'), true, 'TLS failure never silently switches protocol')
    checks.push('synchronous double-submit guard; distinct HTTP403, destination timeout, DNS, TLS, TCP and SSH failures; no protocol fallback')
    await page.close()
  }
  {
    const { page, control, calls } = await fixture()
    control.results = { 'http://ok.example': { status: 'response', http_status: 403 }, 'https://queued.example': { status: 'not_checked', reason: 'batch_deadline' }, 'http://queued.example': { status: 'not_checked', reason: 'batch_deadline' } }
    await run(page, 'ok.example\nhttp://ok.example\nqueued.example\nhttps://QUEUED.example/\nhttp://queued.example')
    await finished(page)
    const retry = page.getByRole('button', { name: 'Повторить непроверенные (2)', exact: true })
    await retry.waitFor()
    control.status = 429
    await retry.click()
    await page.getByRole('alert').filter({ hasText: 'уже выполняется' }).waitFor()
    assert.match(await row(page, 1).textContent(), /HTTP 200/)
    assert.match(await row(page, 2).textContent(), /HTTP 403/)
    assert.equal(await retry.isEnabled(), true)
    control.status = 200
    control.delay = 180
    control.results = { 'https://queued.example': { status: 'response', http_status: 204 }, 'http://queued.example': { status: 'timeout', reason: 'target_timeout' } }
    await retry.evaluate((button) => { button.click(); button.click() })
    await row(page, 3).locator('[data-http-status="response"]').waitFor()
    assert.equal(siteCalls(calls).length, 3)
    assert.deepEqual(siteCalls(calls)[2].body.destinations, ['https://queued.example', 'http://queued.example'])
    assert.match(await row(page, 1).textContent(), /HTTP 200/)
    assert.match(await row(page, 2).textContent(), /HTTP 403/)
    assert.match(await row(page, 3).textContent(), /HTTP 204/)
    assert.match(await row(page, 4).textContent(), /Повтор строки 3/)
    assert.match(await row(page, 5).textContent(), /Таймаут ответа сайта/)
    assert.equal(await page.getByRole('button', { name: /^Повторить непроверенные/ }).count(), 0)
    checks.push('deadline subset retry keeps prior200/403, preserves duplicates and mixed schemes; failed retry retains state; double retry sends one request')
    await page.close()
  }
  {
    const { page, control } = await fixture()
    control.delay = 650
    control.result = { status: 'response', http_status: 201 }
    await run(page, 'old.example')
    await input(page).fill('http://new.example')
    control.delay = 0
    control.result = { status: 'response', http_status: 403 }
    await submit(page).click()
    await row(page, 1).locator('.cascade-route-http-error').filter({ hasText: 'HTTP 403' }).waitFor()
    await page.waitForTimeout(700)
    assert.doesNotMatch(await row(page, 1).textContent(), /201/)
    assert.match(await row(page, 1).textContent(), /http:\/\/new.example/)
    await input(page).fill('keep.example\nhttp://keep.example')
    await page.evaluate(() => window.dispatchEvent(new Event('poll-server')))
    assert.equal(await input(page).inputValue(), 'keep.example\nhttp://keep.example')
    control.delay = 600
    await submit(page).click()
    await page.evaluate(() => window.dispatchEvent(new Event('migrate-server')))
    await page.waitForFunction(() => document.querySelector('#site-check-addresses')?.value === '')
    assert.equal(await input(page).inputValue(), '')
    await page.waitForTimeout(650)
    assert.equal(await page.locator('.site-check-output').count(), 0)
    await input(page).fill('other.example')
    await submit(page).click()
    await page.evaluate(() => window.dispatchEvent(new Event('switch-server')))
    await page.waitForTimeout(650)
    assert.equal(await page.locator('.site-check-output').count(), 0)
    assert.match(await page.locator('.site-check-source').textContent(), /Other server/)
    checks.push('input/protocol edits and same-ID host/port migration/server switch reject stale results; ordinary polling preserves multiline draft')
    await page.close()
  }
  {
    const { page, control } = await fixture()
    control.status = 401
    await run(page)
    await page.waitForFunction(() => document.querySelector('output').getAttribute('data-unauthorized') === '1')
    assert.equal(await input(page).inputValue(), 'example.com')
    control.status = 200
    control.source = { server_id: 999 }
    await submit(page).click()
    await page.getByRole('alert').filter({ hasText: 'Контекст HTTP-проверки изменился' }).waitFor()
    assert.equal(await page.locator('.cascade-route-http-success').count(), 0)
    control.source = null
    control.delay = 600
    await submit(page).click()
    await page.getByRole('button', { name: 'Закрыть', exact: true }).click()
    assert.equal(await page.getByRole('dialog').count(), 0)
    await page.waitForTimeout(650)
    checks.push('401 delegated, input retained; mismatched source rejected; closing cancels readonly request')
    await page.close()
  }
  {
    const { page, calls } = await fixture()
    const hundred = Array.from({ length: 100 }, (_, n) => `site${n}.example`)
    await input(page).fill([...hundred, 'extra.example'].join('\n'))
    assert.equal(await submit(page).isDisabled(), true)
    await page.getByRole('alert').filter({ hasText: 'Лимит 100 строк' }).waitFor()
    assert.equal(siteCalls(calls).length, 0)
    await run(page, hundred.join('\n'))
    await finished(page)
    assert.equal(siteCalls(calls)[0].body.destinations.length, 100)
    assert.equal(await page.locator('.site-check-row').count(), 100)
    await run(page, 'a'.repeat(1025) + '\n\nexample.com')
    await finished(page)
    assert.match(await row(page, 1).textContent(), /Не больше 1024/)
    assert.deepEqual(siteCalls(calls).at(-1).body.destinations, ['example.com'])
    assert.match(await row(page, 3).textContent(), /HTTP 200/)
    await page.getByRole('button', { name: 'Очистить', exact: true }).click()
    assert.equal(await input(page).inputValue(), '')
    assert.equal(await page.locator('.site-check-output').count(), 0)
    checks.push('100-row bound without truncation, oversized invalid row retains identity while valid rows run, clear resets editor/results')
    await page.close()
  }
  {
    const { page, control, calls } = await fixture(390, 'light', { height: 520 })
    control.delay = 1000
    const text = 'example.com\nhttp://example.com\nqueued.example'
    await run(page, text)
    await page.getByRole('status').filter({ hasText: 'Проверка адресов: 3' }).waitFor()
    assert.equal(await page.locator('[data-http-status="checking"]').count(), 3)
    assert.equal(await input(page).isEditable(), true)
    assert.equal(await submit(page).isDisabled(), true)
    assert.equal(await page.getByRole('button', { name: 'Очистить', exact: true }).isEnabled(), true)
    assert.equal(await page.getByRole('button', { name: 'Закрыть', exact: true }).isEnabled(), true)
    const geometry = await page.evaluate(() => {
      const footer = document.querySelector('.site-check-footer').getBoundingClientRect(), body = document.querySelector('.site-check-body').getBoundingClientRect(), status = document.querySelector('.site-check-progress').getBoundingClientRect()
      const buttons = [...document.querySelectorAll('.site-check-footer button')].map((element) => { const rect = element.getBoundingClientRect(); return { left: rect.left, right: rect.right, top: rect.top, bottom: rect.bottom } })
      return { footerTop: footer.top, footerBottom: footer.bottom, bodyBottom: body.bottom, statusTop: status.top, statusBottom: status.bottom, scrollWidth: document.documentElement.scrollWidth, buttons }
    })
    assert.ok(geometry.bodyBottom <= geometry.footerTop && geometry.footerBottom <= 520 && geometry.statusTop >= geometry.footerTop && geometry.statusBottom <= 520 && geometry.scrollWidth <= 390, JSON.stringify(geometry))
    for (const button of geometry.buttons) assert.ok(button.left >= 0 && button.right <= 390 && button.top >= 0 && button.bottom <= 520)
    await page.screenshot({ path: `${artifacts}/batch-390-light-pending-short.png` })
    await finished(page)
    assert.deepEqual(siteCalls(calls)[0].body.destinations, text.split('\n'))
    assert.equal(await input(page).inputValue(), text)
    checks.push('visible per-row pending and count on390x520; editor/clear/close usable; footer/progress/actions remain inside viewport; protocol/input order preserved')
    await page.close()
  }
  {
    const { page } = await fixture(390, 'light', { lang: 'en' })
    await page.getByRole('textbox', { name: 'Website addresses', exact: true }).fill('example.com\nhttp://example.com')
    await page.getByRole('button', { name: 'Check list', exact: true }).click()
    await page.locator('.cascade-route-http-success').first().waitFor()
    assert.doesNotMatch(await page.getByRole('dialog').textContent(), /[а-яА-ЯёЁ]/)
    checks.push('batch editor, counts, URL rows and actions translated into English')
    await page.close()
  }
  {
    const name = 'SyntheticServerNameWithoutAnySpaces'.repeat(4)
    const { page } = await fixture(320, 'light', { menu: true, serverName: name })
    await page.getByRole('button', { name: /^Ещё/ }).click()
    await page.getByRole('button', { name: 'Проверить сайты', exact: true }).click()
    await page.getByRole('dialog').waitFor()
    await page.locator('.site-check-modal').evaluate(async (modal) => { await Promise.all([...modal.getAnimations(), ...modal.parentElement.getAnimations()].map((animation) => animation.finished)) })
    assert.match(await page.locator('.site-check-source').textContent(), new RegExp(name))
    const layout = await page.evaluate(() => {
      const modal = document.querySelector('.site-check-modal'), source = modal.querySelector('.site-check-source').getBoundingClientRect(), footer = modal.querySelector('.site-check-footer').getBoundingClientRect()
      return { scroll: document.documentElement.scrollWidth, modalScroll: modal.scrollWidth, modalWidth: modal.clientWidth, sourceLeft: source.left, sourceRight: source.right, footerBottom: footer.bottom }
    })
    assert.ok(layout.scroll <= 320 && layout.modalScroll <= layout.modalWidth + 1 && layout.sourceLeft >= 0 && layout.sourceRight <= 320 && layout.footerBottom <= 900, JSON.stringify(layout))
    await page.screenshot({ path: `${artifacts}/batch-320-light-long-source.png` })
    checks.push('320px long unbroken live server name wraps within source header without horizontal overflow or hidden footer')
    await page.close()
  }
  for (const width of [320, 390, 1100]) for (const theme of ['light', 'dark']) {
    const { page, control } = await fixture(width, theme)
    control.results = { 'http://example.com': { status: 'response', http_status: 403 }, 'https://slow.example': { status: 'timeout', reason: 'target_timeout', timings_ms: { dns: 2, total: 3000 } } }
    await run(page, 'example.com\nhttp://example.com\nhttps://EXAMPLE.com/\nslow.example\nhttps://reader@example.com\nlast.example')
    await finished(page)
    const layout = await page.evaluate(() => {
      const modal = document.querySelector('.site-check-modal'), rect = modal.getBoundingClientRect(), actions = modal.querySelector('.site-check-footer').getBoundingClientRect(), body = modal.querySelector('.site-check-body').getBoundingClientRect(), head = modal.querySelector('.clients-head').getBoundingClientRect()
      return { scroll: document.documentElement.scrollWidth, modalScroll: modal.scrollWidth, modalWidth: modal.clientWidth, top: rect.top, bottom: rect.bottom, footerTop: actions.top, footerBottom: actions.bottom, bodyBottom: body.bottom, headerTop: head.top, rows: [...modal.querySelectorAll('.site-check-row')].map((r) => r.getBoundingClientRect().height) }
    })
    assert.ok(layout.scroll <= width && layout.modalScroll <= layout.modalWidth + 1 && layout.top >= 0 && layout.bottom <= 900 && layout.footerBottom <= 900 && layout.bodyBottom <= layout.footerTop && layout.headerTop >= 0, `responsive ${width}/${theme}: ${JSON.stringify(layout)}`)
    assert.ok(Math.max(...layout.rows) < (width < 620 ? 145 : 85), `compact rows ${width}/${theme}: ${JSON.stringify(layout.rows)}`)
    await page.screenshot({ path: `${artifacts}/batch-${width}-${theme}.png` })
    await row(page, 1).locator('summary').click()
    await page.screenshot({ path: `${artifacts}/batch-${width}-${theme}-details.png` })
    checks.push(`batch ${width}px ${theme}: compact rows, no overflow, pinned source/header/actions, expandable timings`)
    await page.close()
  }
  assert.deepEqual(errors, [])
  await writeFile(`${artifacts}/standalone-browser-results.json`, JSON.stringify({ checks, errors }, null, 2))
  console.log(`Website batch browser tests passed (${checks.length}). Artifacts: ${artifacts}`)
} finally { await browser.close(); await vite.close() }
