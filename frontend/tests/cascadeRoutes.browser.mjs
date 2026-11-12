// Exercises the real route editor with a synthetic, in-memory API; no gateway is contacted.
import assert from 'node:assert/strict'
import { existsSync } from 'node:fs'
import { mkdir, writeFile } from 'node:fs/promises'
import { createServer } from 'vite'
import { chromium } from 'playwright'
const artifacts = process.env.CASCADE_TEST_ARTIFACTS || 'C:/tmp/acontrol-cascade-batch-08446'
await mkdir(artifacts, { recursive: true })
const server = await createServer({ server: { host: '127.0.0.1', port: 0 } })
await server.listen()
const executablePath = process.env.CHROME_PATH || ['C:/Program Files/Google/Chrome/Application/chrome.exe', '/usr/bin/chromium', '/usr/bin/google-chrome'].find(existsSync)
const browser = await chromium.launch({ headless: true, ...(executablePath ? { executablePath } : {}) })
const errors = []
const checks = []
// The server validator has separate Python tests. These responses model its canonical contract,
// including outputs where Python IDNA2003 differs from browser URL processing.
function canonical(raw) {
  const value = raw.trim().replace(/\.+$/, '').toLowerCase()
  const known = { 'faß.example': 'fass.example', 'bücher.example': 'xn--bcher-kva.example' }
  if (value === 'api.ipify.org') return { valid: false, error: 'reserved_destination' }
  if (known[value]) return { valid: true, destination: known[value] }
  if (value === '192.0.2.0/24') return { valid: true, destination: value }
  if (/^[a-z][a-z0-9.-]*\.[a-z]+$/.test(value)) return { valid: true, destination: value }
  return { valid: false, error: 'invalid_destination' }
}
async function fixture(count = 16, width = 1100, theme = 'dark', language = 'ru') {
  const page = await browser.newPage({ viewport: { width, height: 900 }, colorScheme: theme })
  page.setDefaultTimeout(10000)
  page.on('pageerror', (error) => errors.push(error.message))
  await page.addInitScript(({ theme, language }) => { localStorage.setItem('acontrol_lang', language); localStorage.setItem('acontrol_theme', theme) }, { theme, language })
  const calls = []
  const control = { saveStatus: 200, previewStatus: 200, saveDelay: 0, previewDelay: 0 }
  await page.route('**/api/cascades/**', async (route) => {
    const request = route.request()
    const body = request.postDataJSON()
    const path = new URL(request.url()).pathname
    calls.push({ path, method: request.method(), body })
    const preview = path.endsWith('/preview')
    const status = preview ? control.previewStatus : control.saveStatus
    const delay = preview ? control.previewDelay : control.saveDelay
    if (delay) await new Promise((resolve) => setTimeout(resolve, delay))
    const data = status === 200 ? preview ? { results: body.destinations.map(canonical) } : { id: Number(path.split('/')[3]), entry_server_id: 1, exit_server_id: 2, entry_ip: '192.0.2.10', exit_ip: '198.51.100.20', routes: body.routes } : { detail: 'Synthetic route failure' }
    await route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(data) })
  })
  await page.goto(`${server.resolvedUrls.local[0]}tests/fixtures/cascade-routes.html?count=${count}`)
  await page.getByRole('dialog').waitFor()
  return { page, calls, control }
}
const rowList = (page) => page.locator('.cascade-route-row')
const save = (page) => page.getByRole('button', { name: 'Сохранить', exact: true })
const input = (page) => page.getByRole('textbox', { name: 'По одному адресу на строку', exact: true })
async function validate(page, text) { await input(page).fill(text); await page.getByRole('button', { name: 'Проверить адреса', exact: true }).click(); await page.locator('.cascade-route-preview').waitFor() }
async function agree(page, action) { page.once('dialog', (dialog) => dialog.accept()); await action() }
async function waitAttribute(page, name, value) { await page.waitForFunction(({ name, value }) => document.querySelector('output')?.getAttribute(name) === value, { name, value }) }
try {
  {
    const { page, calls, control } = await fixture()
    assert.equal(await rowList(page).count(), 16)
    assert.equal(await save(page).isDisabled(), true)
    assert.equal(calls.length, 0, 'opening a draft must not call the API')
    assert.equal(await page.locator('.cascade-route-node').count(), 2)
    assert.equal(await page.getByText('Entry server', { exact: false }).count(), 1)
    await page.getByRole('checkbox', { name: 'Выбрать правило 1', exact: true }).check()
    await page.getByRole('checkbox', { name: 'Выбрать правило 2', exact: true }).check()
    await page.getByRole('searchbox', { name: 'Поиск по адресу' }).fill('r16.')
    assert.equal(await rowList(page).count(), 1)
    assert.equal(await rowList(page).first().getAttribute('data-priority'), '16')
    assert.match(await page.locator('.cascade-route-selection').textContent(), /Выбрано: 2, скрыто поиском: 2/)
    await page.getByRole('combobox', { name: 'Направление выбранных', exact: true }).selectOption('exit')
    await page.getByRole('button', { name: 'Применить к 2', exact: true }).click()
    await page.getByRole('button', { name: 'Снять выбор', exact: true }).click()
    await page.getByRole('searchbox', { name: 'Поиск по адресу' }).fill('')
    assert.equal(await page.getByRole('combobox', { name: 'Направление правила 1', exact: true }).inputValue(), 'exit')
    await page.getByRole('button', { name: 'Редактировать правило 2', exact: true }).click()
    await page.getByRole('textbox', { name: 'Домен, IPv4 или подсеть', exact: true }).fill('BÜCHER.example.')
    await page.getByRole('spinbutton', { name: 'Приоритет', exact: true }).fill('1')
    await page.getByRole('button', { name: 'Применить правило', exact: true }).click()
    await page.locator('.cascade-route-editor').waitFor({ state: 'hidden' })
    assert.match(await rowList(page).first().textContent(), /xn--bcher-kva.example/)
    await page.getByRole('button', { name: 'Удалить правило 16', exact: true }).click()
    assert.equal(await rowList(page).count(), 15)
    await validate(page, ' New.Example.com. \nr3.example.com\nbad address\nNEW.EXAMPLE.COM\nchild.r1.example.com\n192.0.2.0/24\n192.0.2.1/24\napi.ipify.org\nfaß.example')
    assert.match(await page.locator('.cascade-route-preview').textContent(), /К добавлению: 4, пропущено: 5/)
    assert.match(await page.locator('.cascade-route-preview').textContent(), /Пересекается с правилом/)
    assert.equal(await page.locator('.cascade-route-preview li').count(), 9)
    await page.getByRole('button', { name: 'Добавить 4', exact: true }).click()
    assert.equal(await rowList(page).count(), 19)
    assert.match(await page.locator('.cascade-route-preview').textContent(), /Пропуск: неверный/)
    assert.equal(await save(page).isEnabled(), true, 'adding valid addresses leaves a direct save path and a read-only skip report')
    assert.equal(await input(page).inputValue(), '')
    await page.getByRole('checkbox', { name: 'Выбрать правило 1', exact: true }).check()
    control.saveStatus = 500
    await agree(page, () => save(page).click())
    await page.getByRole('alert').filter({ hasText: 'Synthetic route failure' }).waitFor()
    assert.equal(await rowList(page).count(), 19)
    assert.equal(await page.getByRole('checkbox', { name: 'Выбрать правило 1', exact: true }).isChecked(), true)
    control.saveStatus = 200
    control.saveDelay = 500
    await agree(page, async () => page.locator('form').evaluate((form) => { form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })); form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })) }))
    await waitAttribute(page, 'data-saved', '1')
    const puts = calls.filter(({ method }) => method === 'PUT')
    assert.equal(puts.length, 2, 'one failed request and one retry despite double submit')
    assert.equal(puts[1].body.routes.length, 19)
    assert.deepEqual(puts[1].body.routes.slice(-4), [
      { destination: 'new.example.com', via: 'exit' }, { destination: 'child.r1.example.com', via: 'exit' },
      { destination: '192.0.2.0/24', via: 'exit' }, { destination: 'fass.example', via: 'exit' },
    ])
    assert.equal(puts[1].body.routes[0].destination, 'xn--bcher-kva.example')
    assert.equal(puts[1].body.routes[1].destination, 'r1.example.com')
    checks.push('16-rule list; global search priorities; hidden selection; bulk direction; normalized edit/reorder/delete; canonical batch statuses/overlap; atomic PUT; failure preservation and double-submit guard')
    await page.close()
  }
  {
    const { page, calls } = await fixture(99)
    await validate(page, 'one.example\ntwo.example')
    assert.equal(await page.getByRole('button', { name: 'Добавить 2', exact: true }).isDisabled(), true)
    assert.match(await page.locator('.cascade-route-preview').textContent(), /Лимит 100 правил. Свободно: 1/)
    assert.equal(await rowList(page).count(), 99)
    await validate(page, 'one.example')
    await page.getByRole('button', { name: 'Добавить 1', exact: true }).click()
    assert.equal(await rowList(page).count(), 100)
    assert.equal(await page.getByRole('button', { name: 'Добавить правило', exact: true }).isDisabled(), true)
    assert.equal(calls.filter(({ method }) => method === 'PUT').length, 0)
    checks.push('100-rule cap refuses whole oversized batch and accepts exactly one available slot')
    await page.close()
  }
  {
    const { page, calls, control } = await fixture()
    control.previewDelay = 500
    await input(page).fill('old.example')
    await page.getByRole('button', { name: 'Проверить адреса', exact: true }).click()
    await input(page).fill('new.example')
    await page.getByRole('button', { name: 'Проверить адреса', exact: true }).waitFor()
    await page.waitForTimeout(600)
    assert.equal(await page.locator('.cascade-route-preview').count(), 0, 'stale preview never validates changed text')
    control.previewStatus = 500
    control.previewDelay = 0
    await page.getByRole('button', { name: 'Проверить адреса', exact: true }).click()
    await page.getByRole('alert').waitFor()
    assert.equal(await input(page).inputValue(), 'new.example')
    control.previewStatus = 401
    await page.getByRole('button', { name: 'Проверить адреса', exact: true }).click()
    await waitAttribute(page, 'data-unauthorized', '1')
    control.previewStatus = 200
    await page.getByRole('button', { name: 'Очистить ввод', exact: true }).click()
    await page.getByRole('combobox', { name: 'Направление правила 1', exact: true }).selectOption('exit')
    control.saveDelay = 500
    await agree(page, () => save(page).click())
    await page.evaluate(() => window.dispatchEvent(new Event('switch-cascade')))
    await waitAttribute(page, 'data-cascade', '2')
    await page.waitForTimeout(650)
    assert.equal(await page.locator('output').getAttribute('data-saved'), '0', 'stale save must not replace a different cascade')
    assert.equal(await page.getByRole('combobox', { name: 'Направление правила 1', exact: true }).inputValue(), 'entry')
    assert.equal(await save(page).isDisabled(), true)
    assert.equal(calls.filter(({ method }) => method === 'PUT').length, 1)
    checks.push('stale preview ignored; validation failure preserves input; preview 401 delegated; cascade identity reset ignores stale save')
    await page.close()
  }
  {
    const { page, control } = await fixture()
    await page.getByRole('combobox', { name: 'Направление правила 1', exact: true }).selectOption('exit')
    page.once('dialog', (dialog) => dialog.dismiss())
    await page.getByRole('button', { name: 'Закрыть', exact: true }).click()
    assert.equal(await page.getByRole('dialog').count(), 1)
    page.once('dialog', (dialog) => dialog.dismiss())
    await page.keyboard.press('Escape')
    assert.equal(await page.getByRole('dialog').count(), 1)
    control.saveStatus = 401
    await agree(page, () => save(page).click())
    await waitAttribute(page, 'data-unauthorized', '1')
    await agree(page, () => page.getByRole('button', { name: 'Отменить изменения', exact: true }).click())
    assert.equal(await save(page).isDisabled(), true)
    assert.equal(await page.getByRole('combobox', { name: 'Направление правила 1', exact: true }).inputValue(), 'entry')
    await page.getByRole('button', { name: 'Закрыть', exact: true }).click()
    assert.equal(await page.getByRole('dialog').count(), 0)
    checks.push('close/Escape unsaved confirmation; save 401 delegated; cancel restores original draft; no-op save disabled')
    await page.close()
  }
  {
    const { page } = await fixture(0, 320, 'light')
    await page.getByRole('button', { name: 'Добавить правило', exact: true }).click()
    await page.getByRole('textbox', { name: 'Домен, IPv4 или подсеть', exact: true }).fill('BÜCHER.example.')
    await page.getByRole('button', { name: 'Применить правило', exact: true }).click()
    await page.locator('.cascade-route-editor').waitFor({ state: 'hidden' })
    assert.equal(await rowList(page).count(), 1)
    assert.match(await rowList(page).first().textContent(), /xn--bcher-kva.example/)
    await page.getByRole('button', { name: 'Редактировать правило 1', exact: true }).click()
    assert.equal(await page.getByRole('combobox', { name: 'Направление правила 1', exact: true }).isDisabled(), true, 'concurrent row edits are blocked')
    await page.getByRole('textbox', { name: 'Домен, IPv4 или подсеть', exact: true }).fill('api.ipify.org')
    await page.getByRole('button', { name: 'Применить правило', exact: true }).click()
    await page.getByRole('alert').filter({ hasText: 'зарезервирован' }).waitFor()
    await page.getByRole('textbox', { name: 'Домен, IPv4 или подсеть', exact: true }).fill('new.example')
    await page.getByRole('spinbutton', { name: 'Приоритет', exact: true }).fill('0')
    await page.getByRole('button', { name: 'Применить правило', exact: true }).click()
    await page.getByRole('alert').filter({ hasText: 'Укажите приоритет' }).waitFor()
    await page.getByRole('button', { name: 'Отмена', exact: true }).click()
    assert.equal(await page.getByRole('combobox', { name: 'Направление правила 1', exact: true }).isEnabled(), true)
    checks.push('320px single add/edit; server canonical IDN; reserved/priority rejection; competing row mutations disabled')
    await page.close()
  }
  {
    const { page, control } = await fixture()
    await page.getByRole('combobox', { name: 'Направление правила 1', exact: true }).selectOption('exit')
    await page.evaluate(() => window.dispatchEvent(new Event('poll-routes')))
    assert.equal(await rowList(page).count(), 16, 'polling route props must not discard a draft')
    control.saveDelay = 500
    await agree(page, () => save(page).click())
    await page.evaluate(() => window.dispatchEvent(new Event('switch-endpoint')))
    await page.waitForTimeout(650)
    assert.equal(await page.locator('output').getAttribute('data-saved'), '0', 'same-ID endpoint/transport change ignores stale save')
    assert.equal(await page.getByRole('combobox', { name: 'Направление правила 1', exact: true }).inputValue(), 'entry')
    checks.push('route polling preserves draft; same-ID gateway address/transport change resets context and ignores stale save')
    await page.close()
  }
  {
    const { page } = await fixture(16, 390, 'light', 'en')
    await page.getByRole('heading', { name: 'Cascade routes', exact: true }).waitFor()
    await page.getByRole('textbox', { name: 'One address per line', exact: true }).fill('new.example\nbad address')
    await page.getByRole('button', { name: 'Validate addresses', exact: true }).click()
    await page.locator('.cascade-route-preview').waitFor()
    assert.doesNotMatch(await page.getByRole('dialog').textContent(), /[а-яА-ЯёЁ]/)
    await page.screenshot({ path: `${artifacts}/routes-390-light-en.png` })
    checks.push('English UI has translated labels, preview statuses and actions')
    await page.close()
  }
  for (const width of [320, 390, 1100]) for (const theme of ['light', 'dark']) {
    const { page } = await fixture(16, width, theme)
    await page.screenshot({ path: `${artifacts}/routes-${width}-${theme}-initial.png` })
    await validate(page, 'new.example\nbad address\nchild.r1.example.com')
    assert.equal(await page.getByRole('dialog').getByRole('status').textContent(), 'Есть незавершенный ввод')
    const layout = await page.evaluate(() => {
      const modal = document.querySelector('.cascade-routes-modal')
      const footer = document.querySelector('.cascade-route-footer').getBoundingClientRect()
      const body = document.querySelector('.cascade-routes-scroll').getBoundingClientRect()
      const header = document.querySelector('.clients-head').getBoundingClientRect()
      const buttons = [...document.querySelectorAll('.cascade-route-footer button')].map((button) => button.getBoundingClientRect())
      return { viewport: innerWidth, scroll: document.documentElement.scrollWidth, modalScroll: modal.scrollWidth, modalWidth: modal.clientWidth, bodyBottom: body.bottom, headerTop: header.top, footerTop: footer.top, footerBottom: footer.bottom, height: innerHeight, buttons: buttons.map(({ x, right, y, bottom }) => ({ x, right, y, bottom })) }
    })
    assert.ok(layout.scroll <= width && layout.modalScroll <= layout.modalWidth + 1, `no horizontal overflow ${width}/${theme}: ${JSON.stringify(layout)}`)
    assert.ok(layout.bodyBottom <= layout.footerTop + 1 && layout.headerTop >= 0, `scroll body respects header/footer ${width}/${theme}: ${JSON.stringify(layout)}`)
    assert.ok(layout.footerTop >= 0 && layout.footerBottom <= layout.height + 1, `footer visible ${width}/${theme}`)
    for (const button of layout.buttons) assert.ok(button.x >= 0 && button.right <= width && button.y >= 0 && button.bottom <= 900)
    await page.screenshot({ path: `${artifacts}/routes-${width}-${theme}.png` })
    checks.push(`responsive ${width}px ${theme}: no overflow; footer and save/cancel visible`)
    await page.close()
  }
  assert.deepEqual(errors, [])
  await writeFile(`${artifacts}/browser-results.json`, JSON.stringify({ checks, errors }, null, 2))
  console.log(`Cascade routes browser checks passed (${checks.length}). Artifacts: ${artifacts}`)
} finally { await browser.close(); await server.close() }

