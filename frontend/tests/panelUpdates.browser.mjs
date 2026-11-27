import assert from 'node:assert/strict'
import { existsSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { chromium } from 'playwright'
import { createServer } from 'vite'

const root = fileURLToPath(new URL('..', import.meta.url))
const vite = await createServer({ root, server: { host: '127.0.0.1', port: 0, hmr: false } })
await vite.listen()
const executablePath = process.env.CHROME_PATH || [
  'C:/Program Files/Google/Chrome/Application/chrome.exe', '/usr/bin/chromium', '/usr/bin/google-chrome',
].find(existsSync)
const browser = await chromium.launch({ headless: true, ...(executablePath ? { executablePath } : {}) })

const project = 'https://github.com/mihsergeev/amnezia-control'
const available = {
  current_version: '1.2.3',
  latest_version: 'v1.3.0',
  release_url: project + '/releases/tag/v1.3.0',
  status: 'available',
  checked_at: '2026-11-27T09:30:00Z',
  stale: false,
}
const page = await browser.newPage({ viewport: { width: 1280, height: 860 } })
page.setDefaultTimeout(8_000)
const calls = []
const pageErrors = []
page.on('pageerror', (error) => pageErrors.push(error.message))
await page.addInitScript(() => localStorage.setItem('acontrol_lang', 'ru'))
let automatic = available
let manual = available
let manualStatus = 200
let manualGate

try {
  await page.route('**/api/**', async (route) => {
    const request = route.request()
    const path = new URL(request.url()).pathname
    if (path === '/api/updates' || path === '/api/updates/check') {
      const requestHeaders = await request.allHeaders()
      calls.push({ method: request.method(), path, authorization: requestHeaders.authorization })
      if (path === '/api/updates') return route.fulfill({ json: automatic })
      await manualGate?.promise
      return route.fulfill({ status: manualStatus, json: manual })
    }
    if (path === '/api/auth/login') return route.fulfill({ json: { access_token: 'panel-test-token' } })
    if (path === '/api/branding') return route.fulfill({ json: { version: null, header_title: 'Test panel' } })
    if (path === '/api/config') return route.fulfill({ json: { version: '1.2.3' } })
    if (['/api/servers', '/api/cascades', '/api/stats/nodes'].includes(path)) return route.fulfill({ json: [] })
    return route.fulfill({ json: { per_server: [] } })
  })

  await page.goto(vite.resolvedUrls.local[0])
  await page.getByRole('heading', { name: 'Вход в панель' }).waitFor()
  assert.deepEqual(calls, [])
  await page.getByLabel('Логин', { exact: true }).fill('admin')
  await page.getByLabel('Пароль', { exact: true }).fill('test')

  const menu = page.getByRole('button', { name: 'Меню', exact: true })
  const dialog = page.getByRole('dialog', { name: 'Обновления', exact: true })
  const check = dialog.getByRole('button', { name: 'Проверить', exact: true })
  const open = async () => {
    await menu.click()
    await page.getByRole('button', { name: 'Обновления', exact: true }).click()
    await dialog.waitFor()
  }

  await page.getByRole('button', { name: 'Войти', exact: true }).click()
  await menu.locator('.menu-gear-update').waitFor()
  assert.equal(await menu.getAttribute('aria-description'), 'Доступно обновление панели.')
  assert.deepEqual(calls, [{ method: 'GET', path: '/api/updates', authorization: 'Bearer panel-test-token' }])
  await page.getByRole('heading', { name: 'Test panel' }).waitFor()
  assert.equal(await page.getByRole('link', { name: 'v1.2.3', exact: true }).getAttribute('href'), project)
  await open()
  await dialog.getByText('Доступно обновление панели.').waitFor()
  assert.equal(await dialog.getByText('1.2.3', { exact: true }).count(), 1)
  assert.equal(await dialog.getByText('v1.3.0', { exact: true }).count(), 1)
  assert.equal(await dialog.locator('time').getAttribute('datetime'), available.checked_at)
  assert.equal(await dialog.getByRole('link', { name: 'Открыть релиз' }).getAttribute('href'), available.release_url)

  for (const width of [320, 1280]) {
    await page.setViewportSize({ width, height: 820 })
    const bounds = await dialog.boundingBox()
    assert.ok(bounds.x >= 0 && bounds.x + bounds.width <= width)
    assert.ok(await dialog.evaluate((element) => element.scrollWidth <= element.clientWidth))
  }
  await page.mouse.click(2, 2)
  assert.equal(await dialog.isVisible(), true)
  await page.keyboard.press('Escape')
  await dialog.waitFor({ state: 'detached' })

  await open()
  assert.equal(calls.length, 1)
  manualGate = Promise.withResolvers()
  manual = { ...available, stale: true }
  await check.click()
  await dialog.getByText('Проверяем обновления…').waitFor()
  assert.equal(await check.isDisabled(), true)
  manualGate.resolve()
  await dialog.getByText('Не удалось обновить сведения о релизе. Показана ранее полученная версия.').waitFor()
  assert.equal(await menu.getAttribute('aria-description'), null)
  assert.equal(await dialog.getByRole('link', { name: 'Открыть релиз' }).getAttribute('href'), available.release_url)
  assert.deepEqual(calls[1], { method: 'POST', path: '/api/updates/check', authorization: 'Bearer panel-test-token' })

  manual = { ...available, release_url: 'https://example.test/releases/tag/v1.3.0', status: 'up_to_date' }
  await check.click()
  await dialog.getByText('Установлена последняя стабильная версия.').waitFor()
  assert.equal(await dialog.getByRole('link', { name: 'Открыть релиз' }).count(), 0)

  manual = { ...available, status: 'disabled', latest_version: null, checked_at: null, release_url: null }
  await check.click()
  await dialog.getByText('Проверка обновлений отключена в конфигурации панели.').waitFor()
  assert.equal(await check.isDisabled(), true)
  assert.equal(await dialog.getByRole('link').count(), 0)

  automatic = { ...manual, status: 'unavailable' }
  await page.reload()
  await open()
  await dialog.getByText('Не удалось проверить обновления.').waitFor()
  assert.equal(await check.isEnabled(), true)
  assert.equal(await dialog.getByRole('link').count(), 0)

  manualStatus = 401
  await check.click()
  await page.getByRole('heading', { name: 'Вход в панель' }).waitFor()
  assert.equal(await dialog.count(), 0)
  assert.equal(calls.filter(({ method }) => method === 'GET').length, 2)
  assert.deepEqual(pageErrors, [])
} finally {
  await browser.close()
  await vite.close()
}

console.log('Panel updates passed for signed-in checks, cached results, status, safe links and mobile layout')
