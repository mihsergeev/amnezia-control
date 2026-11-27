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
const installCalls = []
const pageErrors = []
page.on('pageerror', (error) => pageErrors.push(error.message))
await page.addInitScript(() => {
  if (!localStorage.getItem('acontrol_lang')) localStorage.setItem('acontrol_lang', 'ru')
})
const origin = 'https://panel-updates.test'
const installation = (phase = 'idle', version = null, error = null, enabled = true) => ({ enabled, phase, version, error })
let installer = installation('idle', null, null, false)
let statusUnavailable = false
let postOutcome = 'invalidOtp'
let automatic = available
let manual = available
let manualStatus = 200
let manualGate

try {
  await page.route(`${origin}/**`, async (route) => {
    const request = route.request()
    const { pathname: path, search } = new URL(request.url())
    if (!path.startsWith('/api/')) {
      const response = await page.request.get(new URL(path + search, vite.resolvedUrls.local[0]).href)
      return route.fulfill({ response })
    }
    if (path === '/api/updates' || path === '/api/updates/check') {
      const requestHeaders = await request.allHeaders()
      calls.push({ method: request.method(), path, authorization: requestHeaders.authorization })
      if (path === '/api/updates') return route.fulfill({ json: automatic })
      await manualGate?.promise
      return route.fulfill({ status: manualStatus, json: manual })
    }
    if (path === '/api/updates/installation') {
      if (request.method() === 'GET') {
        if (statusUnavailable) return route.fulfill({ status: 502, body: 'Bad Gateway' })
        return route.fulfill({ json: installer })
      }
      assert.equal(request.method(), 'POST')
      const headers = await request.allHeaders()
      assert.equal(headers.authorization, 'Bearer panel-test-token')
      assert.equal(headers.origin, origin)
      assert.equal(headers['x-acontrol-session'], '1')
      assert.equal(headers['x-confirm-otp'], undefined)
      const { version, password, otp } = request.postDataJSON()
      assert.equal(version, available.latest_version.slice(1))
      assert.equal(password, 'test')
      assert.match(otp, /^\d{6}$/)
      installCalls.push(otp)
      if (postOutcome === 'invalidOtp') return route.fulfill({ status: 403, json: { detail: '2fa_invalid' } })
      if (postOutcome === 'busy') {
        installer = installation('verifying', '1.3.0')
        return route.fulfill({ status: 409, json: { detail: 'installation_busy' } })
      }
      if (postOutcome === 'lostResponse') {
        installer = installation('installing', '1.3.0')
        statusUnavailable = true
        return route.abort()
      }
      installer = installation('queued', '1.3.0')
      return route.fulfill({ status: 202, json: installer })
    }
    if (path === '/api/auth/login') return route.fulfill({ json: { access_token: 'panel-test-token' } })
    if (path === '/api/branding') return route.fulfill({ json: { version: null, header_title: 'Test panel' } })
    if (path === '/api/config') return route.fulfill({ json: { version: '1.2.3' } })
    if (['/api/servers', '/api/cascades', '/api/stats/nodes'].includes(path)) return route.fulfill({ json: [] })
    return route.fulfill({ json: { per_server: [] } })
  })

  await page.goto(origin)
  await page.getByRole('heading', { name: 'Вход в панель' }).waitFor()
  assert.deepEqual(calls, [])
  const login = async () => {
    await page.getByLabel('Логин', { exact: true }).fill('admin')
    await page.getByLabel('Пароль', { exact: true }).fill('test')
    await page.getByRole('button', { name: 'Войти', exact: true }).click()
  }

  const menu = page.getByRole('button', { name: 'Меню', exact: true })
  const dialog = page.getByRole('dialog', { name: 'Обновления', exact: true })
  const check = dialog.getByRole('button', { name: 'Проверить', exact: true })
  const open = async () => {
    await menu.click()
    await page.getByRole('button', { name: 'Обновления', exact: true }).click()
    await dialog.waitFor()
  }

  await login()
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
  assert.equal(await dialog.getByRole('link', { name: 'Как включить установщик' }).getAttribute('href'), project + '/blob/main/docs/panel-updater.md')
  assert.equal(await dialog.getByRole('button', { name: 'Установить v1.3.0', exact: true }).count(), 0)

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

  automatic = manual = available
  installer = installation()
  manualStatus = 200
  await login()
  await open()
  const install = dialog.getByRole('button', { name: 'Установить v1.3.0', exact: true })
  const confirm = page.getByRole('dialog', { name: 'Подтвердите установку' })
  const confirmButton = confirm.getByRole('button', { name: 'Установить', exact: true })
  const otp = confirm.getByRole('textbox', { name: 'Код 2FA из приложения' })
  const openConfirmation = async () => {
    await install.click()
    await confirm.waitFor()
    await confirm.getByLabel('Пароль', { exact: true }).fill('test')
  }

  await openConfirmation()
  await page.setViewportSize({ width: 320, height: 480 })
  assert.ok(await confirm.evaluate((el) => el.scrollWidth <= el.clientWidth))
  assert.equal(await confirmButton.isDisabled(), true)
  await otp.fill('12345')
  assert.equal(await confirmButton.isDisabled(), true)
  await otp.fill('123456')
  await confirmButton.click()
  await confirm.getByRole('alert').getByText('Код 2FA неверен или уже использован. Введите новый код.').waitFor()
  assert.equal(await otp.inputValue(), '')
  assert.deepEqual(installCalls, ['123456'])

  postOutcome = 'busy'
  await otp.fill('234567')
  await confirmButton.click()
  await dialog.getByText('Проверяем подпись образов.').waitFor()
  await dialog.getByRole('alert').getByText('На сервере уже выполняется обновление.').waitFor()
  assert.equal(await install.count(), 0)
  installer = installation('failed', '1.3.0', 'verification_failed')
  await dialog.getByText('Проверка подлинности образов не прошла.').waitFor()

  postOutcome = 'accepted'
  await openConfirmation()
  await otp.fill('345678')
  await confirmButton.click()
  await dialog.getByText('Обновление поставлено в очередь.').waitFor()
  assert.equal(await install.count(), 0)
  installer = installation('backing_up', '1.3.0')
  await dialog.getByText('Создаём и проверяем резервную копию.').waitFor()
  installer = installation('rolling_back', '1.3.0', 'health_failed')
  await dialog.getByText('Восстанавливаем предыдущую версию.').waitFor()
  installer = installation('rolled_back', '1.3.0', 'health_failed')
  await dialog.getByText('Предыдущая версия восстановлена.').waitFor()
  await dialog.getByText('Новая версия не прошла проверку работоспособности.').waitFor()
  await install.waitFor()

  manual = { ...available, stale: true }
  await check.click()
  await dialog.getByText('Не удалось обновить сведения о релизе. Показана ранее полученная версия.').waitFor()
  assert.equal(await install.count(), 0)
  manual = available
  await check.click()

  postOutcome = 'lostResponse'
  await openConfirmation()
  await otp.fill('456789')
  await confirmButton.click()
  await dialog.getByText('Не удалось получить статус установки. Повторяем запрос…').waitFor()
  await dialog.getByText('Ответ на запрос установки потерян. Проверяем её статус…').waitFor()
  assert.deepEqual(installCalls, ['123456', '234567', '345678', '456789'])
  assert.equal(await install.count(), 0)

  await page.reload()
  await open()
  await dialog.getByText('Не удалось получить статус установки. Повторяем запрос…').waitFor()
  statusUnavailable = false
  installer = installation('checking', '1.3.0')
  await dialog.getByText('Проверяем работу панели после установки.').waitFor()
  automatic = { ...available, current_version: '1.3.0', status: 'up_to_date' }
  installer = installation('succeeded', '1.3.0')
  await dialog.getByText('Обновление установлено.').waitFor()
  await dialog.getByText('Установлена последняя стабильная версия.').waitFor()
  assert.equal(await dialog.locator('dd').first().textContent(), '1.3.0')
  assert.equal(await install.count(), 0)
  assert.equal(installCalls.length, 4)

  await dialog.getByRole('button', { name: 'Закрыть' }).click()
  await page.getByRole('button', { name: 'EN', exact: true }).click()
  await page.getByRole('button', { name: 'Menu', exact: true }).click()
  await page.getByRole('button', { name: 'Updates', exact: true }).click()
  await page.getByRole('dialog', { name: 'Updates' }).getByText('Update installed.').waitFor()

  installer = installation('recovery_required', '1.3.0', 'recovery_failed')
  automatic = available
  await page.reload()
  await page.getByRole('button', { name: 'Menu', exact: true }).click()
  await page.getByRole('button', { name: 'Updates', exact: true }).click()
  const englishDialog = page.getByRole('dialog', { name: 'Updates' })
  await englishDialog.getByText('A panel update is available.').waitFor()
  await englishDialog.getByText('Manual recovery is required on the server.').waitFor()
  assert.equal(await englishDialog.getByRole('button', { name: 'Install v1.3.0' }).count(), 0)
  assert.deepEqual(pageErrors, [])
} finally {
  await browser.close()
  await vite.close()
}

console.log('Panel updates passed for release checks, mandatory OTP, concurrent installation, rollback, outage recovery, reload and mobile layout')
