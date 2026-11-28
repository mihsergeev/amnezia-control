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

const cookieName = 'accontrol_refresh'
const trustCookieName = 'acontrol_trusted_device'
const cookieOptions = '; Path=/api/auth; Secure; HttpOnly; SameSite=Strict'
const markerKey = 'acontrol_remembered_session'
const tokenKey = 'acontrol_token'
const actualOrigin = vite.resolvedUrls.local[0]
const stored = (page, key) => page.evaluate((key) => localStorage.getItem(key), key)
const timestamp = '2026-11-27T09:30:00Z'

async function fixture(run, { origin = 'https://remembered-login.test', language = 'ru' } = {}) {
  const context = await browser.newContext({ viewport: { width: 320, height: 820 } })
  context.setDefaultTimeout(8_000)
  const calls = []
  const pageErrors = []
  const state = {
    requireOtp: true, active: false, expired: false, issue: 0, conflicts: 0,
    refreshPause: null, protectedRequests: 0, reactiveStatus: null, ttl: 900, logoutNetworkError: false,
  }
  const makeToken = (remember) => {
    const iat = Math.floor(Date.now() / 1000)
    const body = { sub: 'admin', iat, exp: iat + state.ttl, issue: ++state.issue }
    if (remember) body.sid = 'current-session'
    return `eyJhbGciOiJIUzI1NiJ9.${Buffer.from(JSON.stringify(body)).toString('base64url')}.test`
  }
  const entries = [
    { id: 'current-session', user_agent: 'Chrome/100 Safari/537', current: true },
    { id: 'other', user_agent: 'Firefox/130', current: false },
  ].map((entry) => ({ ...entry, created_at: timestamp, last_used_at: timestamp, expires_at: timestamp }))
  const trustedDevice = {
    id: 'current-device', user_agent: 'Chrome/100 Safari/537',
    created_at: timestamp, last_used_at: timestamp, expires_at: timestamp,
  }
  let deviceRegistered = false

  await context.addInitScript((language) => {
    if (location.protocol === 'http:' || location.protocol === 'https:') {
      localStorage.setItem('acontrol_lang', language)
    }
  }, language)
  context.on('page', (page) => page.on('pageerror', (error) => pageErrors.push(error.message)))
  await context.route(`${origin}/**`, async (route) => {
    const request = route.request()
    const { pathname, search } = new URL(request.url())
    const method = request.method()
    if (!pathname.startsWith('/api/')) {
      const response = await context.request.get(new URL(pathname + search, actualOrigin).href)
      return route.fulfill({ response })
    }

    const headers = await request.allHeaders()
    calls.push({ path: pathname, method, headers, body: request.postData() })
    const reply = (json, status = 200, extra = {}) => route.fulfill({ status, json, headers: extra })
    const cookie = (value) => ({ 'Set-Cookie': `${cookieName}=${value}${cookieOptions}` })
    const clearCookie = { 'Set-Cookie': `${cookieName}=${cookieOptions}; Max-Age=0` }
    const trusted = deviceRegistered && headers.cookie?.includes(`${trustCookieName}=trusted`)
    if (pathname === '/api/auth/login') {
      const { username, password, otp, remember, trust_device } = request.postDataJSON()
      assert.equal(username, 'admin')
      assert.equal(password, 'password')
      assert.equal(typeof remember, 'boolean')
      assert.equal(headers['x-acontrol-session'], '1')
      if (state.requireOtp && !otp && !trusted) return reply({ detail: '2fa_required' }, 401)
      if (state.requireOtp && otp && otp !== '123456') return reply({ detail: '2fa_invalid' }, 401)
      state.active = remember
      state.expired = false
      let setCookie = remember ? cookie('initial') : clearCookie
      if (trust_device) {
        assert.equal(otp, '123456')
        deviceRegistered = true
        setCookie = { 'Set-Cookie': `${trustCookieName}=trusted${cookieOptions}` }
      }
      return reply({ access_token: makeToken(remember) }, 200, setCookie)
    }
    if (pathname === '/api/auth/refresh') {
      assert.equal(headers['x-acontrol-session'], '1')
      assert.ok(headers.cookie?.includes(`${cookieName}=`), 'Refresh must send the browser cookie')
      state.refreshPause?.started.resolve()
      await state.refreshPause?.release.promise
      if (state.expired || !state.active) return reply({ detail: 'invalid session' }, 401)
      if (state.conflicts > 0) {
        state.conflicts--
        return reply({ detail: 'rotation in progress' }, 409)
      }
      return reply({ access_token: makeToken(true) }, 200, cookie(`rotated-${state.issue}`))
    }
    if (pathname === '/api/auth/logout') {
      assert.equal(headers['x-acontrol-session'], '1')
      if (state.logoutNetworkError) return route.abort()
      state.active = false
      return route.fulfill({ status: 204, headers: clearCookie })
    }
    if (pathname === '/api/auth/sessions') return reply(entries)
    if (pathname.startsWith('/api/auth/sessions/')) {
      assert.equal(method, 'DELETE')
      const id = pathname.split('/').at(-1)
      const index = entries.findIndex((entry) => entry.id === id)
      assert.notEqual(index, -1)
      const [removed] = entries.splice(index, 1)
      if (removed.current) state.active = false
      return route.fulfill({ status: 204, headers: removed.current ? clearCookie : {} })
    }
    if (pathname.startsWith('/api/auth/trusted-devices')) {
      assert.equal(headers['x-acontrol-session'], '1')
      assert.match(headers.authorization, /^Bearer /)
      if (method === 'GET') return reply(deviceRegistered ? [{ ...trustedDevice, current: !!trusted }] : [])
      assert.equal(method, 'DELETE')
      assert.equal(pathname, `/api/auth/trusted-devices/${trustedDevice.id}`)
      deviceRegistered = false
      return route.fulfill({
        status: 204,
        headers: trusted ? { 'Set-Cookie': `${trustCookieName}=${cookieOptions}; Max-Age=0` } : {},
      })
    }
    if (pathname === '/api/auth/2fa') return reply({ enabled: state.requireOtp })
    if (pathname === '/api/backup/download') {
      assert.equal(request.postDataJSON().password, 'password')
      assert.equal(headers['x-confirm-otp'], '654321')
      return route.fulfill({ status: 200, contentType: 'application/gzip', body: 'test' })
    }
    if (['/api/auth/password', '/api/auth/2fa/enable', '/api/auth/2fa/disable', '/api/backup/restore'].includes(pathname)) {
      assert.equal(method, 'POST')
      state.active = false
      return reply({ access_token: makeToken(false), enabled: pathname.endsWith('enable'), restored: {} }, 200, clearCookie)
    }
    if (pathname === '/api/test/request') {
      state.protectedRequests++
      if (state.reactiveStatus === 401) {
        state.reactiveStatus = null
        return reply({ detail: 'invalid access token' }, 401)
      }
      return reply({ ok: true })
    }
    if (pathname === '/api/branding') return reply({ version: null })
    if (pathname === '/api/config') return reply({ version: 'test' })
    if (['/api/servers', '/api/cascades', '/api/stats/nodes'].includes(pathname)) return reply([])
    if (pathname === '/api/stats/overview') return reply({ per_server: [] })
    return reply({})
  })
  try {
    const newPage = async () => {
      const page = await context.newPage()
      await page.goto(origin)
      return page
    }
    const page = await newPage()
    try {
      await run({ context, page, state, calls, newPage })
    } catch (error) {
      console.error(await page.locator('body').innerText(), calls.map(({ method, path }) => `${method} ${path}`), pageErrors)
      throw error
    }
    assert.deepEqual(pageErrors, [])
  } finally {
    await context.close()
  }
}

const count = (calls, name) => calls.filter(({ path }) => path === `/api/auth/${name}`).length
const signedIn = (page) => page.getByRole('button', { name: /^(Серверы|Servers)$/ }).waitFor()
const signedOut = (page) => page.getByRole('heading', { name: /^(Вход в панель|Sign in)$/ }).waitFor()

const rememberOption = (page) => page.getByRole('checkbox', { name: /Запомнить вход|Remember sign-in/ })
const trustOption = (page) => page.getByRole('checkbox', { name: /Доверять этому устройству|Trust this device/ })
const otpInput = (page) => page.locator('input[autocomplete="one-time-code"]')
const submitLogin = (page) => page.getByRole('button', { name: /^(Войти|Log in)$/ }).click()

async function enterCredentials(page) {
  await page.getByLabel(/^(Логин|Login)$/).fill('admin')
  await page.getByLabel(/^(Пароль|Password)$/).fill('password')
}

async function signIn(page, { remember = false, otp = true } = {}) {
  await enterCredentials(page)
  if (remember) await rememberOption(page).check()
  await submitLogin(page)
  if (otp) {
    await otpInput(page).fill('123456')
    if (remember) assert.equal(await rememberOption(page).isChecked(), true)
    await submitLogin(page)
  }
  await signedIn(page)
}

async function probe(page, method = 'GET', otp = false) {
  return page.evaluate(async ({ method, otp }) => {
    const { api } = await import('/src/api.ts')
    try {
      await api('/api/test/request', { method, headers: otp ? { 'X-Confirm-OTP': '123456' } : {} })
      return 200
    } catch (error) {
      return error.status
    }
  }, { method, otp })
}

try {
  await fixture(async ({ context, page, state, calls, newPage }) => {
    await signedOut(page)
    assert.equal(count(calls, 'refresh'), 0)
    assert.equal(await page.getByRole('checkbox').isChecked(), false)
    const rememberBounds = await rememberOption(page).boundingBox()
    assert.ok(rememberBounds.width >= 16 && rememberBounds.height >= 16)
    assert.ok(await page.locator('.login-card').evaluate((el) => el.scrollWidth <= el.clientWidth))
    await page.getByRole('button', { name: 'Показать пароль' }).click()
    assert.equal(await page.getByLabel('Пароль', { exact: true }).getAttribute('type'), 'text')
    await page.getByRole('button', { name: 'Скрыть пароль' }).click()
    assert.equal(await page.getByLabel('Пароль', { exact: true }).getAttribute('type'), 'password')
    await signIn(page, { remember: true })
    assert.deepEqual(calls.filter(({ path }) => path.endsWith('/login')).map(({ body }) => ({
      remember: JSON.parse(body).remember, otp: JSON.parse(body).otp,
    })), [{ remember: true, otp: null }, { remember: true, otp: '123456' }])
    assert.equal(await stored(page, tokenKey), null)
    assert.equal(await stored(page, markerKey), 'current-session')
    const [cookie] = await context.cookies()
    assert.deepEqual([cookie.name, cookie.path, cookie.secure, cookie.httpOnly, cookie.sameSite],
      [cookieName, '/api/auth', true, true, 'Strict'])
    assert.ok(!(await page.evaluate(() => document.cookie)).includes(cookieName))

    state.conflicts = 1
    await page.reload()
    await signedIn(page)
    assert.equal(count(calls, 'refresh'), 2)

    state.reactiveStatus = 401
    assert.equal(await probe(page), 200)
    assert.equal(state.protectedRequests, 2)
    state.reactiveStatus = 401
    assert.equal(await probe(page, 'POST'), 409)
    assert.equal(state.protectedRequests, 3)
    state.reactiveStatus = 401
    assert.equal(await probe(page, 'GET', true), 409)
    assert.equal(state.protectedRequests, 4)

    const second = await newPage()
    await signedIn(second)
    await page.getByRole('button', { name: 'Меню' }).click()
    await page.getByText('Сохранённые сеансы', { exact: true }).click()
    const dialog = page.getByRole('dialog', { name: 'Сохранённые сеансы' })
    const current = dialog.getByRole('listitem').filter({ hasText: 'Текущий сеанс' })
    await current.getByText('Chrome').waitFor()
    await dialog.getByText('Последняя активность').first().waitFor()
    await page.mouse.click(2, 2)
    assert.equal(await dialog.isVisible(), true)
    page.once('dialog', (dialog) => dialog.accept())
    const other = dialog.getByRole('listitem').filter({ hasText: 'Firefox' })
    await other.getByRole('button', { name: 'Отозвать' }).click()
    await other.waitFor({ state: 'detached' })
    page.once('dialog', (dialog) => dialog.accept())
    await current.getByRole('button', { name: 'Отозвать' }).click()
    await signedOut(page)
    await signedOut(second)
    assert.equal(await stored(page, markerKey), null)
    assert.equal((await context.cookies()).length, 0)
  })

  await fixture(async ({ page, state, calls }) => {
    state.requireOtp = false
    await signedOut(page)
    assert.equal(await page.getByRole('checkbox').count(), 0)
    await signIn(page, { otp: false })
    assert.equal(JSON.parse(calls.find(({ path }) => path.endsWith('/login')).body).remember, false)
    assert.ok(await stored(page, tokenKey))
    await page.reload()
    await signedIn(page)
    assert.equal(count(calls, 'refresh'), 0)
  }, { origin: 'http://ordinary-login.test', language: 'en' })

  await fixture(async ({ page, calls }) => {
    await enterCredentials(page)
    await submitLogin(page)
    await otpInput(page).fill('123456')
    assert.equal(await trustOption(page).count(), 0)
    assert.equal(await rememberOption(page).count(), 0)
    await submitLogin(page)
    await signedIn(page)
    assert.ok(calls.filter(({ path }) => path.endsWith('/login')).every(({ body }) => !('trust_device' in JSON.parse(body))))
  }, { origin: 'http://ordinary-login.test', language: 'en' })

  await fixture(async ({ context, page, calls }) => {
    const loginBodies = () => calls.filter(({ path }) => path.endsWith('/login')).map(({ body }) => JSON.parse(body))
    const menu = async (label) => {
      await page.getByRole('button', { name: 'Меню' }).click()
      await page.getByText(label, { exact: true }).click()
    }
    const logout = async () => {
      const response = page.waitForResponse((res) => res.url().endsWith('/logout'))
      await menu('Выйти')
      await signedOut(page)
      await response
    }

    assert.equal(await trustOption(page).count(), 0)
    await enterCredentials(page)
    await submitLogin(page)
    await trustOption(page).waitFor()
    assert.equal(await trustOption(page).isChecked(), false)
    assert.equal(await rememberOption(page).isChecked(), false)
    await trustOption(page).check()
    await otpInput(page).fill('123456')
    await submitLogin(page)
    await signedIn(page)
    assert.deepEqual(loginBodies().map(({ remember, otp, trust_device }) => [remember, otp, trust_device]), [
      [false, null, undefined], [false, '123456', true],
    ])
    assert.equal(await stored(page, markerKey), null)

    await logout()
    assert.equal((await context.cookies()).find(({ name }) => name === trustCookieName)?.httpOnly, true)
    assert.equal(count(calls, 'refresh'), 0)
    await signIn(page, { otp: false })
    assert.equal(loginBodies().at(-1).otp, null)
    assert.equal(loginBodies().at(-1).trust_device, undefined)

    await menu('Скачать бэкап')
    const stepUp = page.locator('form.modal')
    await stepUp.getByPlaceholder('Пароль', { exact: true }).fill('password')
    await otpInput(page).waitFor()
    const proceed = stepUp.getByRole('button', { name: 'Продолжить' })
    assert.equal(await proceed.isDisabled(), true)
    await otpInput(page).fill('654321')
    const backup = page.waitForResponse((res) => res.url().endsWith('/api/backup/download'))
    await proceed.click()
    assert.equal((await backup).status(), 200)
    await stepUp.waitFor({ state: 'detached' })

    await menu('Доверенные устройства')
    const dialog = page.getByRole('dialog', { name: 'Доверенные устройства' })
    const current = dialog.getByRole('listitem').filter({ hasText: 'Текущий браузер' })
    await current.getByText('Chrome').waitFor()
    for (const width of [320, 1280]) {
      await page.setViewportSize({ width, height: 820 })
      const bounds = await dialog.boundingBox()
      assert.ok(bounds.x >= 0 && bounds.x + bounds.width <= width)
    }
    const revoke = current.getByRole('button', { name: 'Отозвать' })
    page.once('dialog', (confirm) => confirm.dismiss())
    await revoke.click()
    assert.equal(await current.isVisible(), true)
    page.once('dialog', (confirm) => confirm.accept())
    await revoke.click()
    await dialog.getByText('Доверенных устройств нет.').waitFor()
    await dialog.getByRole('button', { name: 'Закрыть' }).click()
    await signedIn(page)
    assert.equal((await context.cookies()).some(({ name }) => name === trustCookieName), false)
    await logout()
    await signIn(page)
  })

  for (const conflicts of [0, 1]) {
    await fixture(async ({ page, state, calls }) => {
      state.requireOtp = false
      await signIn(page, { remember: true, otp: false })
      state.refreshPause = { started: Promise.withResolvers(), release: Promise.withResolvers() }
      state.conflicts = conflicts
      state.reactiveStatus = 401
      const refreshRequest = page.waitForRequest((request) => request.url().endsWith('/refresh'))
      const inFlight = probe(page)
      await refreshRequest
      await state.refreshPause.started.promise
      const before = count(calls, 'refresh')
      await page.getByRole('button', { name: 'Menu' }).click()
      await page.getByText('Log out', { exact: true }).click()
      await signedOut(page)
      assert.equal(count(calls, 'logout'), 0)
      const logoutResponse = page.waitForResponse((response) => response.url().endsWith('/logout'))
      state.refreshPause.release.resolve()
      await inFlight
      assert.equal((await logoutResponse).status(), 204)
      assert.equal(count(calls, 'refresh'), before)
      assert.equal(count(calls, 'logout'), 1)
      assert.equal(await stored(page, markerKey), null)
      await page.reload()
      await signedOut(page)
      assert.equal(count(calls, 'refresh'), before)
    }, { language: 'en' })
  }

  for (const remember of [false, true]) {
    await fixture(async ({ page, state, calls }) => {
      state.requireOtp = false
      state.logoutNetworkError = true
      await signIn(page, { remember, otp: false })
      await page.getByRole('button', { name: 'Меню' }).click()
      await page.getByText('Выйти', { exact: true }).click()
      await signedOut(page)
      assert.equal(await stored(page, markerKey), null)
      assert.equal(await stored(page, tokenKey), null)
      await page.reload()
      await signedOut(page)
      assert.equal(count(calls, 'refresh'), 0)
    })
  }

  await fixture(async ({ page, state, calls }) => {
    state.requireOtp = false
    await signIn(page, { remember: true, otp: false })
    state.conflicts = 4
    await page.reload()
    const retry = page.getByRole('button', { name: 'Повторить восстановление входа' })
    await retry.waitFor()
    assert.equal(await stored(page, markerKey), 'current-session')
    await retry.click()
    await signedIn(page)
    state.expired = true
    await page.reload()
    await signedOut(page)
    assert.equal(await stored(page, markerKey), null)
    const before = count(calls, 'refresh')
    await page.reload()
    await signedOut(page)
    assert.equal(count(calls, 'refresh'), before)
  })

  await fixture(async ({ page, state, calls }) => {
    state.requireOtp = false
    state.ttl = 5
    await signIn(page, { remember: true, otp: false })
    state.ttl = 900
    await page.evaluate(() => Object.defineProperty(document, 'hidden', { value: true, configurable: true }))
    state.reactiveStatus = 401
    assert.equal(await probe(page), 503)
    assert.equal(count(calls, 'refresh'), 0)
    const refreshed = page.waitForResponse((response) => response.url().endsWith('/refresh'))
    await page.evaluate(() => delete document.hidden)
    await refreshed
    assert.equal(count(calls, 'refresh'), 1)
  })

  for (const operation of ['changePassword', 'enable2FA', 'disable2FA', 'restoreBackup']) {
    await fixture(async ({ context, page, state, newPage, calls }) => {
      state.requireOtp = false
      await signIn(page, { remember: true, otp: false })
      const second = await newPage()
      await signedIn(second)
      await page.evaluate(async (operation) => {
        const api = await import('/src/api.ts')
        if (operation === 'restoreBackup') await api.restoreBackup(new Blob(['test']), 'password')
        else await api[operation]('password', 'test-token')
      }, operation)
      await signedOut(second)
      assert.equal(await stored(page, markerKey), null)
      assert.ok(await stored(page, tokenKey))
      assert.equal((await context.cookies()).length, 0)
      const before = count(calls, 'refresh')
      await page.reload()
      await signedIn(page)
      assert.equal(count(calls, 'refresh'), before)
    })
  }
} finally {
  await browser.close()
  await vite.close()
}

console.log('Remembered sign-in, trusted devices, rotation, revocation and security transitions passed')
