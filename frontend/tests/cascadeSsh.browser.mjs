import assert from 'node:assert/strict'
import { existsSync } from 'node:fs'
import { chromium } from 'playwright'
import { createServer } from 'vite'

const server = await createServer({ server: { host: '127.0.0.1', port: 0 } })
await server.listen()
const executablePath = process.env.CHROME_PATH || ['C:/Program Files/Google/Chrome/Application/chrome.exe', '/usr/bin/chromium', '/usr/bin/google-chrome'].find(existsSync)
let browser
try {
  browser = await chromium.launch({ headless: true, ...(executablePath ? { executablePath } : {}) })
  const page = await browser.newPage({ viewport: { width: 390, height: 1000 } })
  await page.addInitScript(() => localStorage.setItem('acontrol_lang', 'ru'))
  const requests = []
  const errors = []
  page.on('pageerror', error => errors.push(error.message))
  let registered
  let ready = false
  const bootstrapBodies = []
  const prepareStarted = Promise.withResolvers()
  const prepareResponse = Promise.withResolvers()
  const origin = new URL(server.resolvedUrls.local[0]).origin
  await page.route('**/*', async route => {
    const request = route.request()
    const url = new URL(request.url())
    if (url.origin !== origin) return route.abort()
    if (!url.pathname.startsWith('/api/')) return route.continue()
    requests.push(url.pathname)
    if (url.pathname === '/api/servers' && request.method() === 'POST') {
      registered = { ...request.postDataJSON(), id: 4, country: 'FI', last_check_ok: false }
      return route.fulfill({ json: registered })
    }
    if (url.pathname === '/api/cascades') return route.fulfill({ json: [] })
    if (url.pathname === '/api/servers/4/check') return route.fulfill({ json: { ...registered, last_check_ok: ready } })
    if (url.pathname === '/api/servers/4/bootstrap') {
      bootstrapBodies.push(request.postDataJSON())
      if (bootstrapBodies.length === 1) return route.fulfill({ status: 400, json: { detail: 'Synthetic SSH setup failure' } })
      return route.fulfill({ json: { ...registered, last_check_ok: true } })
    }
    if (url.pathname === '/api/servers/4/setup-script') return route.fulfill({ json: { script: '# Example setup script' } })
    if (url.pathname === '/api/servers/4/ssh-access/prepare') {
      prepareStarted.resolve()
      await prepareResponse.promise
      ready = true
      return route.fulfill({ json: { ...registered, last_check_ok: true } })
    }
    throw new Error(`Unexpected request: ${request.method()} ${url.pathname}`)
  })
  await page.goto(`${origin}/tests/fixtures/cascade-ipv6.html`)
  const button = name => page.getByRole('button', { name, exact: true })
  const host = page.getByRole('textbox', { name: 'Хост (IP или домен)' })
  const ssh = page.getByRole('group', { name: 'Доступ SSH' })
  const connection = ssh.getByRole('combobox', { name: 'Подключение' })
  const source = ssh.getByRole('combobox', { name: 'Разрешенные источники ключа панели' })
  const firewall = ssh.getByRole('combobox', { name: 'Firewall сервера' })
  const addresses = ssh.getByRole('textbox', { name: 'IP или CIDR через запятую' })

  await button('Новый сервер').click()
  await host.fill('203.0.113.40')
  await button('Скрипт').click()
  await connection.selectOption('2')
  await ssh.locator('summary').click()
  await source.selectOption('custom')
  await addresses.fill('192.0.2.0/24, 2001:db8::/32')
  await firewall.selectOption('preserve')
  await button('Дальше').click()
  const prepare = button('Подготовить промежуточную ноду')
  await prepare.waitFor()
  assert.equal(registered.ssh_jump_server_id, 2)
  assert.deepEqual(registered.ssh_source_ips, ['192.0.2.0/24', '2001:db8::/32'])
  assert.equal(registered.ssh_firewall_mode, 'preserve')

  try {
    await prepare.click()
    await prepareStarted.promise
    assert.equal(await prepare.isDisabled(), true)
    assert.equal(await button('Закрыть').isDisabled(), true)
    assert.equal(await button('Подключаюсь…').isDisabled(), true)
  } finally {
    prepareResponse.resolve()
  }
  await button('Дальше').click()

  await button('Новый сервер').click()
  assert.equal(await host.inputValue(), '')
  assert.equal(await connection.inputValue(), '')
  assert.equal(await ssh.locator('details').getAttribute('open'), null)
  await ssh.locator('summary').click()
  assert.equal(await source.inputValue(), 'panel')
  assert.equal(await firewall.inputValue(), 'add')
  assert.equal(await page.locator('input[type=password]').count(), 1)

  await host.fill('198.51.100.25')
  await connection.selectOption('3')
  await page.locator('input[type=password]').fill('fixture-only-password')
  await button('Назад').click()
  await button('Новый сервер').click()
  assert.equal(await host.inputValue(), '')
  assert.equal(await connection.inputValue(), '')
  assert.equal(await page.locator('input[type=password]').inputValue(), '')
  assert.deepEqual(requests, ['/api/servers', '/api/cascades', '/api/servers/4/check',
    '/api/servers/4/setup-script', '/api/servers/4/ssh-access/prepare', '/api/servers/4/check', '/api/cascades'])

  ready = false
  await host.fill('203.0.113.41')
  await page.locator('input[type=password]').fill('fixture-only-password')
  await ssh.locator('summary').click()
  await source.selectOption('custom')
  await addresses.fill('invalid-draft')
  await source.selectOption('panel')
  await button('Дальше').click()
  await page.getByRole('alert').getByText('Synthetic SSH setup failure').waitFor()
  assert.equal(await page.locator('input[type=password]').inputValue(), '')
  assert.equal(await button('Дальше').isDisabled(), true)
  await page.locator('input[type=password]').fill('unused-fixture-password')
  await button('Скрипт').click()
  await button('Пароль').click()
  assert.equal(await page.locator('input[type=password]').inputValue(), '')
  await page.locator('input[type=password]').fill('fixture-retry-password')
  await button('Дальше').click()
  await button('Назад').waitFor()
  assert.deepEqual(registered.ssh_source_ips, [])
  assert.equal(registered.password, undefined)
  assert.deepEqual(bootstrapBodies, [
    { password: 'fixture-only-password', become_password: null },
    { password: 'fixture-retry-password', become_password: null },
  ])
  assert.deepEqual(requests.slice(-4), ['/api/servers', '/api/cascades', '/api/servers/4/check', '/api/servers/4/bootstrap'])
  assert.deepEqual(errors, [])
  console.log('Cascade SSH: script preparation serialized, entry and exit settings isolated')
} finally {
  await browser?.close()
  await server.close()
}
