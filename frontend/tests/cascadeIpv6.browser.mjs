import assert from 'node:assert/strict'
import { existsSync } from 'node:fs'
import { mkdir } from 'node:fs/promises'
import { createServer } from 'vite'
import { chromium } from 'playwright'

const server = await createServer({ server: { host: '127.0.0.1', port: 0 } })
await server.listen()
const executablePath = process.env.CHROME_PATH || ['C:/Program Files/Google/Chrome/Application/chrome.exe', '/usr/bin/chromium', '/usr/bin/google-chrome'].find(existsSync)
const browser = await chromium.launch({ headless: true, ...(executablePath ? { executablePath } : {}) })
const errors = []
try {
  for (const lang of ['ru', 'en']) for (const width of [390, 1100]) {
    const page = await browser.newPage({ viewport: { width, height: 1000 } })
    page.on('pageerror', error => errors.push(error.message))
    await page.addInitScript(language => localStorage.setItem('acontrol_lang', language), lang)
    const probes = [], creates = []
    await page.route('**/api/**', async route => {
      const request = route.request(), path = new URL(request.url()).pathname
      const fulfill = value => route.fulfill({ contentType: 'application/json', body: JSON.stringify(value) })
      if (path.endsWith('/progress')) return fulfill({})
      if (path.endsWith('/probe-transport')) {
        const body = request.postDataJSON()
        probes.push(body)
        return fulfill({ transport: body.transport, measurement: body.transport, ok: true, status: 'ok',
          bytes: 20971520, requested_bytes: 20971520, secs: 1, mbps: 168, error: '', entry_port: 51830, exit_port: 51831 })
      }
      if (path.endsWith('/cascades') && request.method() === 'POST') {
        creates.push(request.postDataJSON())
        return route.fulfill({ status: 409, contentType: 'application/json', body: JSON.stringify({ detail: 'Fixture stopped before installation' }) })
      }
      throw new Error(`Unexpected request: ${request.method()} ${path}`)
    })
    await page.goto(`${server.resolvedUrls.local[0]}tests/fixtures/cascade-ipv6.html`)
    await page.getByRole('radio').first().check()
    await page.getByRole('button', { name: lang === 'ru' ? 'Дальше' : 'Next', exact: true }).click()
    await page.getByRole('radio').first().check()
    await page.getByRole('button', { name: lang === 'ru' ? 'Дальше' : 'Next', exact: true }).click()
    const family = page.getByRole('combobox', { name: lang === 'ru' ? 'Адреса между узлами каскада' : 'Addresses between cascade nodes' })
    assert.equal(await family.inputValue(), 'ipv4')
    await family.selectOption('ipv6')
    await page.getByRole('textbox', { name: lang === 'ru' ? 'IPv6 входа' : 'Entry IPv6' }).fill('2001:db8::10')
    await page.getByRole('textbox', { name: lang === 'ru' ? 'IPv6 выхода' : 'Exit IPv6' }).fill('2001:db8::20')
    await page.getByRole('button', { name: lang === 'ru' ? 'Проверить выбранный транспорт' : 'Test selected transport' }).click()
    await page.getByText(lang === 'ru' ? 'Данные прошли' : 'Data received', { exact: true }).waitFor()
    assert.equal(probes.length, 1)
    assert.equal(probes[0].address_family, 'ipv6')
    assert.equal(probes[0].entry_endpoint, '2001:db8::10')
    assert.equal(probes[0].exit_endpoint, '2001:db8::20')
    await page.getByRole('textbox', { name: lang === 'ru' ? 'IPv6 выхода' : 'Exit IPv6' }).fill('2001:db8::21')
    assert.equal(await page.getByText(lang === 'ru' ? 'Данные прошли' : 'Data received', { exact: true }).count(), 0)
    await page.getByRole('button', { name: lang === 'ru' ? 'Собрать каскад' : 'Build the cascade' }).click()
    await page.getByText('Fixture stopped before installation', { exact: false }).waitFor()
    assert.equal(creates.length, 1)
    assert.equal(creates[0].address_family, 'ipv6')
    assert.equal(creates[0].exit_endpoint, '2001:db8::21')
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), `${lang}/${width} fits viewport`)
    if (process.env.CASCADE_IPV6_SCREENSHOTS) {
      await mkdir(process.env.CASCADE_IPV6_SCREENSHOTS, { recursive: true })
      await page.screenshot({ path: `${process.env.CASCADE_IPV6_SCREENSHOTS}/${lang}-${width}.png` })
    }
    await page.getByRole('button', { name: lang === 'ru' ? 'Назад' : 'Back', exact: true }).click()
    await page.getByRole('radio').last().check()
    await page.getByRole('button', { name: lang === 'ru' ? 'Дальше' : 'Next', exact: true }).click()
    assert.equal(await page.getByRole('textbox', { name: lang === 'ru' ? 'IPv6 выхода' : 'Exit IPv6' }).inputValue(), '')
    assert.equal(await page.getByRole('textbox', { name: lang === 'ru' ? 'IPv6 входа' : 'Entry IPv6' }).inputValue(), '2001:db8::10')
    await page.close()
  }
  assert.deepEqual(errors, [])
  console.log('IPv6 cascade wizard: RU/EN, desktop/mobile, explicit family/endpoints and probe invalidation passed')
} finally {
  await browser.close()
  await server.close()
}
