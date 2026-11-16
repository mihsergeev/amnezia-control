// Exercise the actual route editor with synthetic API responses, no VPN hosts.
import assert from 'node:assert/strict'
import { existsSync } from 'node:fs'
import { mkdir } from 'node:fs/promises'
import { createServer } from 'vite'
import { chromium } from 'playwright'

const server = await createServer({ server: { host: '127.0.0.1', port: 0 } })
await server.listen()
const base = server.resolvedUrls.local[0]
const executablePath = process.env.CHROME_PATH || ['C:/Program Files/Google/Chrome/Application/chrome.exe', '/usr/bin/chromium', '/usr/bin/google-chrome'].find(existsSync)
const browser = await chromium.launch({ headless: true, ...(executablePath ? { executablePath } : {}) })
const errors = []
try {
  for (const lang of ['ru', 'en']) for (const width of [390, 1100]) {
    const page = await browser.newPage({ viewport: { width, height: 900 } })
    page.on('pageerror', error => errors.push(error.message))
    await page.addInitScript(language => localStorage.setItem('acontrol_lang', language), lang)
    let state = 'pending'
    let readCount = 0
    const writes = []
    page.on('dialog', dialog => dialog.accept())
    await page.route('**/api/**', async route => {
      const request = route.request()
      const fulfill = value => route.fulfill({ contentType: 'application/json', body: JSON.stringify(value) })
      if (new URL(request.url()).pathname.endsWith('/routes/state')) {
        readCount++
        return fulfill({ state, applied_country: state === 'unknown' ? null : 'RU', desired_country: 'FI' })
      }
      if (request.method() === 'PUT') {
        writes.push(request.postDataJSON())
        return fulfill({ entry_country: request.postDataJSON().entry_country || 'FI' })
      }
      throw new Error(`Unexpected request: ${request.method()} ${request.url()}`)
    })
    await page.goto(`${base}tests/fixtures/country-routing.html`)
    const apply = page.getByRole('button', { name: lang === 'ru' ? 'Применить маршруты' : 'Apply routes', exact: true })
    await page.getByText(lang === 'ru' ? 'Страна в работающем шлюзе: RU' : 'Country in the running gateway: RU', { exact: false }).waitFor()
    await page.getByText(lang === 'ru' ? 'Желаемая страна: FI' : 'Desired country: FI').waitFor()
    assert.equal(await apply.isEnabled(), true, 'metadata-only change is explicitly applicable')
    assert.equal(writes.length, 0, 'opening and observing never applies rules')
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), `${lang}/${width} fits viewport`)
    await page.getByRole('textbox', { name: lang === 'ru' ? 'Страна входа' : 'Entry country', exact: true }).fill('DE')
    await apply.click()
    await page.waitForFunction(() => document.body.dataset.savedCountry === 'DE')
    assert.deepEqual(writes, [{ routes: [], entry_country: 'DE' }])
    state = 'unknown'
    await page.getByRole('button', { name: lang === 'ru' ? 'Проверить состояние правил' : 'Check rule status' }).click()
    await page.getByText(lang === 'ru' ? 'Фактические правила неизвестны: шлюз недоступен или конфигурация не подтверждена' : 'Actual rules unknown: gateway unavailable or configuration unconfirmed').waitFor()
    assert.equal(await page.getByText(lang === 'ru' ? 'Правила синхронизированы' : 'Rules are synchronized', { exact: false }).count(), 0)
    assert.equal(writes.length, 1)
    assert.ok(readCount >= 2)
    if (process.env.COUNTRY_ROUTING_SCREENSHOTS) {
      await mkdir(process.env.COUNTRY_ROUTING_SCREENSHOTS, { recursive: true })
      await page.screenshot({ path: `${process.env.COUNTRY_ROUTING_SCREENSHOTS}/${lang}-${width}.png` })
    }
    await page.close()
  }
  assert.deepEqual(errors, [])
  console.log('Country routing editor: RU/EN, desktop/mobile, pending/unknown and explicit apply passed')
} finally {
  await browser.close()
  await server.close()
}
