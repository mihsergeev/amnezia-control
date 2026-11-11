// Runs actual React components with an in-memory API. No VPN host is contacted.
import assert from 'node:assert/strict'
import { existsSync } from 'node:fs'
import { readFile } from 'node:fs/promises'
import { createServer } from 'vite'
import { chromium } from 'playwright'

const server = await createServer({ server: { host: '127.0.0.1', port: 0 } })
await server.listen()
const base = server.resolvedUrls.local[0]
const executablePath = process.env.CHROME_PATH || ['C:/Program Files/Google/Chrome/Application/chrome.exe', '/usr/bin/chromium', '/usr/bin/google-chrome'].find(existsSync)
const browser = await chromium.launch({ headless: true, ...(executablePath ? { executablePath } : {}) })
const labels = { awg: 'AmneziaWG 2.0', awg3: 'AmneziaWG 3.1', awglegacy: 'AmneziaWG Legacy', wireguard: 'WireGuard', xray: 'Xray', openvpn: 'OpenVPN + Cloak', 'openvpn-native': 'OpenVPN' }
const awgLike = (protocol) => ['awg', 'awg3', 'awglegacy', 'wireguard'].includes(protocol)
const canonical = (path) => path === 'awg-legacy' ? 'awglegacy' : path
const errors = []

async function fixture(protocol = 'awg', width = 1100) {
  const page = await browser.newPage({ viewport: { width, height: 1000 }, acceptDownloads: true })
  page.setDefaultTimeout(10000)
  page.on('pageerror', (error) => errors.push(error.message))
  const clients = new Map()
  const calls = []
  const control = { failCreate: false, failMetadata: false, failList: false, delayCreate: 0, delayConfig: 0, delayMetadata: 0 }
  const list = (key) => { if (!clients.has(key)) clients.set(key, []); return clients.get(key) }
  const response = (key, client) => {
    const conf = `[Interface]\n# synthetic ${client.public_key}\nAddress = ${client.address}\n`
    const amnezia = 'vpn://' + Buffer.from(`synthetic-${key}-${client.client_id}-`.repeat(80)).toString('base64url')
    if (key === 'wireguard') return { client, name: client.name, config: conf, filename: 'client.conf' }
    if (key === 'openvpn-native') return { client, name: client.name, config: `client\n# synthetic ${client.client_id}\nremote vpn.example.test 1194\n`, filename: 'client.ovpn' }
    return { client, name: client.name, ...(awgLike(key) ? { config: conf } : {}), config_amnezia: amnezia,
      ...(key === 'xray' ? { configs: [
        { key: 'vision', label: 'VLESS Reality', amnezia, uri: `vless://synthetic-${client.client_id}@vpn.example.test:443` },
        { key: 'xhttp', label: 'XHTTP', amnezia: amnezia + 'AA', uri: `vless://synthetic-${client.client_id}@vpn.example.test:443?type=xhttp` },
      ] } : {}) }
  }
  await page.route('**/api/**', async (route) => {
    const request = route.request()
    const url = new URL(request.url()).pathname
    const body = request.postDataJSON()
    calls.push({ url, method: request.method(), body })
    const fulfill = (data, status = 200) => route.fulfill({ status, contentType: 'application/json', body: status === 204 ? '' : JSON.stringify(data) })
    if (url === '/api/share/services') return fulfill([{ id: 'synthetic', name: 'Test sharing', engine: 'p', url: 'https://share.example.test' }])
    if (url === '/api/share') return fulfill({ url: 'https://share.example.test/one-time', ttl_days: 1 })
    if (url.endsWith('/torrent')) return fulfill({ clients: [] })
    if (url.endsWith('/version')) return fulfill({ deployed: true, current_version: 'test', update_available: false })
    if (url.endsWith('/client-metadata')) {
      if (control.delayMetadata) await new Promise((resolve) => setTimeout(resolve, control.delayMetadata))
      if (control.failMetadata) return fulfill({ detail: 'Synthetic metadata failure' }, 500)
      const client = list(body.protocol).find((client) => client.client_id === body.client_id || client.public_key === body.client_id)
      assert.ok(client)
      Object.assign(client, { group_name: body.group_name, device_name: body.device_name })
      return fulfill(null, 204)
    }
    const match = url.match(/^\/api\/servers\/1\/([^/]+)(?:\/(clients|config))?$/)
    if (!match) return fulfill([])
    const key = canonical(match[1])
    if (match[2] === 'clients') {
      if (control.delayCreate) await new Promise((resolve) => setTimeout(resolve, control.delayCreate))
      if (control.failCreate) return fulfill({ detail: 'Synthetic create failure' }, 500)
      const id = `${key}-${list(key).length + 1}`
      const client = { ...body, public_key: `public-${id}`, client_id: id, address: `10.8.0.${list(key).length + 2}/32`, has_config: true, note: body.note || '', latest_handshake: null, rx_bytes: 0, tx_bytes: 0, creation_date: '2026-01-01' }
      list(key).push(client)
      return fulfill(response(key, client))
    }
    if (match[2] === 'config') {
      if (control.delayConfig) await new Promise((resolve) => setTimeout(resolve, control.delayConfig))
      const client = list(key).find((client) => client.client_id === body.client_id || client.public_key === body.public_key)
      assert.ok(client, 'configuration is requested by the existing stable ID')
      return fulfill(response(key, client))
    }
    if (control.failList) return fulfill({ detail: 'Synthetic list failure' }, 500)
    return fulfill({ clients: list(key), interface: 'wg0', endpoint: 'vpn.example.test:51820', address: '10.8.0.0/24', params_v31: true, capabilities: {} })
  })
  await page.goto(`${base}tests/fixtures/quick-issue.html?protocol=${protocol}`)
  await page.getByRole('button', { name: '+ Выдать конфиг', exact: true }).waitFor()
  return { page, calls, clients, control }
}

const createCalls = (calls) => calls.filter((call) => call.method === 'POST' && call.url.endsWith('/clients'))
const ready = (page) => page.getByRole('region', { name: 'Готовый конфиг' })
async function openForm(page) {
  await page.getByRole('button', { name: '+ Выдать конфиг', exact: true }).click()
  assert.equal(await page.locator('.modal-backdrop').count(), 1, 'creation remains inline')
  assert.equal(await page.locator('.quick-issue-form details').getAttribute('open'), null)
  assert.equal(await page.locator('.quick-issue-form select').inputValue(), 'none')
}
async function create(page, name) {
  await page.getByRole('textbox', { name: 'Имя клиента', exact: true }).fill(name)
  await page.getByRole('button', { name: 'Создать конфиг', exact: true }).click()
  await ready(page).waitFor()
  await page.locator('.client-table tbody tr').last().waitFor()
}

try {
  for (const protocol of Object.keys(labels)) {
    const { page, calls, clients } = await fixture(protocol)
    await openForm(page)
    await create(page, 'same-name')
    assert.equal(createCalls(calls).length, 1)
    assert.equal(createCalls(calls)[0].body.expires_at, null, `${protocol} defaults to unlimited`)
    assert.equal(await page.locator('.modal-backdrop').count(), 1, 'ready output remains beside table')
    const text = await ready(page).locator('pre').innerText()
    if (protocol === 'openvpn-native') {
      assert.equal(await ready(page).locator('img, canvas').count(), 0, 'native OpenVPN offers file, no QR')
      assert.match(text, /^client/)
    } else {
      await ready(page).locator('img').first().waitFor()
    }
    if (protocol === 'wireguard') assert.match(text, /^\[Interface\]/)
    if (protocol === 'xray') {
      await ready(page).getByRole('button', { name: 'Ссылка vless://' }).click()
      assert.match(await ready(page).locator('pre').innerText(), /^vless:\/\//)
      await ready(page).getByRole('button', { name: 'XHTTP', exact: true }).click()
      assert.match(await ready(page).locator('pre').innerText(), /type=xhttp$/)
    }
    const exportedText = await ready(page).locator('pre').innerText()
    const downloadEvent = page.waitForEvent('download')
    await ready(page).getByRole('button', { name: /^Скачать/ }).click()
    const download = await downloadEvent
    assert.equal(await readFile(await download.path(), 'utf8'), exportedText)
    assert.ok(download.suggestedFilename().endsWith(protocol === 'openvpn-native' ? '.ovpn' : protocol === 'wireguard' ? '.conf' : '.txt'))
    await ready(page).getByRole('button', { name: 'Ссылка', exact: true }).click()
    await ready(page).locator('.share-link-url').waitFor()
    assert.equal(calls.findLast((call) => call.url === '/api/share').body.text, exportedText)
    await ready(page).getByRole('button', { name: 'Готово', exact: true }).click()
    await page.locator('.client-table').getByRole('button', { name: 'Конфиг', exact: true }).click()
    await ready(page).waitFor()
    assert.equal(createCalls(calls).length, 1, 'reopening fetches the same existing client')
    const configCall = calls.findLast((call) => call.url.endsWith('/config'))
    const client = clients.get(protocol)[0]
    assert.equal(awgLike(protocol) ? configCall.body.public_key : configCall.body.client_id, awgLike(protocol) ? client.public_key : client.client_id)
    await ready(page).getByRole('button', { name: 'Создать следующего' }).click()
    assert.equal(await page.getByRole('textbox', { name: 'Имя клиента', exact: true }).inputValue(), '')
    assert.equal(await page.locator('.quick-issue-form select').inputValue(), 'none')
    await create(page, 'same-name')
    assert.equal(createCalls(calls).length, 2)
    assert.equal(clients.get(protocol).length, 2, 'same names do not merge credentials')
    await page.close()
    console.log(`PASS ${protocol}: creation, unlimited default, real format controls, download/share, reopen, next`)
  }

  {
    const { page, calls, control } = await fixture()
    await openForm(page)
    await page.getByRole('textbox', { name: 'Имя клиента', exact: true }).fill('retry-name')
    await page.locator('.quick-issue-form summary').click()
    await page.getByRole('textbox', { name: 'Клиент / человек' }).fill('Person')
    await page.getByRole('textbox', { name: 'Устройство', exact: true }).fill('Laptop')
    await page.locator('.quick-issue-form select').selectOption('7')
    control.failCreate = true
    await page.getByRole('button', { name: 'Создать конфиг', exact: true }).click()
    await page.getByText('Synthetic create failure', { exact: true }).waitFor()
    assert.equal(await page.getByRole('textbox', { name: 'Имя клиента', exact: true }).inputValue(), 'retry-name')
    assert.equal(await page.getByRole('textbox', { name: 'Устройство', exact: true }).inputValue(), 'Laptop')
    control.failCreate = false
    control.delayCreate = 150
    await page.getByRole('button', { name: 'Создать конфиг', exact: true }).evaluate((button) => { button.click(); button.click() })
    await ready(page).waitFor()
    assert.equal(createCalls(calls).length, 2, 'failed attempt + one retry; double click sends no duplicate')
    assert.ok(createCalls(calls)[1].body.expires_at)
    assert.equal(createCalls(calls)[1].body.group_name, 'Person')
    await ready(page).getByRole('button', { name: 'Создать следующего' }).click()
    assert.equal(await page.locator('.quick-issue-form select').inputValue(), 'none', 'next never inherits finite expiry')
    await create(page, 'flat-next')
    assert.equal(createCalls(calls)[2].body.expires_at, null)
    assert.equal(createCalls(calls)[2].body.group_name, '')
    await ready(page).getByRole('button', { name: 'Готово', exact: true }).click()
    await page.getByRole('checkbox', { name: 'Группировать по клиенту' }).check()
    assert.equal(await page.locator('.client-group-heading').innerText(), 'Person')
    await page.getByPlaceholder('Поиск по имени или адресу…').fill('Laptop')
    assert.equal(await page.locator('.client-table tbody tr').count(), 1)
    await page.getByPlaceholder('Поиск по имени или адресу…').fill('')
    await page.locator('.client-table tbody tr').first().getByRole('button', { name: 'Ещё', exact: true }).click()
    await page.getByRole('button', { name: 'Клиент и устройство', exact: true }).click()
    control.failMetadata = true
    await page.getByRole('textbox', { name: 'Устройство', exact: true }).fill('Work computer')
    await page.getByRole('button', { name: 'Сохранить', exact: true }).click()
    await page.getByText('Synthetic metadata failure', { exact: true }).waitFor()
    assert.equal(await page.getByRole('textbox', { name: 'Устройство', exact: true }).inputValue(), 'Work computer')
    control.failMetadata = false
    await page.getByRole('button', { name: 'Сохранить', exact: true }).click()
    await page.locator('.client-device-label', { hasText: 'Work computer' }).waitFor()
    const update = calls.findLast((call) => call.url.endsWith('/client-metadata'))
    assert.equal(update.body.client_id, 'public-awg-1')
    assert.equal(createCalls(calls).length, 3, 'group editing does not regenerate credentials')
    await page.close()
    console.log('PASS failure/retry, double submit, finite expiry -> unlimited next, optional grouping/search/inline edit')
  }

  {
    const { page, control, calls } = await fixture()
    await openForm(page)
    control.delayCreate = 250
    await page.getByRole('textbox', { name: 'Имя клиента', exact: true }).fill('stale-awg')
    await page.getByRole('button', { name: 'Создать конфиг', exact: true }).click()
    await page.getByRole('button', { name: 'WireGuard', exact: true }).click()
    await page.getByRole('button', { name: '+ Выдать конфиг', exact: true }).waitFor()
    await page.waitForTimeout(350)
    assert.equal(await ready(page).count(), 0)
    assert.equal(await page.getByText('stale-awg', { exact: true }).count(), 0)
    assert.equal(createCalls(calls).length, 1)
    await page.close()
    console.log('PASS stale protocol response cannot show another protocol credentials')
  }

  for (const protocol of ['awg', 'xray', 'openvpn-native']) {
    const { page, calls, control } = await fixture(protocol)
    await openForm(page)
    control.failList = true
    await page.getByRole('textbox', { name: 'Имя клиента', exact: true }).fill('issued-once')
    await page.getByRole('button', { name: 'Создать конфиг', exact: true }).click()
    await ready(page).waitFor()
    await page.getByText('Synthetic list failure', { exact: true }).waitFor()
    assert.equal(createCalls(calls).length, 1, 'list failure never retries successful issuance')
    assert.match(await ready(page).locator('h3').innerText(), /issued-once/)
    await ready(page).getByRole('button', { name: 'Создать следующего' }).click()
    await page.getByRole('textbox', { name: 'Имя клиента', exact: true }).waitFor()
    assert.equal(createCalls(calls).length, 1, 'opening next form does not duplicate issuance')
    control.failList = false
    await create(page, 'explicit-next')
    assert.equal(createCalls(calls).length, 2)
    await page.close()
    console.log(`PASS ${protocol}: ready result and next form survive list refresh failure`)
  }

  for (const protocol of ['awg', 'xray', 'openvpn-native']) {
    const { page, calls, control } = await fixture(protocol)
    await openForm(page)
    await create(page, 'first-person')
    await ready(page).getByRole('button', { name: 'Создать следующего' }).click()
    await create(page, 'second-person')
    await ready(page).getByRole('button', { name: 'Готово', exact: true }).click()
    const rows = page.locator('.client-table tbody tr')
    control.delayConfig = 250
    await rows.nth(0).getByRole('button', { name: 'Конфиг', exact: true }).click()
    control.delayConfig = 0
    await rows.nth(1).getByRole('button', { name: 'Конфиг', exact: true }).click()
    await ready(page).locator('h3', { hasText: 'second-person' }).waitFor()
    await page.waitForTimeout(350)
    assert.match(await ready(page).locator('h3').innerText(), /second-person/)
    await ready(page).getByRole('button', { name: 'Готово', exact: true }).click()
    await rows.nth(0).getByRole('button', { name: 'Ещё', exact: true }).click()
    await page.getByRole('button', { name: 'Клиент и устройство', exact: true }).click()
    await page.getByRole('textbox', { name: 'Устройство', exact: true }).fill('First device')
    control.delayMetadata = 250
    await page.getByRole('button', { name: 'Сохранить', exact: true }).click()
    await rows.nth(1).getByRole('button', { name: 'Ещё', exact: true }).click()
    await page.getByRole('button', { name: 'Клиент и устройство', exact: true }).click()
    await page.waitForTimeout(350)
    assert.match(await page.locator('.quick-issue-form h4').innerText(), /second-person/)
    assert.equal(await page.getByRole('textbox', { name: 'Устройство', exact: true }).inputValue(), '')
    control.delayMetadata = 0
    await page.getByRole('textbox', { name: 'Устройство', exact: true }).fill('Second device')
    await page.getByRole('button', { name: 'Сохранить', exact: true }).click()
    await rows.nth(1).locator('.client-device-label', { hasText: 'Second device' }).waitFor()
    await rows.nth(0).locator('.client-device-label', { hasText: 'First device' }).waitFor()
    const updates = calls.filter((call) => call.url.endsWith('/client-metadata'))
    assert.notEqual(updates[0].body.client_id, updates[1].body.client_id)
    assert.equal(createCalls(calls).length, 2)
    await page.close()
    console.log(`PASS ${protocol}: late config and metadata responses preserve selected client identity`)
  }

  for (const width of [320, 390]) {
    for (const protocol of ['awg', 'xray', 'openvpn-native']) {
      const { page } = await fixture(protocol, width)
      await openForm(page)
      await create(page, 'long-client-name-with-device-and-no-spaces-1234567890')
      await ready(page).getByRole('button', { name: 'Готово', exact: true }).click()
      const table = page.locator('.client-table')
      assert.ok(await table.evaluate((node) => node.scrollWidth <= node.clientWidth + 1), `${protocol} table fits ${width}`)
      for (const locator of [table.locator('.name-cell').first(), table.getByRole('button', { name: 'Конфиг', exact: true }), ...(awgLike(protocol) ? [table.locator('tbody td:nth-child(3)').first()] : [])]) {
        const box = await locator.boundingBox()
        assert.ok(box && box.x >= 0 && box.x + box.width <= width, `${protocol} primary data visible at ${width}`)
      }
      assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), `page fits ${width}`)
      await page.locator('.client-table-options summary').click()
      await page.getByRole('checkbox', { name: 'Показать все столбцы' }).check()
      assert.ok(await table.locator('tbody td:nth-last-child(2)').isVisible(), 'secondary fields remain accessible')
      await page.close()
    }
    console.log(`PASS ${width}px: name/address/config visible, no horizontal scroll, optional full columns`)
  }
  assert.deepEqual(errors, [], 'no browser errors')
} finally {
  await browser.close()
  await server.close()
}
