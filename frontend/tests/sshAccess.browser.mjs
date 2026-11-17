// Actual React workflow with an in-memory API; no SSH host is contacted.
import assert from 'node:assert/strict'
import { existsSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { createServer } from 'vite'
import { chromium } from 'playwright'

const root = fileURLToPath(new URL('..', import.meta.url)).replaceAll('\\', '/').replace(/\/$/, '')
const fixtureId = root + '/src/__ssh_access_workflow.tsx'
const fixture = `import {createRoot} from 'react-dom/client';
import {I18nProvider} from '/src/i18n';import {ServersPage} from '/src/ServersPage';
import '/src/index.css';import '/src/App.css';
createRoot(document.getElementById('root')!).render(<I18nProvider><ServersPage onUnauthorized={()=>{throw Error('Unexpected logout')}}/></I18nProvider>);`
const vite = await createServer({ root, server: { host: '127.0.0.1', port: 0 }, plugins: [{
  name: 'ssh-access-workflow',
  enforce: 'pre',
  resolveId(id) { if (id === '/__ssh_access_workflow.tsx') return fixtureId },
  load(id) { if (id === fixtureId) return fixture },
  configureServer(server) {
    server.middlewares.use(async (req, res, next) => {
      if (req.url !== '/__ssh_access_workflow.html') return next()
      res.setHeader('Content-Type', 'text/html')
      res.end(await server.transformIndexHtml(req.url, '<html lang="ru"><div id="root"></div><script type="module" src="/__ssh_access_workflow.tsx"></script></html>'))
    })
  },
}] })
await vite.listen()
const executablePath = process.env.CHROME_PATH || ['C:/Program Files/Google/Chrome/Application/chrome.exe', '/usr/bin/chromium', '/usr/bin/google-chrome'].find(existsSync)
const browser = await chromium.launch({ headless: true, ...(executablePath ? { executablePath } : {}) })
const page = await browser.newPage({ viewport: { width: 1100, height: 1000 } })
const pageErrors = []
page.on('pageerror', error => pageErrors.push(error.message))
const node = id => ({
  id, name: `Node ${id}`, host: `192.0.2.${id}`, ssh_port: 22, ssh_user: 'acontrol',
  client_endpoint: '', note: '', group_name: '', position: id, country: '', country_override: '',
  torrent_block: false, torrent_autopause: false, alerts_enabled: false, last_check_ok: true,
  last_check_info: JSON.stringify({ hostname: `node-${id}`, amnezia_containers: [] }),
  ssh_jump_server_id: null, ssh_source_mode: 'panel', ssh_source_ips: [], ssh_firewall_mode: 'add', ssh_access_pending: false,
})
const nodes = [node(1), node(2)]
const calls = []
let failMetadata = true
let proposed
try {
  await page.addInitScript(() => localStorage.setItem('acontrol_lang', 'ru'))
  await page.route('**/api/**', async route => {
    const request = route.request()
    const path = new URL(request.url()).pathname
    const method = request.method()
    const body = request.postDataJSON()
    calls.push({ path, method, body })
    const respond = (value, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(value) })
    if (path === '/api/servers' && method === 'GET') return respond(nodes)
    if (path === '/api/config') return respond({ default_ssh_user: 'acontrol', panel_ip: '203.0.113.7', protocols: [] })
    if (path === '/api/stats/overview') return respond({ per_server: [] })
    if (path === '/api/servers/1/ssh-access/preview') {
      proposed = structuredClone(body)
      return respond({ token: '1'.repeat(32), sources: [], unrestricted: true, firewall: 'add', actions: [], jump_user: null })
    }
    if (path === '/api/servers/1/ssh-access/apply') {
      Object.assign(nodes[0], proposed)
      return respond(nodes[0])
    }
    if (path === '/api/servers/1' && method === 'PATCH') {
      if (failMetadata) return respond({ detail: 'Synthetic metadata save failure' }, 409)
      Object.assign(nodes[0], body)
      return respond(nodes[0])
    }
    if (path === '/api/servers/2' && method === 'PATCH') {
      Object.assign(nodes[1], body)
      return respond(nodes[1])
    }
    return respond([])
  })
  await page.goto(vite.resolvedUrls.local[0] + '__ssh_access_workflow.html')
  const form = page.locator('form.modal')
  async function edit(name) {
    await page.locator('.srv-item').filter({ hasText: name }).click()
    await page.locator('.srv-detail').getByRole('button', { name: 'Ещё' }).click()
    await page.getByRole('button', { name: 'Изменить', exact: true }).click()
  }
  await edit('Node 1')
  await form.locator('.ssh-access-options summary').click()
  await form.getByLabel('Разрешенные источники ключа панели').selectOption('any')
  await form.getByRole('button', { name: 'Сохранить', exact: true }).click()
  await form.getByText('Предпросмотр изменения SSH', { exact: true }).waitFor()
  await form.getByRole('button', { name: 'Применить SSH и сохранить', exact: true }).click()
  await form.getByText('Synthetic metadata save failure', { exact: true }).waitFor()
  assert.equal(nodes[0].ssh_source_mode, 'any', 'SSH was already committed before the metadata failure')
  failMetadata = false
  await form.getByLabel('Имя', { exact: true }).fill('Saved node')
  await form.getByRole('button', { name: 'Сохранить', exact: true }).click()
  await form.waitFor({ state: 'hidden' })
  assert.equal(calls.filter(call => call.path.endsWith('/ssh-access/preview')).length, 1)
  assert.equal(calls.filter(call => call.path.endsWith('/ssh-access/apply')).length, 1)
  assert.equal(nodes[0].name, 'Saved node')
  // Updating one record must retain another record and survive the list reload.
  await edit('Node 2')
  await form.getByLabel('Имя', { exact: true }).fill('Other node')
  await form.getByRole('button', { name: 'Сохранить', exact: true }).click()
  await form.waitFor({ state: 'hidden' })
  await edit('Saved node')
  await form.locator('.ssh-access-options summary').click()
  assert.equal(await form.getByLabel('Разрешенные источники ключа панели').inputValue(), 'any')
  assert.equal(nodes[1].name, 'Other node')
  assert.deepEqual(pageErrors, [])
  console.log('PASS SSH apply + metadata failure retries metadata only and preserves other records')
} finally {
  await browser.close()
  await vite.close()
}
