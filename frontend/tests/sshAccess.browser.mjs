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
      if (req.url?.split('?')[0] !== '/__ssh_access_workflow.html') return next()
      res.setHeader('Content-Type', 'text/html')
      res.end(await server.transformIndexHtml(req.url, '<html lang="ru"><div id="root"></div><script type="module" src="/__ssh_access_workflow.tsx"></script></html>'))
    })
  },
}] })
await vite.listen()
const executablePath = process.env.CHROME_PATH || ['C:/Program Files/Google/Chrome/Application/chrome.exe', '/usr/bin/chromium', '/usr/bin/google-chrome'].find(existsSync)
const browser = await chromium.launch({ headless: true, ...(executablePath ? { executablePath } : {}) })
async function workflow(scenario) {
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
  let metadataFailures = 2
  const previews = new Map()
  const policyFields = ['ssh_jump_server_id', 'ssh_source_mode', 'ssh_source_ips', 'ssh_firewall_mode']
  function canonicalize(body) {
    if (JSON.stringify(body.ssh_source_ips) !== JSON.stringify(scenario.input)) return body
    return { ...body, ssh_source_ips: scenario.canonical }
  }
  const holds = new Map()
  const previewPath = '/api/servers/1/ssh-access/preview'
  const applyPath = '/api/servers/1/ssh-access/apply'
  const patchPath = '/api/servers/1'
  function holdResponse(path) {
    const started = page.waitForRequest(request => new URL(request.url()).pathname === path)
    const response = Promise.withResolvers()
    holds.set(path, response.promise)
    return { started, release: response.resolve }
  }
  try {
    await page.addInitScript(() => localStorage.setItem('acontrol_lang', 'ru'))
    await page.route('**/api/**', async route => {
      const request = route.request()
      const path = new URL(request.url()).pathname
      const method = request.method()
      const body = request.postDataJSON()
      calls.push({ path, method, body })
      const hold = holds.get(path)
      if (hold) {
        holds.delete(path)
        await hold
      }
      const respond = (value, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(value) })
      if (path === '/api/servers' && method === 'GET') return respond(nodes)
      if (path === '/api/config') return respond({ default_ssh_user: 'acontrol', panel_ip: '203.0.113.7', protocols: [] })
      if (path === '/api/stats/overview') return respond({ per_server: [] })
      if (path === previewPath) {
        const token = String(previews.size + 1).padStart(32, '0')
        const policy = canonicalize(body)
        const sources = policy.ssh_source_ips
        previews.set(token, policy)
        return respond({ token, sources, unrestricted: body.ssh_source_mode === 'any', firewall: body.ssh_firewall_mode, actions: [], jump_user: null })
      }
      if (path === applyPath) {
        assert.ok(previews.has(body.token), 'Apply must use a token issued for the chosen preview')
        Object.assign(nodes[0], previews.get(body.token))
        return respond(nodes[0])
      }
      if (method === 'PATCH' && (path === patchPath || path === '/api/servers/2')) {
        if (path === patchPath && metadataFailures) return respond({ detail: `Synthetic metadata save failure ${3 - metadataFailures--}` }, 409)
        const record = path === patchPath ? nodes[0] : nodes[1]
        const changes = canonicalize(body)
        if (policyFields.some(key => key in changes && JSON.stringify(changes[key]) !== JSON.stringify(record[key]))) {
          return respond({ detail: 'SSH policy must already be applied' }, 409)
        }
        Object.assign(record, changes)
        return respond(record)
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
    const name = form.getByLabel('Имя', { exact: true })
    const mode = form.getByLabel('Разрешенные источники ключа панели')
    const sources = form.getByLabel('IP или CIDR через запятую')
    const save = form.getByRole('button', { name: 'Сохранить', exact: true })
    const apply = form.getByRole('button', { name: 'Применить SSH и сохранить', exact: true })
    const cancel = form.getByRole('button', { name: 'Отмена', exact: true })
    const preview = form.getByText('Предпросмотр изменения SSH', { exact: true })
    async function assertFormLocked(phase) {
      const saving = form.getByRole('button', { name: 'Сохранение…', exact: true })
      await saving.waitFor()
      assert.equal(await saving.isDisabled(), true, phase + ' must prevent repeat submission')
      assert.equal(await sources.isDisabled(), true, phase + ' must prevent editing SSH sources')
      assert.equal(await name.isDisabled(), true, phase + ' must prevent editing metadata')
      assert.equal(await cancel.isDisabled(), true, phase + ' must prevent cancel')
      await page.keyboard.press('Escape')
      assert.equal(await form.isVisible(), true, phase + ' must keep the original editor open')
    }

    await edit('Node 1')
    await name.fill('Unsaved metadata')
    await form.locator('.ssh-access-options summary').click()
    await mode.selectOption(scenario.mode)
    if (scenario.mode === 'custom') await sources.fill(scenario.input.join(', '))
    let expectedSources = scenario.canonical
    let expectedPreviewCount = 1
    if (scenario.delayed) {
      const pending = holdResponse(previewPath)
      await save.click()
      try {
        assert.deepEqual((await pending.started).postDataJSON().ssh_source_ips, scenario.input)
        await assertFormLocked('Preview')
      } finally {
        pending.release()
      }
      await preview.waitFor()
      assert.equal(await cancel.isEnabled(), true)
      expectedSources = ['198.51.100.9']
      await sources.fill(expectedSources[0])
      await preview.waitFor({ state: 'hidden' })
      expectedPreviewCount++
    }
    await save.click()
    await preview.waitFor()
    if (scenario.delayed) {
      assert.deepEqual(calls.filter(call => call.path === previewPath).at(-1).body.ssh_source_ips, expectedSources)
      const pendingApply = holdResponse(applyPath)
      const pendingPatch = holdResponse(patchPath)
      await apply.click()
      try {
        const { token } = (await pendingApply.started).postDataJSON()
        assert.equal(token, Array.from(previews.keys()).at(-1))
        assert.deepEqual(previews.get(token).ssh_source_ips, expectedSources)
        await assertFormLocked('Apply')
        await page.locator('.srv-item').filter({ hasText: 'Node 2' }).press('Enter')
        await page.locator('.srv-detail').getByRole('button', { name: 'Ещё' }).press('Enter')
        await page.getByRole('button', { name: 'Изменить', exact: true }).press('Enter')
        assert.equal(await name.inputValue(), 'Unsaved metadata', 'Another editor must not replace the active draft')
        pendingApply.release()
        assert.equal((await pendingPatch.started).postDataJSON().name, 'Unsaved metadata')
        await assertFormLocked('Metadata PATCH')
      } finally {
        pendingApply.release()
        pendingPatch.release()
      }
    } else {
      await apply.click()
    }
    await form.getByText('Synthetic metadata save failure 1', { exact: true }).waitFor()
    assert.equal(nodes[0].ssh_source_mode, scenario.mode, 'SSH was already committed before the metadata failure')
    assert.equal(await form.getByLabel('Имя', { exact: true }).inputValue(), 'Unsaved metadata', 'Apply must retain unsaved metadata')
    if (scenario.mode === 'custom') assert.equal(await form.getByLabel('IP или CIDR через запятую').inputValue(), expectedSources.join(', '), 'Form must retain the canonical committed policy')
    await form.getByLabel('Заметка', { exact: true }).fill('New draft note')
    await save.click()
    await form.getByText('Synthetic metadata save failure 2', { exact: true }).waitFor()
    assert.equal(calls.filter(call => call.path === patchPath && call.method === 'PATCH').at(-1).body.note, 'New draft note')
    assert.equal(calls.filter(call => call.path === previewPath).length, expectedPreviewCount)
    assert.equal(calls.filter(call => call.path === applyPath).length, 1)
    await form.getByLabel('Имя', { exact: true }).fill('Saved node')
    await form.getByRole('button', { name: 'Сохранить', exact: true }).click()
    await form.waitFor({ state: 'hidden' })
    assert.equal(calls.filter(call => call.path === previewPath).length, expectedPreviewCount)
    assert.equal(calls.filter(call => call.path === applyPath).length, 1)
    assert.equal(calls.filter(call => call.path === '/api/servers/1' && call.method === 'PATCH').length, 3)
    assert.equal(nodes[0].name, 'Saved node')
    assert.equal(nodes[0].note, 'New draft note')
    // Updating one record must retain another record and survive the list reload.
    await edit('Node 2')
    assert.equal(await name.inputValue(), 'Node 2')
    await form.locator('.ssh-access-options summary').click()
    assert.equal(await mode.inputValue(), 'panel')
    assert.equal(await form.getByRole('alert').count(), 0)
    await name.fill('Other node')
    await form.getByRole('button', { name: 'Сохранить', exact: true }).click()
    await form.waitFor({ state: 'hidden' })
    await page.reload()
    await edit('Saved node')
    await form.locator('.ssh-access-options summary').click()
    assert.equal(await form.getByLabel('Разрешенные источники ключа панели').inputValue(), scenario.mode)
    if (scenario.mode === 'custom') assert.equal(await form.getByLabel('IP или CIDR через запятую').inputValue(), expectedSources.join(', '))
    assert.equal(nodes[1].name, 'Other node')
    assert.equal(nodes[1].ssh_source_mode, 'panel')
    assert.deepEqual(nodes[0].ssh_source_ips, expectedSources)
    await page.keyboard.press('Escape')
    await form.waitFor({ state: 'hidden' })
    assert.deepEqual(pageErrors, [])
    console.log(`PASS SSH apply + repeated metadata failure retries metadata only: ${scenario.mode} ${scenario.input.join(', ')}`)
    if (scenario.delayed) console.log('PASS delayed preview, apply and PATCH preserve the active draft and the next editor')
  } finally {
    await page.close()
  }
}
try {
  for (const scenario of [
    { mode: 'any', input: [], canonical: [] },
    { mode: 'custom', input: ['203.0.113.7/32', '2001:0db8::7/128', '203.0.113.7/32'], canonical: ['203.0.113.7', '2001:db8::7'] },
    { mode: 'custom', input: ['203.0.113.7/24', '2001:0db8::7/64'], canonical: ['203.0.113.0/24', '2001:db8::/64'] },
    { mode: 'custom', input: ['203.0.113.7/32'], canonical: ['203.0.113.7'], delayed: true },
  ]) await workflow(scenario)
} finally {
  await browser.close()
  await vite.close()
}
