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
createRoot(document.getElementById('root')!).render(<I18nProvider><ServersPage onUnauthorized={()=>{document.body.dataset.unauthorized = 'true'}}/></I18nProvider>);`
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
const workflowUrl = vite.resolvedUrls.local[0] + '__ssh_access_workflow.html'
const node = id => ({
  id, name: `Node ${id}`, host: `192.0.2.${id}`, ssh_port: 22, ssh_user: 'acontrol',
  client_endpoint: '', note: '', group_name: '', position: id, country: '', country_override: '',
  torrent_block: false, torrent_autopause: false, alerts_enabled: false, last_check_ok: true,
  last_check_info: JSON.stringify({ hostname: `node-${id}`, amnezia_containers: [] }),
  ssh_jump_server_id: null, ssh_source_mode: 'panel', ssh_source_ips: [], ssh_firewall_mode: 'add', ssh_access_pending: false,
})
const policyFields = ['ssh_jump_server_id', 'ssh_source_mode', 'ssh_source_ips', 'ssh_firewall_mode']
const partialSaveMessage = 'Настройки SSH применены. Остальные изменения еще не сохранены.'

function assertMetadataOnly(body) {
  assert.equal(policyFields.some(key => key in body), false, 'Metadata PATCH must omit SSH policy')
}

async function openMenu(page, name) {
  await page.locator('.srv-item').filter({ hasText: name }).click()
  await page.locator('.srv-detail').getByRole('button', { name: 'Ещё' }).click()
}

async function workflow(scenario) {
  const page = await browser.newPage({ viewport: { width: 1100, height: 1000 } })
  const pageErrors = []
  page.on('pageerror', error => pageErrors.push(error.message))
  const nodes = [node(1), { ...node(2), ssh_source_ips: ['198.51.100.6'] }]
  const calls = []
  let metadataFailures = 2
  const previews = new Map()
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
        if (body.ssh_source_mode !== 'custom') assert.deepEqual(body.ssh_source_ips, [], 'Hidden custom draft must be omitted from the preview')
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
        assertMetadataOnly(body)
        if (path === patchPath && metadataFailures) return respond({ detail: `Synthetic metadata save failure ${3 - metadataFailures--}` }, 409)
        const record = path === patchPath ? nodes[0] : nodes[1]
        Object.assign(record, body)
        return respond(record)
      }
      return respond([])
    })
    await page.goto(workflowUrl)
    const form = page.locator('form.modal')
    async function edit(name) {
      await openMenu(page, name)
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
    if (scenario.mode === 'any') {
      await mode.selectOption('custom')
      await sources.fill('unfinished CIDR draft')
    }
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
    await form.getByRole('status').getByText(partialSaveMessage).waitFor()
    assert.equal(nodes[0].ssh_source_mode, scenario.mode, 'SSH was already committed before the metadata failure')
    assert.equal(await form.getByLabel('Имя', { exact: true }).inputValue(), 'Unsaved metadata', 'Apply must retain unsaved metadata')
    if (scenario.mode === 'custom') assert.equal(await form.getByLabel('IP или CIDR через запятую').inputValue(), expectedSources.join(', '), 'Form must retain the canonical committed policy')
    await form.getByLabel('Заметка', { exact: true }).fill('New draft note')
    await save.click()
    await form.getByText('Synthetic metadata save failure 2', { exact: true }).waitFor()
    await form.getByRole('status').getByText(partialSaveMessage).waitFor()
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
    assert.deepEqual(nodes[1].ssh_source_ips, ['198.51.100.6'])
    assert.deepEqual(nodes[0].ssh_source_ips, expectedSources)
    await page.keyboard.press('Escape')
    await form.waitFor({ state: 'hidden' })
    assert.deepEqual(pageErrors, [])
    assert.equal(await page.locator('body').getAttribute('data-unauthorized'), null)
    console.log(`PASS SSH apply + repeated metadata failure retries metadata only: ${scenario.mode} ${scenario.input.join(', ')}`)
    if (scenario.delayed) console.log('PASS delayed preview, apply and PATCH preserve the active draft and the next editor')
  } finally {
    await page.close()
  }
}

async function editorWorkflow(run) {
  const page = await browser.newPage({ viewport: { width: 1100, height: 1000 } })
  page.setDefaultTimeout(4000)
  const nodes = [node(1), { ...node(2), ssh_access_pending: true }]
  const calls = []
  const routes = new Map()
  const errors = []
  page.on('pageerror', error => errors.push(error.message))
  try {
    await page.addInitScript(() => localStorage.setItem('acontrol_lang', 'ru'))
    await page.route('**/api/**', async route => {
      const request = route.request()
      const path = new URL(request.url()).pathname
      const key = `${request.method()} ${path}`
      const body = request.postDataJSON()
      calls.push({ key, body })
      const respond = (value, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(value) })
      const handler = routes.get(key)
      if (handler) return handler(body, respond)
      if (key === 'GET /api/servers') return respond(nodes)
      if (key === 'GET /api/config') return respond({ default_ssh_user: 'test-user', panel_ip: '203.0.113.7', protocols: [] })
      if (key === 'GET /api/stats/overview') return respond({ per_server: [] })
      if (key === 'GET /api/stats/nodes' || key === 'GET /api/cascades') return respond([])
      throw new Error(`Unexpected request: ${key}`)
    })
    await page.goto(workflowUrl)
    await page.locator('.srv-item').filter({ hasText: 'Node 1' }).waitFor()
    const form = page.locator('form.modal')
    const save = form.getByRole('button', { name: 'Сохранить', exact: true })
    const name = form.getByLabel('Имя', { exact: true })
    const recover = { name: 'Восстановить настройку SSH', exact: true }
    async function edit(server) {
      await openMenu(page, server)
      await page.getByRole('button', { name: 'Изменить', exact: true }).click()
    }
    await run({ page, form, save, name, edit, recover, nodes, calls, routes })
    assert.deepEqual(errors, [])
  } finally {
    await page.close()
  }
}

async function bootstrapUnauthorized({ page, form, save, name, nodes, calls, routes }) {
  routes.set('POST /api/servers', (body, respond) => {
    nodes.push({ ...node(3), ...body })
    return respond(nodes[2], 201)
  })
  routes.set('POST /api/servers/3/host-key', (_body, respond) => respond({ known: true }))
  routes.set('POST /api/servers/3/bootstrap', (_body, respond) => respond({ detail: 'Synthetic bootstrap session expired' }, 401))
  await page.getByRole('button', { name: '+ Добавить сервер', exact: true }).click()
  await name.fill('New node')
  await form.getByLabel('Хост (IP или домен)').fill('192.0.2.3')
  await form.getByLabel(/^SSH-пароль пользователя/).fill('fixture-password')
  await save.click()
  await page.locator('body[data-unauthorized="true"]').waitFor()
  await form.waitFor({ state: 'hidden' })
  assert.equal(calls.filter(call => call.key === 'GET /api/servers').length, 1)
  assert.equal(calls.filter(call => call.key === 'POST /api/servers').length, 1)
  assert.deepEqual(calls.find(call => call.key === 'POST /api/servers/3/bootstrap').body,
    { password: 'fixture-password', become_password: null, host_key_fingerprint: null })
}

async function manualOnboarding({ page, form, save, name, nodes, calls, routes }) {
  const stored = ['203.0.113.10/32', '198.51.100.0/24', '2001:db8::/64']
  const draft = '203.0.113.10/32,  198.51.100.0/24, 2001:db8::/64, '
  const mode = form.getByLabel('Разрешенные источники ключа панели')
  const sources = form.getByLabel('IP или CIDR через запятую')
  const firewall = form.getByLabel('Firewall сервера')
  let createAttempts = 0
  routes.set('POST /api/servers', (body, respond) => {
    createAttempts++
    if (createAttempts === 1) {
      assert.deepEqual(body.ssh_source_ips, [...stored, 'invalid'])
      return respond({ detail: 'Источники SSH должны быть IP-адресами или CIDR' }, 422)
    }
    assert.equal(body.ssh_source_mode, 'panel')
    assert.deepEqual(body.ssh_source_ips, [])
    assert.equal(body.ssh_firewall_mode, 'preserve')
    assert.equal(body.ssh_jump_server_id, 1)
    assert.equal(body.name, 'Added manually')
    assert.equal(body.host, '192.0.2.3')
    assert.equal(body.ssh_port, 2221)
    nodes.push({ ...node(3), ...body, last_check_ok: null })
    return respond(nodes[2], 201)
  })
  let scriptAttempts = 0
  routes.set('GET /api/servers/3/setup-script', (_body, respond) => {
    scriptAttempts++
    return scriptAttempts === 1
      ? respond({ detail: 'Synthetic setup script error' }, 503)
      : respond({ script: '# test setup script' })
  })
  await page.getByRole('button', { name: '+ Добавить сервер', exact: true }).click()
  await name.fill('Added manually')
  await form.getByLabel('Хост (IP или домен)').fill('192.0.2.3')
  await form.getByLabel('SSH-порт', { exact: true }).fill('2221')
  await form.locator('.ssh-access-options summary').click()
  await form.getByLabel('Подключение', { exact: true }).selectOption('1')
  await mode.selectOption('custom')
  await sources.pressSequentially(draft)
  assert.equal(await sources.inputValue(), draft)
  // Inserting a space mid-list must preserve the caret for the next keystroke.
  await sources.press('Home')
  for (let index = 0; index < stored[0].length + 1; index++) await sources.press('ArrowRight')
  await sources.press('Space')
  assert.equal(await sources.inputValue(), draft.replace(',  ', ',   '))
  assert.equal(await sources.evaluate(el => el.selectionStart), stored[0].length + 2)
  await sources.press('End')
  await sources.pressSequentially('invalid')
  await firewall.selectOption('preserve')
  await form.getByRole('radio', { name: /Скриптом/ }).check()
  await save.click()
  await form.getByRole('alert').getByText('Источники SSH должны быть IP-адресами или CIDR').waitFor()
  assert.equal(await name.inputValue(), 'Added manually')
  assert.equal(await firewall.inputValue(), 'preserve')
  assert.equal(await sources.inputValue(), draft.replace(',  ', ',   ') + 'invalid')
  await mode.selectOption('panel')
  await mode.selectOption('custom')
  assert.equal(await sources.inputValue(), draft.replace(',  ', ',   ') + 'invalid')
  await mode.selectOption('panel')
  await save.dblclick()
  await form.waitFor({ state: 'hidden' })
  await page.getByRole('heading', { name: 'Подготовка сервера «Added manually»', exact: true }).waitFor()
  await page.getByRole('alert').getByText('Synthetic setup script error').waitFor()
  await page.getByRole('button', { name: 'Повторить', exact: true }).click()
  await page.getByText('# test setup script', { exact: true }).waitFor()
  assert.equal(createAttempts, 2)
  assert.equal(scriptAttempts, 2)
  assert.equal(calls.filter(call => call.key.endsWith('/bootstrap') || call.key.endsWith('/ssh-access/preview')).length, 0)
}

async function passwordOnboarding({ page, form, save, name, nodes, calls, routes }, fail = false) {
  const registration = Promise.withResolvers()
  routes.set('POST /api/servers', async (body, respond) => {
    assert.equal(body.ssh_source_mode, 'custom')
    assert.deepEqual(body.ssh_source_ips, ['198.51.100.0/24', '2001:db8::/64'])
    assert.equal(body.ssh_firewall_mode, 'preserve')
    assert.ok(!('password' in body) && !('become_password' in body))
    await registration.promise
    nodes.push({ ...node(3), ...body, last_check_ok: null })
    return respond(nodes[2], 201)
  })
  routes.set('POST /api/servers/3/host-key', (_body, respond) => respond({ known: true }))
  routes.set('POST /api/servers/3/bootstrap', (body, respond) => {
    assert.deepEqual(body, { password: 'fixture-password', become_password: 'fixture-sudo', host_key_fingerprint: null })
    if (fail) return respond({ detail: 'Synthetic SSH authentication failure' }, 400)
    nodes[2].last_check_ok = true
    return respond(nodes[2])
  })
  routes.set('GET /api/servers/3/setup-script', (_body, respond) => respond({ script: '# fallback setup script' }))
  await page.getByRole('button', { name: '+ Добавить сервер', exact: true }).click()
  await name.fill('Added by password')
  await form.getByLabel('Хост (IP или домен)').fill('192.0.2.3')
  await form.locator('.ssh-access-options summary').click()
  const mode = form.getByLabel('Разрешенные источники ключа панели')
  await mode.selectOption('custom')
  const sources = form.getByLabel('IP или CIDR через запятую')
  await sources.pressSequentially('198.51.100.0/24, 2001:db8::/64, ')
  await form.getByLabel('Firewall сервера').selectOption('preserve')
  await save.click()
  assert.equal(calls.filter(call => call.key === 'POST /api/servers').length, 0)
  await form.getByLabel(/^SSH-пароль пользователя/).fill('fixture-password')
  await form.getByRole('button', { name: 'Отдельный пароль для sudo?', exact: true }).click()
  await form.getByLabel('Пароль для sudo (если отличается)').fill('fixture-sudo')
  const started = page.waitForRequest(request => request.method() === 'POST' && new URL(request.url()).pathname === '/api/servers')
  try {
    await save.dblclick()
    await started
    assert.equal(await sources.isDisabled(), true)
    assert.equal(await form.getByRole('button', { name: 'Создание…' }).isDisabled(), true)
    await page.keyboard.press('Escape')
    assert.equal(await form.isVisible(), true)
  } finally {
    registration.resolve()
  }
  await form.waitFor({ state: 'hidden' })
  if (fail) {
    await page.getByRole('alert').getByText(/Synthetic SSH authentication failure/).waitFor()
    await page.getByText('# fallback setup script', { exact: true }).waitFor()
    await page.getByRole('button', { name: 'Закрыть', exact: true }).click()
  } else {
    await page.getByText('Сервер «Added by password» настроен и подключён.', { exact: true }).waitFor()
  }
  assert.deepEqual(calls.filter(call => call.key.startsWith('POST ')).map(call => call.key),
    ['POST /api/servers', 'POST /api/servers/3/host-key', 'POST /api/servers/3/bootstrap'])
  assert.equal(calls.filter(call => call.key === 'GET /api/servers/3/setup-script').length, fail ? 1 : 0)
  await page.getByRole('button', { name: '+ Добавить сервер', exact: true }).click()
  assert.equal(await form.getByLabel(/^SSH-пароль пользователя/).inputValue(), '')
  await form.getByRole('button', { name: 'Отдельный пароль для sudo?', exact: true }).click()
  assert.equal(await form.getByLabel('Пароль для sudo (если отличается)').inputValue(), '')
  await form.locator('.ssh-access-options summary').click()
  await mode.selectOption('custom')
  assert.equal(await sources.inputValue(), '')
}

async function passwordOnboardingFailure(context) {
  await passwordOnboarding(context, true)
}

async function recoveryUnauthorized({ page, form, edit, recover, calls, routes }) {
  routes.set('POST /api/servers/2/ssh-access/recover', (_body, respond) => respond({ detail: 'Synthetic recovery session expired' }, 401))
  await edit('Node 2')
  await form.getByRole('button', recover).click()
  await page.locator('body[data-unauthorized="true"]').waitFor()
  assert.equal(calls.filter(call => call.key === 'GET /api/servers').length, 1)
}

async function recoveryMenuKeepsDraft({ page, form, save, name, edit, recover, nodes, calls, routes }) {
  routes.set('POST /api/servers/1/ssh-access/preview', (body, respond) => respond({ token: 'fixture', sources: body.ssh_source_ips, unrestricted: false, firewall: 'add', actions: [], jump_user: null }))
  routes.set('POST /api/servers/2/ssh-access/recover', (_body, respond) => respond({ detail: 'Synthetic recovery failure' }, 409))
  await edit('Node 1')
  await name.fill('Unsaved node')
  await form.locator('.ssh-access-options summary').click()
  await form.getByLabel('Разрешенные источники ключа панели').selectOption('custom')
  await form.getByLabel('IP или CIDR через запятую').fill('198.51.100.9')
  await save.click()
  const preview = form.getByText('Предпросмотр изменения SSH', { exact: true })
  await preview.waitFor()
  await page.locator('.srv-item').filter({ hasText: 'Node 2' }).press('Enter')
  await page.locator('.srv-detail').getByRole('button', { name: 'Ещё' }).press('Enter')
  const menuRecovery = page.locator('.srv-detail').getByRole('button', recover)
  assert.equal(await menuRecovery.isDisabled(), true, 'Background recovery must be disabled while the editor is open')
  await page.keyboard.press('Tab')
  await page.keyboard.press('Escape')
  assert.equal(await form.isVisible(), true, 'Escape closes the background menu before the editor')
  assert.equal(await name.inputValue(), 'Unsaved node')
  assert.equal(await preview.isVisible(), true)
  assert.equal(await form.getByRole('alert').count(), 0)
  assert.equal(calls.filter(call => call.key === 'POST /api/servers/2/ssh-access/recover').length, 0, 'The background recovery action must not affect the active editor')

  await form.getByRole('button', { name: 'Отмена', exact: true }).click()
  await openMenu(page, 'Node 2')
  await menuRecovery.click()
  await page.locator('.form-error').filter({ hasText: 'Synthetic recovery failure' }).waitFor()
  await edit('Node 2')
  await name.fill('Recovered node')
  const editorRecovery = form.getByRole('button', recover)
  assert.equal(await save.isDisabled(), true)
  await editorRecovery.click()
  await form.getByRole('alert').filter({ hasText: 'Synthetic recovery failure' }).waitFor()
  assert.equal(await save.isDisabled(), true)
  assert.equal(await editorRecovery.isEnabled(), true)

  routes.set('POST /api/servers/2/ssh-access/recover', (_body, respond) => {
    nodes[1].ssh_access_pending = false
    return respond(nodes[1])
  })
  routes.set('PATCH /api/servers/2', (body, respond) => {
    Object.assign(nodes[1], body)
    return respond(nodes[1])
  })
  await editorRecovery.click()
  await editorRecovery.waitFor({ state: 'hidden' })
  assert.equal(await name.inputValue(), 'Recovered node')
  assert.equal(await form.getByRole('alert').count(), 0)
  await save.click()
  await form.waitFor({ state: 'hidden' })
  assert.equal(calls.filter(call => call.key === 'POST /api/servers/2/ssh-access/recover').length, 3)
  assert.equal(calls.filter(call => call.key === 'PATCH /api/servers/2').length, 1)
  assert.equal(await page.locator('body').getAttribute('data-unauthorized'), null)
}

async function metadataWithFailedRefresh({ page, form, save, name, edit, nodes, calls, routes }) {
  routes.set('PATCH /api/servers/1', (body, respond) => {
    Object.assign(nodes[0], body)
    routes.set('GET /api/servers', (_body, respond) => respond({ detail: 'Synthetic list refresh failure' }, 503))
    return respond(nodes[0])
  })
  await edit('Node 1')
  await name.fill('Saved node')
  await save.click()
  await form.waitFor({ state: 'hidden' })
  await page.getByText('Synthetic list refresh failure', { exact: true }).waitFor()
  await page.locator('.srv-item').filter({ hasText: 'Saved node' }).waitFor()
  await page.locator('.srv-item').filter({ hasText: 'Node 2' }).waitFor()
  assert.equal(calls.filter(call => call.key === 'PATCH /api/servers/1').length, 1)
  assert.equal(calls.filter(call => call.key.includes('/ssh-access/')).length, 0)
}

async function recoveryRestoresPolicy({ page, form, save, name, edit, recover, nodes, calls, routes }) {
  for (const refreshFails of [false, true]) {
    Object.assign(nodes[1], {
      ssh_access_pending: true,
      ssh_source_mode: 'custom',
      ssh_source_ips: ['198.51.100.9'],
    })
    routes.delete('GET /api/servers')
    await page.reload()
    await edit('Node 2')
    await name.fill('Recovered metadata')
    await form.locator('.ssh-access-options summary').click()
    const mode = form.getByLabel('Разрешенные источники ключа панели')
    assert.equal(await mode.inputValue(), 'custom')

    routes.set('POST /api/servers/2/ssh-access/recover', (_body, respond) => {
      Object.assign(nodes[1], { ssh_access_pending: false, ssh_source_mode: 'panel', ssh_source_ips: [] })
      if (refreshFails) routes.set('GET /api/servers', (_body, respond) => respond({ detail: 'Synthetic recovery refresh failure' }, 503))
      // require_idle confirms completion even if the response still reflects the
      // pending flag on the record initially loaded by the recovery endpoint.
      return respond({ ...nodes[1], ssh_access_pending: true })
    })
    routes.set('PATCH /api/servers/2', (body, respond) => {
      assertMetadataOnly(body)
      Object.assign(nodes[1], body)
      return respond(nodes[1])
    })
    const recovery = form.getByRole('button', recover)
    await recovery.click()
    await recovery.waitFor({ state: 'hidden' })
    assert.equal(await mode.inputValue(), 'panel', 'The recovered policy must replace the pre-recovery policy in the editor')
    assert.equal(await name.inputValue(), 'Recovered metadata')
    await save.click()
    await form.waitFor({ state: 'hidden' })
    assert.equal(nodes[1].name, 'Recovered metadata')
    nodes[1].name = 'Node 2'
  }
  assert.equal(calls.filter(call => call.key === 'PATCH /api/servers/2').length, 2)
  assert.equal(calls.filter(call => call.key.endsWith('/ssh-access/preview')).length, 0)
}

async function applyFailureRecovery({ form, save, name, edit, nodes, calls, routes }) {
  const previewPath = 'POST /api/servers/1/ssh-access/preview'
  const applyPath = 'POST /api/servers/1/ssh-access/apply'
  const patchPath = 'PATCH /api/servers/1'
  const rawSource = '2001:0db8::9/64'
  const canonicalSource = '2001:db8::/64'
  const warning = 'Synthetic SSH cleanup warning'
  let previewCount = 0
  routes.set(previewPath, (body, respond) => {
    assert.deepEqual(body.ssh_source_ips, [rawSource])
    const token = String(++previewCount).padStart(32, '0')
    return respond({ token, sources: [canonicalSource], unrestricted: false, actions: [], jump_user: null })
  })
  routes.set(applyPath, (body, respond) => {
    assert.equal(body.token, String(previewCount).padStart(32, '0'))
    if (previewCount === 1) return respond({ detail: 'Synthetic expired preview' }, 409)
    Object.assign(nodes[0], {
      ssh_source_mode: 'custom',
      ssh_source_ips: [canonicalSource],
      last_check_info: JSON.stringify({ ssh_access_warning: warning }),
    })
    return respond({ detail: 'Synthetic lost apply reply' }, 502)
  })
  routes.set(patchPath, (body, respond) => {
    assertMetadataOnly(body)
    Object.assign(nodes[0], body)
    return respond(nodes[0])
  })
  await edit('Node 1')
  await name.fill('Unsaved node')
  await form.locator('.ssh-access-options summary').click()
  await form.getByLabel('Разрешенные источники ключа панели').selectOption('custom')
  const sources = form.getByLabel('IP или CIDR через запятую')
  const apply = form.getByRole('button', { name: 'Применить SSH и сохранить', exact: true })
  await sources.fill(rawSource)
  await save.click()
  await apply.click()
  await form.getByRole('alert').getByText('Synthetic expired preview').waitFor()
  assert.equal(await sources.inputValue(), rawSource)
  assert.equal(await name.inputValue(), 'Unsaved node')
  assert.equal(await save.isEnabled(), true)
  assert.equal(await apply.count(), 0)
  assert.equal(nodes[0].ssh_source_mode, 'panel')

  await save.click()
  await apply.click()
  await form.getByRole('alert').getByText('Synthetic lost apply reply').waitFor()
  await form.getByRole('status').getByText(partialSaveMessage).waitFor()
  await form.getByRole('status').getByText(warning).waitFor()
  assert.equal(await sources.inputValue(), canonicalSource)
  assert.equal(await name.inputValue(), 'Unsaved node')
  assert.equal(nodes[0].name, 'Node 1')
  await save.click()
  await form.waitFor({ state: 'hidden' })
  assert.equal(calls.filter(call => call.key === previewPath).length, 2)
  assert.equal(calls.filter(call => call.key === applyPath).length, 2)
  assert.equal(calls.filter(call => call.key === patchPath).length, 1)
  assert.equal(nodes[0].name, 'Unsaved node')
  assert.deepEqual(nodes[0].ssh_source_ips, [canonicalSource])
}

async function applyUnauthorized({ page, form, save, edit, calls, routes }) {
  routes.set('POST /api/servers/1/ssh-access/preview', (_body, respond) => respond({ token: 'fixture', sources: [], unrestricted: true, actions: [], jump_user: null }))
  routes.set('POST /api/servers/1/ssh-access/apply', (_body, respond) => respond({ detail: 'Synthetic apply session expired' }, 401))
  await edit('Node 1')
  await form.locator('.ssh-access-options summary').click()
  await form.getByLabel('Разрешенные источники ключа панели').selectOption('any')
  await save.click()
  await form.getByRole('button', { name: 'Применить SSH и сохранить', exact: true }).click()
  await page.locator('body[data-unauthorized="true"]').waitFor()
  assert.equal(calls.filter(call => call.key === 'GET /api/servers').length, 1)
  assert.equal(calls.filter(call => call.key === 'PATCH /api/servers/1').length, 0)
}

async function replaceHostKey({ page, form, nodes, calls, routes }) {
  const path = 'POST /api/servers/1/host-key/replacement'
  const old = 'SHA256:' + 'A'.repeat(43)
  const fingerprintFromServer = 'SHA256:' + 'B'.repeat(43)
  const fingerprints = { previous_fingerprints: [old], fingerprint: fingerprintFromServer }
  routes.set(`${path}/preview`, (_body, respond) => respond({ host: nodes[0].host, port: 22, ...fingerprints, key_type: 'ssh-ed25519' }))
  routes.set('GET /api/auth/2fa', (_body, respond) => respond({ enabled: true }))
  routes.set(path, (body, respond) => {
    assert.deepEqual(body, { host: nodes[0].host, port: 22, ...fingerprints, password: 'fixture-password' })
    return respond(undefined, 204)
  })
  routes.set('POST /api/servers/1/check', (_body, respond) => respond(nodes[0]))

  await openMenu(page, 'Node 1')
  await page.getByRole('button', { name: 'Заменить ключ SSH', exact: true }).click()
  await form.getByText(old, { exact: true }).waitFor()
  await page.setViewportSize({ width: 320, height: 600 })
  assert.equal(await form.evaluate(element => element.scrollWidth > element.clientWidth), false)
  const fingerprint = form.getByLabel('Отпечаток из доверенной консоли')
  const next = form.getByRole('button', { name: 'Продолжить' })
  await fingerprint.fill(old)
  assert.equal(await next.isEnabled(), false)
  await fingerprint.fill(fingerprintFromServer)
  await next.click()
  await form.getByPlaceholder('Пароль', { exact: true }).fill('fixture-password')
  const otp = form.getByPlaceholder('Код 2FA из приложения')
  await otp.waitFor()
  assert.equal(await next.isEnabled(), false)
  await otp.fill('123456')
  const confirmed = page.waitForRequest(request => `${request.method()} ${new URL(request.url()).pathname}` === path)
  await next.click()
  assert.equal((await confirmed).headers()['x-confirm-otp'], '123456')
  await form.waitFor({ state: 'hidden' })
  await page.getByText('Ключ SSH заменен', { exact: true }).waitFor()
  assert.equal(calls.filter(call => call.key === path).length, 1)
}

try {
  const scenarios = [
    manualOnboarding, passwordOnboarding, passwordOnboardingFailure, bootstrapUnauthorized,
    recoveryUnauthorized, recoveryMenuKeepsDraft, metadataWithFailedRefresh, recoveryRestoresPolicy,
  ]
  const checks = await Promise.allSettled(scenarios.map(async check => {
    await editorWorkflow(check)
    console.log(`PASS ${check.name}`)
  }))
  const failures = checks.flatMap((result, index) => result.status === 'rejected' ? [`${scenarios[index].name}: ${result.reason}`] : [])
  assert.deepEqual(failures, [])
  for (const check of [applyFailureRecovery, applyUnauthorized, replaceHostKey]) {
    await editorWorkflow(check)
    console.log(`PASS ${check.name}`)
  }
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
