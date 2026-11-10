import { useCallback, useEffect, useRef, useState } from 'react'
import {
  api,
  ApiError,
  createCascade,
  getCascade,
  listCascades,
  parseCheckInfo,
  protocolsFromContainers,
  probeCascadeTransport,
  reinstallCascade,
  type Cascade,
  type CascadeCreateRequest,
  type CascadeImageTransport,
  type CascadeRoute,
  type CascadeTransportProbe,
  type CascadeTransport,
  type Server,
} from './api'
import { copyText } from './clipboard'
import { countryFlag, formatBytes } from './format'
import {
  cascadeEntryCountry, cascadeLocalExpected, cascadeLocalRoute, cascadeMeasurement, cascadePort, cascadeRequestId,
  cascadeTransportLabel, DEFAULT_CASCADE_TRANSPORT, formatProbeMetric,
  probeRowTone, PROBE_TRANSPORTS, queuedProbeRows, runTransportProbes, testedAwgPorts,
  type TransportProbeRow, type TransportProbeRows,
} from './cascadeUi'
import { CascadeSecurity } from './CascadeSecurity'
import { cascadeServerEligible } from './serverList'
import { useI18n } from './i18n'
import { useModalDismiss } from './useModalDismiss'

type Step = 'entry' | 'exit' | 'link' | 'install' | 'done'

export type RecoveredEntry = {
  id: number
  country: string
  routes: CascadeRoute[]
  transport: CascadeTransport
}

type Props = {
  servers: Server[]
  cascades: Cascade[]
  defaultUser: string
  // открыть сразу на установке уже созданного каскада (ход или ошибка)
  resume?: Cascade
  recovered?: RecoveredEntry
  onClose: () => void
  onRemove: (cascade: Cascade) => void
  onRecover: (entry: Server) => void
  onChanged: () => void
  onUnauthorized: () => void
}

const STEPS: { key: Step; label: string }[] = [
  { key: 'entry', label: '1. Вход' },
  { key: 'exit', label: '2. Выход' },
  { key: 'link', label: '3. Связь' },
  { key: 'install', label: '4. Установка' },
]

const EMPTY_SERVER_FORM = { host: '', port: 22, user: 'root', password: '' }

function TransportProbeStatus({ row }: { row: TransportProbeRow }) {
  const { t, lang } = useI18n()
  const tone = probeRowTone(row)
  const result = row.result
  const text = row.state === 'queued' ? t('В очереди')
    : row.state === 'preparing' ? t('Подготовка образа и проверка…')
    : row.state === 'running' ? t('Проверяется…')
    : row.state === 'error' ? t(row.error)
    : row.state === 'unavailable' ? t(result?.error || row.error || 'Проверка недоступна')
    : result?.ok ? t('Данные прошли') : t(result?.error || 'Данные не прошли')
  return (
    <div className={`cas-transport-probe cas-probe-${tone}`} data-probe-state={row.state} aria-live="polite" aria-busy={tone === 'run'}>
      <div className="cas-transport-status">
        <span aria-hidden="true">{tone === 'ok' ? '✓' : tone === 'bad' ? '✕' : tone === 'run' ? '●' : '○'}</span>
        <span>{text}</span>
      </div>
      {result && result.bytes > 0 && <div className="muted small">
        {result.ok && result.secs != null && result.mbps != null
          ? t('{size} за {secs} с, ~{mbps} Мбит/с', { size: formatBytes(result.bytes), secs: formatProbeMetric(result.secs, lang, 'secs'), mbps: formatProbeMetric(result.mbps, lang, 'mbps') })
          : t('Получено: {size}', { size: formatBytes(result.bytes) })}
      </div>}
      {result?.prerequisite_tcp && result.ok !== true && <div className="muted small">
        {result.prerequisite_tcp.ok ? t('Предварительное TCP-соединение доступно; это не замер VLESS.') : t('Предварительное TCP-соединение недоступно.')}
      </div>}
      {tone === 'run' && <div className="cas-probe-indeterminate" aria-hidden="true" />}
    </div>
  )
}

// шаги установки по фазе: выход ставится первым, потом вход и проверка
function installTasks(c: Cascade) {
  const gre = c.transport === 'gre'
  const awg = c.transport === 'awg'
  const order = ['exit', 'entry']
  // ошибка без стороны (установку прервал рестарт панели) - крестик ставить некуда
  const at =
    c.status === 'ready' ? 2 : c.phase ? order.indexOf(c.phase) : c.status === 'error' ? -1 : 0
  const failed = c.status === 'error'
  const state = (i: number) =>
    i < at ? 'ok' : i === at ? (failed ? 'bad' : c.status === 'ready' ? 'ok' : 'run') : 'wait'
  return [
    {
      title: awg ? 'Выход: туннель AWG 3.1 и выпуск в интернет' : gre ? 'Выход: GRE-туннель и выпуск в интернет' : 'Выход: сервер VLESS Reality',
      sub: awg ? 'отдельный межсерверный туннель, UDP-порт доступен только для {ip}' : gre
        ? 'маскарад, подрезка MSS, туннель принимается только от {ip}'
        : 'порт открыт только для {ip}',
      ip: c.entry_ip,
      state: state(0),
    },
    {
      title: 'Вход: шлюз каскада',
      sub: 'сайты страны входа напрямую, остальное на выход; если выход пропадет, трафик клиентов никуда не уйдет',
      ip: '',
      state: state(1),
    },
  ]
}

export function CascadeWizard({
  servers,
  cascades,
  defaultUser,
  resume,
  recovered,
  onClose,
  onRemove,
  onRecover,
  onChanged,
  onUnauthorized,
}: Props) {
  const { t, lang } = useI18n()
  const [step, setStep] = useState<Step>(
    resume ? (resume.status === 'ready' ? 'done' : 'install') : recovered ? 'exit' : 'entry',
  )
  const [entryId, setEntryId] = useState<number | null>(resume?.entry_server_id ?? recovered?.id ?? null)
  const [entryCountry, setEntryCountry] = useState(recovered?.country ?? '')
  const [exitId, setExitId] = useState<number | null>(resume?.exit_server_id ?? null)
  const [tab, setTab] = useState<'panel' | 'new'>('panel')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  // новый сервер: по паролю (панель сама ставит ключ) или скриптом
  const [nf, setNf] = useState(EMPTY_SERVER_FORM)
  const [nfMode, setNfMode] = useState<'password' | 'script'>('password')
  const [script, setScript] = useState<{ server: Server; text: string } | null>(null)
  const [copied, setCopied] = useState(false)
  const [probe, setProbe] = useState<CascadeTransportProbe | null>(null)
  const [probeRows, setProbeRows] = useState<TransportProbeRows>(queuedProbeRows)
  const activeProbe = useRef<{ controller: AbortController; preparing: boolean } | null>(null)
  const preparing = probeRows.awg.state === 'preparing' || probeRows.vless.state === 'preparing'
  function close() {
    if (!activeProbe.current?.preparing) onClose()
  }
  const dismiss = useModalDismiss(close)
  const [transport, setTransport] = useState<CascadeTransport>(recovered?.transport ?? DEFAULT_CASCADE_TRANSPORT)
  const [entryPort, setEntryPort] = useState('')
  const [exitPort, setExitPort] = useState('')
  const [cascade, setCascade] = useState<Cascade | null>(resume ?? null)
  const createRequests = useRef(new Map<string, CascadeCreateRequest>())
  const [extra, setExtra] = useState<Server[]>([])
  const timer = useRef<number | undefined>(undefined)
  const [pollTick, setPollTick] = useState(0)

  const all = [...servers, ...extra.filter((x) => !servers.some((s) => s.id === x.id))]
  const byId = (id: number | null) => all.find((s) => s.id === id) ?? null
  const entry = byId(entryId)
  const exit = byId(exitId)
  const countryError = cascade?.status === 'error' && cascade.result.error_code === 'cascade_entry_country_unknown'
  const validCountry = /^[A-Z]{2}$/.test(entryCountry)
  const invalidCountry = entryCountry !== '' && !validCountry
  const retryNeedsCountry = countryError && !validCountry
  const localRoute = cascade ? cascadeLocalRoute(cascade.result) : 'unknown'
  const localExpected = cascadeLocalExpected(cascade?.routes)

  const handleError = useCallback(
    (err: unknown) => {
      if (err instanceof ApiError && err.status === 401) onUnauthorized()
      else setError(err instanceof Error ? t(err.message) : t('Ошибка'))
    },
    [onUnauthorized, t],
  )

  // опрос хода установки
  useEffect(() => {
    if (!cascade || cascade.status !== 'installing') return
    timer.current = window.setTimeout(async () => {
      try {
        const c = await getCascade(cascade.id)
        setError(null)
        setCascade(c)
        if (c.status === 'ready') {
          setStep('done')
          onChanged()
        } else if (c.status === 'error') {
          onChanged()
        }
      } catch (err) {
        handleError(err)
        // панель перезапускают или моргнула сеть - спрашиваем дальше, а не замолкаем
        setPollTick((n) => n + 1)
      }
    }, 3000)
    return () => window.clearTimeout(timer.current)
  }, [cascade, pollTick, handleError, onChanged])

  const candidates = (exclude: number | null, role: 'entry' | 'exit') =>
    all.filter((s) => s.id !== exclude && s.last_check_ok === true && cascadeServerEligible(s, cascades, role))

  function eligibleServer(server: Server, currentCascades: Cascade[]): boolean {
    const role = step === 'entry' ? 'entry' : 'exit'
    if (server.id !== (role === 'entry' ? exitId : entryId) && cascadeServerEligible(server, currentCascades, role)) return true
    setError(t('Сервер недоступен для выбранной роли в каскаде.'))
    return false
  }

  function checkedServer(s: Server): Server | null {
    if (s.last_check_ok === true) return s
    const reason = parseCheckInfo(s)?.error
    const target = `${s.ssh_user}@${s.host.includes(':') ? `[${s.host}]` : s.host}:${s.ssh_port}`
    const message = t('Не удалось подключиться по SSH к {target}.', { target })
    setError(reason ? `${message} ${t(reason)}` : message)
    return null
  }

  async function addServer(groupName: string): Promise<Server | null> {
    setBusy(true)
    setError(null)
    const target = { host: nf.host.trim(), ssh_port: nf.port, ssh_user: nfMode === 'password' ? nf.user.trim() : defaultUser }
    let server: Server | null = null
    try {
      server = await api<Server>('/api/servers?reuse_ssh_endpoint=true', {
        method: 'POST',
        body: JSON.stringify({ ...target, name: target.host, note: '', group_name: groupName }),
      })
      const currentCascades = await listCascades()
      if (!eligibleServer(server, currentCascades)) return null
      const checked = await api<Server>(`/api/servers/${server.id}/check`, { method: 'POST' })
      if (checked.last_check_ok === true) return eligibleServer(checked, currentCascades) ? checked : null
      if (nfMode === 'script') {
        const { script: text } = await api<{ script: string }>(
          `/api/servers/${server.id}/setup-script`,
        )
        setScript({ server, text })
        setCopied(false)
        return null
      }
      const ready = await api<Server>(`/api/servers/${server.id}/bootstrap`, {
        method: 'POST',
        body: JSON.stringify({ password: nf.password, become_password: null }),
      })
      return eligibleServer(ready, currentCascades) ? checkedServer(ready) : null
    } catch (err) {
      handleError(err)
      return null
    } finally {
      if (server) onChanged()
      setBusy(false)
    }
  }

  // после ручного запуска скрипта: проверяем связь и берем сервер
  async function scriptDone(): Promise<Server | null> {
    if (!script) return null
    setBusy(true)
    setError(null)
    try {
      const s = await api<Server>(`/api/servers/${script.server.id}/check`, { method: 'POST' })
      onChanged()
      return eligibleServer(s, await listCascades()) ? checkedServer(s) : null
    } catch (err) {
      handleError(err)
      return null
    } finally {
      setBusy(false)
    }
  }

  useEffect(() => {
    return () => {
      activeProbe.current?.controller.abort()
      activeProbe.current = null
    }
  }, [])

  async function runProbe(eId = entryId, xId = exitId, prepareTransport?: CascadeImageTransport) {
    if (eId == null || xId == null || activeProbe.current) return
    const ports = { entry_port: cascadePort(entryPort), exit_port: cascadePort(exitPort) }
    if (prepareTransport !== 'vless' && (ports.entry_port === undefined || ports.exit_port === undefined)) {
      setError(t('UDP-порт должен быть целым числом от 1 до 65535 или пустым для автовыбора.'))
      return
    }
    const controller = new AbortController()
    const run = { controller, preparing: prepareTransport !== undefined }
    activeProbe.current = run
    setBusy(true)
    setError(null)
    if (!prepareTransport) {
      setProbe(null)
      setProbeRows(queuedProbeRows())
    }
    try {
      await runTransportProbes(async (kind, signal) => {
        try {
          return await probeCascadeTransport(eId, xId, kind,
            { entry_port: ports.entry_port ?? null, exit_port: ports.exit_port ?? null }, signal, kind === prepareTransport)
        } catch (err) {
          if (err instanceof ApiError && err.status === 401) {
            controller.abort()
            onUnauthorized()
          }
          throw err
        }
      }, (kind, row) => {
        if (activeProbe.current !== run || controller.signal.aborted) return
        setProbeRows(current => ({ ...current, [kind]: row }))
        if (row.result) setProbe(row.result)
      }, controller.signal, err => err instanceof Error ? err.message : t('Ответ проверки не соответствует транспорту.'), prepareTransport)
    } finally {
      if (activeProbe.current === run) {
        activeProbe.current = null
        if (!controller.signal.aborted) setBusy(false)
      }
    }
  }

  function changeProbePort(set: (value: string) => void, value: string) {
    set(value)
    // A missing image is independent of the UDP ports.
    setProbeRows(current => current.awg.result?.reason === 'local_image_missing' ? current : { ...current, awg: {
      state: 'unavailable', result: null, error: t('UDP-порты изменены. Повторите проверку AWG.'),
    } })
  }

  async function next() {
    setError(null)
    if (step === 'entry' || step === 'exit') {
      let picked = step === 'entry' ? entry : exit
      if (tab === 'new') {
        const added = script ? await scriptDone() : await addServer(step === 'exit' ? entry?.group_name ?? '' : '')
        if (!added) return
        setExtra((current) => [...current.filter((server) => server.id !== added.id), added])
        if (step === 'entry') pickEntry(added.id)
        else setExitId(added.id)
        picked = added
      }
      if (!picked) return
      setNf(EMPTY_SERVER_FORM)
      setScript(null)
      setTab('panel')
      if (step === 'entry') {
        setStep('exit')
      } else {
        setStep('link')
        void runProbe(entryId, picked.id)
      }
    }
  }

  async function build() {
    if (entryId == null || exitId == null || invalidCountry) return
    const ports = { entry_port: cascadePort(entryPort), exit_port: cascadePort(exitPort) }
    if (transport === 'awg' && (ports.entry_port === undefined || ports.exit_port === undefined)) {
      setError(t('UDP-порт должен быть целым числом от 1 до 65535 или пустым для автовыбора.'))
      return
    }
    const requestedPorts = { entry_port: ports.entry_port ?? null, exit_port: ports.exit_port ?? null }
    const form: Omit<CascadeCreateRequest, 'request_id'> = {
      entry_id: entryId,
      exit_id: exitId,
      transport,
      ...(transport === 'awg' ? requestedPorts : {}),
      ...(entryCountry ? { entry_country: entryCountry } : {}),
      ...(recovered?.routes.length ? { routes: recovered.routes } : {}),
    }
    const signature = JSON.stringify(form)
    setBusy(true)
    setError(null)
    try {
      // After an ambiguous response, a fresh probe must not change the sent ports.
      const request = createRequests.current.get(signature) ?? {
        ...form,
        ...(transport === 'awg' ? testedAwgPorts(requestedPorts, probeRows.awg.result) : {}),
        request_id: cascadeRequestId(),
      }
      createRequests.current.set(signature, request)
      const c = await createCascade(request)
      setCascade(c)
      setStep(c.status === 'ready' ? 'done' : 'install')
      onChanged()
    } catch (err) {
      if (err instanceof TypeError || err instanceof ApiError && (err.status === 408 || err.status >= 500)) {
        const message = t('Ответ на создание каскада не получен. Нажмите «Собрать каскад» еще раз, чтобы продолжить.')
        setError(`${err.message}. ${message}`)
        onChanged()
      } else {
        createRequests.current.delete(signature)
        handleError(err)
      }
    } finally {
      setBusy(false)
    }
  }

  async function retry() {
    if (!cascade || retryNeedsCountry) return
    setBusy(true)
    setError(null)
    try {
      setCascade(await reinstallCascade(cascade.id, countryError ? entryCountry : undefined))
    } catch (err) {
      handleError(err)
    } finally {
      setBusy(false)
    }
  }

  function pickEntry(id: number) {
    if (id !== entryId) setEntryCountry('')
    setEntryId(id)
  }

  function countryInput() {
    return (
      <label>
        {t('Страна входа')}
        <input
          className="mono"
          value={entryCountry}
          maxLength={2}
          autoCapitalize="characters"
          spellCheck={false}
          aria-invalid={invalidCountry}
          disabled={busy}
          required={countryError}
          placeholder={countryError ? undefined : t('Автоматически')}
          onChange={event => setEntryCountry(event.target.value.toUpperCase())}
        />
        <span className={`small ${invalidCountry ? 'err-text' : 'muted'}`}>
          {t('Две латинские буквы, например RU. Код определяет, какие сайты пойдут через вход.')}
        </span>
      </label>
    )
  }

  const stepIdx = STEPS.findIndex((s) => s.key === step)
  const measurement = cascade ? cascadeMeasurement(cascade) : null
  const steps = (
    <div className="cas-steps">
      {STEPS.map((s, i) => (
        <span
          key={s.key}
          className={i < stepIdx || step === 'done' ? 'done' : i === stepIdx ? 'on' : ''}
        >
          {t(s.label)}
        </span>
      ))}
    </div>
  )

  function hop(s: Server | null, ip: string, sub: string, isExit = false, country = '') {
    const flag = countryFlag(country || s?.country || '')
    return (
      <div className={`srv-hop${isExit ? ' srv-hop-exit' : ''}`}>
        {flag && <span className="server-flag">{flag}</span>}
        <div>
          <div className="mono">{ip || s?.host}</div>
          <div className="muted small">{sub}</div>
        </div>
      </div>
    )
  }

  // у сервера, добавленного из мастера, имя = адрес: второй раз адрес не пишем
  const named = (s: Server | null, role: string) =>
    s && s.name !== s.host ? s.name : t(role)

  function route(withClients: boolean) {
    const selectedTransport = cascade?.transport ?? transport
    const selectedProbeTone = probeRowTone(probeRows[selectedTransport])
    const exitIp = cascade?.result.egress || probe?.exit_ip || cascade?.exit_ip || exit?.host || ''
    return (
      <div className="srv-route">
        {withClients && (
          <>
            <span className="srv-route-label">{t('Клиенты')}</span>
            <span className="srv-route-arrow">→</span>
          </>
        )}
        {hop(entry, cascade?.entry_ip || probe?.entry_ip || '', named(entry, 'вход'), false, cascade ? cascadeEntryCountry(cascade, entry) : entryCountry)}
        {step === 'link' ? (
          <div
            className={`cc-link cas-link ${
              selectedProbeTone === 'run' ? 'cc-link-run' : selectedProbeTone === 'ok' ? 'cc-link-ok' : selectedProbeTone === 'bad' ? 'cc-link-bad' : ''
            }`}
          />
        ) : (
          <span className="srv-route-arrow">
            {(step === 'done' || step === 'install') && (
              <span className="tun-badge">{cascadeTransportLabel(selectedTransport)}</span>
            )}
            →
          </span>
        )}
        {hop(
          exit,
          exitIp,
          [named(exit, 'выход'), probe?.exit_org].filter(Boolean).join(', '),
          true,
          probe?.exit_country,
        )}
      </div>
    )
  }

  function picker(kind: 'entry' | 'exit') {
    const list = candidates(kind === 'exit' ? entryId : exitId, kind)
    const value = kind === 'entry' ? entryId : exitId
    const set = kind === 'entry' ? pickEntry : setExitId
    return (
      <>
        <div className="tabs">
          <button
            className={tab === 'panel' ? 'tab tab-active' : 'tab'}
            disabled={busy}
            onClick={() => setTab('panel')}
          >
            {t('Уже в панели')}
          </button>
          <button
            className={tab === 'new' ? 'tab tab-active' : 'tab'}
            disabled={busy}
            onClick={() => setTab('new')}
          >
            {t('Новый сервер')}
          </button>
        </div>
        {tab === 'panel' ? (
          <>
            {list.length === 0 ? (
              <p className="muted small">{t('Свободных серверов на связи нет, добавьте новый.')}</p>
            ) : (
              <div className="cas-pick">
                {list.map((s) => (
                  <label key={s.id} className={value === s.id ? 'on' : ''}>
                    <input
                      type="radio"
                      name={`cas-${kind}`}
                      disabled={busy}
                      checked={value === s.id}
                      onChange={() => set(s.id)}
                    />
                    {countryFlag(s.country) && (
                      <span className="server-flag">{countryFlag(s.country)}</span>
                    )}
                    <span className="cas-pick-name">{s.name}</span>
                    <span className="mono muted small">{s.host}</span>
                  </label>
                ))}
              </div>
            )}
            <p className="muted small">
              {kind === 'entry' ? t('Для входа показаны доступные серверы без других каскадов.') : t('Общий выход можно выбрать повторно. Серверы, уже используемые как вход, не показаны.')}
            </p>
          </>
        ) : script ? (
          <>
            <p className="muted small">
              {t(
                'Выполните скрипт на сервере под root: он создаст пользователя панели и поставит ее ключ. Потом нажмите «Дальше».',
              )}
            </p>
            <pre className="script-box cas-script">{script.text}</pre>
            <div>
              <button className="ghost" onClick={async () => setCopied(await copyText(script.text))}>
                {copied ? t('Скопировано ✓') : t('Скопировать')}
              </button>
            </div>
          </>
        ) : (
          <>
            <div className="cas-row2">
              <label>
                {t('Хост (IP или домен)')}
                <input
                  className="mono"
                  value={nf.host}
                  disabled={busy}
                  onChange={(e) => setNf({ ...nf, host: e.target.value })}
                  placeholder="203.0.113.10"
                />
              </label>
              <label>
                {t('Порт SSH')}
                <input
                  type="number"
                  value={nf.port}
                  disabled={busy}
                  onChange={(e) => setNf({ ...nf, port: Number(e.target.value) || 22 })}
                />
              </label>
            </div>
            <div className="tabs">
              <button
                className={nfMode === 'password' ? 'tab tab-active' : 'tab'}
                disabled={busy}
                onClick={() => setNfMode('password')}
              >
                {t('Пароль')}
              </button>
              <button
                className={nfMode === 'script' ? 'tab tab-active' : 'tab'}
                disabled={busy}
                onClick={() => setNfMode('script')}
              >
                {t('Скрипт')}
              </button>
            </div>
            {nfMode === 'password' ? (
              <>
                <div className="cas-row2">
                  <label>
                    {t('Пользователь')}
                    <input
                      className="mono"
                      value={nf.user}
                      disabled={busy}
                      onChange={(e) => setNf({ ...nf, user: e.target.value })}
                    />
                  </label>
                  <label>
                    {t('Пароль')}
                    <input
                      type="password"
                      autoComplete="new-password"
                      value={nf.password}
                      disabled={busy}
                      onChange={(e) => setNf({ ...nf, password: e.target.value })}
                    />
                  </label>
                </div>
                <p className="muted small">
                  {t(
                    'Пароль нужен один раз: панель заходит по нему, ставит свой ключ и дальше работает по ключу.',
                  )}
                </p>
              </>
            ) : (
              <p className="muted small">
                {t('Панель добавит сервер и покажет скрипт, его надо выполнить на сервере под root.')}
              </p>
            )}
          </>
        )}
      </>
    )
  }

  const pickReady =
    tab === 'panel'
      ? (step === 'entry' ? entry : exit) !== null
      : script !== null || (nf.host.trim() !== '' && (nfMode === 'script' || nf.password !== ''))

  const head = (title: string, closable = true) => (
    <div className="clients-head">
      <h3>{title}</h3>
      {closable && (
        <button className="ghost" disabled={preparing} onClick={close}>
          {t('Закрыть')}
        </button>
      )}
    </div>
  )

  return (
    <div className="modal-backdrop" onClick={dismiss}>
      <div className="card modal modal-wide cas-modal" onClick={(e) => e.stopPropagation()}>
        {step === 'entry' && (
          <>
            {head(t('Новый каскад'))}
            {steps}
            <p className="cas-lead">
              {t(
                'Вход - сервер, к которому подключаются клиенты. Сайты его страны будут открываться с него напрямую, остальное пойдет через выход в другой стране.',
              )}
            </p>
            {picker('entry')}
          </>
        )}

        {step === 'exit' && (
          <>
            {head(t('Новый каскад'))}
            {steps}
            <p className="cas-lead">
              {t(
                'Выход - сервер, через который клиенты будут выходить в интернет. У него могут быть свои клиенты и другие входы каскадов.',
              )}
            </p>
            {picker('exit')}
          </>
        )}

        {step === 'link' && (
          <>
            {head(t('Новый каскад'))}
            {steps}
            {route(false)}
            {(!entry?.country || entryCountry) && countryInput()}
            <p className="muted small">{t('Короткие проверки каждого транспорта. Скорость ориентировочная.')}</p>
            <div className="cas-opts">
              {PROBE_TRANSPORTS.map(k => {
                const name = k === 'awg' ? 'AmneziaWG 3.1' : k === 'vless' ? 'VLESS Reality' : 'GRE'
                const row = probeRows[k]
                const needsImage = row.state === 'unavailable' && row.result?.reason === 'local_image_missing'
                return (
                  <div key={k} className={`cas-transport-option${transport === k ? ' on' : ''}`}>
                    <label>
                      <input
                        type="radio"
                        name="cas-transport"
                        checked={transport === k}
                        disabled={preparing}
                        onChange={() => setTransport(k)}
                      />
                      <div>
                        <b>
                          {name}
                          {k === 'awg' && <span className="cas-rec">{t('по умолчанию')}</span>}
                        </b>
                        <p className="muted small">
                          {k === 'awg' ? t('Шифрованный межсерверный туннель по UDP с отдельными ключами. Клиентские VPN-конфигурации не меняются.') : k === 'vless'
                            ? t('Шифрованный туннель, снаружи похож на обычный HTTPS. Подходит, когда TCP от входа к выходу проходит.')
                            : t('Туннель без шифрования межсерверного участка. Выбирайте только при осознанной необходимости открытого GRE.')}
                        </p>
                        <TransportProbeStatus row={row} />
                      </div>
                    </label>
                    {k !== 'gre' && (row.state === 'preparing' || needsImage) && (
                      <button
                        type="button"
                        className="ghost cas-prepare-probe"
                        disabled={busy}
                        aria-label={t('Подготовить и проверить {transport}', { transport: name })}
                        onClick={() => void runProbe(entryId, exitId, k)}
                      >
                        {t('Подготовить и проверить')}
                      </button>
                    )}
                  </div>
                )
              })}
            </div>
            {transport === 'awg' && <details className="cas-port-options">
              <summary>{t('UDP-порты межсерверного канала')}</summary>
              <p className="muted small">{t('Пустые поля — автоматический выбор. Проверенные UDP-порты сохраняются при установке.')}</p>
              <div className="cas-row2">
                <label>{t('UDP-порт входа')}<input inputMode="numeric" disabled={busy} value={entryPort} onChange={e => changeProbePort(setEntryPort, e.target.value)} placeholder={t('Автоматически')} /></label>
                <label>{t('UDP-порт выхода')}<input inputMode="numeric" disabled={busy} value={exitPort} onChange={e => changeProbePort(setExitPort, e.target.value)} placeholder={t('Автоматически')} /></label>
              </div>
            </details>}
          </>
        )}

        {step === 'install' && cascade && (
          <>
            {head(cascade.status === 'error' ? t('Каскад не собрался') : t('Собираю каскад'))}
            {steps}
            {route(false)}
            <div className="cas-tasks">
              {installTasks(cascade).map((task) => (
                <div className="cas-task" key={task.title}>
                  <span className={`cas-ic cas-ic-${task.state}`}>
                    {task.state === 'ok' ? '✓' : task.state === 'bad' ? '✕' : task.state === 'run' ? '●' : '○'}
                  </span>
                  <div>
                    <div>{t(task.title)}</div>
                    <div className="muted small">{t(task.sub, { ip: task.ip })}</div>
                  </div>
                </div>
              ))}
            </div>
            {cascade.error && <p className="small err-text">{countryError
              ? t('Не удалось определить страну входа. Укажите ее вручную и повторите установку.') : cascade.error}</p>}
            {countryError && countryInput()}
            {cascade.log && <pre className="script-box deploy-log">{cascade.log}</pre>}
            {cascade.status === 'installing' && (
              <p className="muted small">
                {t('Окно можно закрыть, установка продолжится. Ход виден в карточке входа.')}
              </p>
            )}
          </>
        )}

        {step === 'done' && cascade && (
          <>
            {head(t('Каскад собран'))}
            {steps}
            {route(true)}
            <CascadeSecurity encrypted={cascade.encrypted} encryption={cascade.encryption} />
            <div className="cas-checks">
              {cascade.result.egress && (
                <div>
                  <span className="ok-text">✓</span>{' '}
                  {t('Проверка шлюза через выход показала адрес {ip}', { ip: cascade.result.egress })}
                </div>
              )}
              {(cascadeEntryCountry(cascade, entry) === 'RU' || cascade.result.ru) && (
                <div>
                  {localRoute === localExpected && <><span className="ok-text">✓</span>{' '}</>}
                  {localRoute === 'entry'
                    ? t('Шлюз открыл проверочный сайт страны входа напрямую')
                    : localRoute === 'exit'
                      ? localExpected === 'exit' ? t('Проверочный сайт страны входа идет через выход по ручному правилу')
                        : t('Шлюз открыл проверочный сайт страны входа через выход')
                      : t('Маршрут для сайта страны входа не подтвержден')}
                  {cascade.result.ru && <span className="muted"> · {t('адрес {ip}', { ip: cascade.result.ru })}</span>}
                </div>
              )}
              {measurement && (
                <div>
                  <span className="ok-text">✓</span>{' '}
                  {measurement.label === 'TCP'
                    ? t('Обычный TCP: ~{mbps} Мбит/с; это не замер VLESS.', { mbps: formatProbeMetric(measurement.mbps, lang, 'mbps') })
                    : t('{transport}: ~{mbps} Мбит/с по короткой проверке', { transport: measurement.label, mbps: formatProbeMetric(measurement.mbps, lang, 'mbps') })}
                </div>
              )}
              <div>
                <span className="ok-text">✓</span>{' '}
                {t('Туннель и шлюз установлены как службы systemd')}
              </div>
            </div>
            {entry && protocolsFromContainers(parseCheckInfo(entry)?.amnezia_containers ?? [], parseCheckInfo(entry)?.protocols ?? {}).length === 0 && (
              <p className="muted small">
                {t(
                  'Протоколов для клиентов на входе пока нет. Развернуть клиентский VPN можно в карточке сервера, меню «Ещё».',
                )}
              </p>
            )}
          </>
        )}

        {error && <p className="small err-text">{error}</p>}

        <div className="cas-actions">
          {((step === 'exit' && !recovered) || step === 'link') && (
            <button
              className="ghost"
              disabled={busy}
              onClick={() => {
                setError(null)
                setTab('panel')
                setScript(null)
                setStep(step === 'exit' ? 'entry' : 'exit')
              }}
            >
              {t('Назад')}
            </button>
          )}
          {step === 'link' && (
            <button className="ghost" disabled={busy} onClick={() => runProbe()}>
              {t('Проверить еще раз')}
            </button>
          )}
          <div className="cas-actions-r">
            {(step === 'entry' || step === 'exit') && (
              <button disabled={busy || !pickReady} onClick={next}>
                {busy ? t('Подключаюсь…') : t('Дальше')}
              </button>
            )}
            {step === 'link' && (
              <button disabled={busy || invalidCountry} onClick={build}>
                {t('Собрать каскад')}
              </button>
            )}
            {step === 'install' && cascade?.status === 'error' && (
              <>
                {entry && !recovered && <button className="ghost" disabled={busy} onClick={() => onRecover(entry)}>
                  {t('Восстановить вход…')}
                </button>}
                <button className="ghost" disabled={busy} onClick={() => onRemove(cascade)}>
                  {t('Разобрать каскад…')}
                </button>
                <button disabled={busy || retryNeedsCountry} onClick={retry}>
                  {t('Запустить еще раз')}
                </button>
              </>
            )}
            {step === 'done' && <button onClick={onClose}>{t('Готово')}</button>}
          </div>
        </div>
      </div>
    </div>
  )
}
