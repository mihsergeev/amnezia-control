import { useCallback, useEffect, useRef, useState } from 'react'
import {
  api,
  ApiError,
  createCascade,
  getCascade,
  getCascadeProbeProgress,
  listCascades,
  parseCheckInfo,
  previewCascadeEntryRecovery,
  protocolsFromContainers,
  probeCascadeTransport,
  recoverCascadeEntry,
  reinstallCascade,
  type Cascade,
  type CascadeCreateRequest,
  type CascadeEntryRecovery,
  type CascadeImageTransport,
  type CascadeProbeProgress,
  type CascadeSideProgress,
  type CascadeTransport,
  type Server,
} from './api'
import { copyText } from './clipboard'
import { countryFlag, formatBytes } from './format'
import {
  cascadeEntryCountry, cascadeEntryOwnershipError, cascadeLocalExpected, cascadeLocalRoute, cascadeMeasurement, cascadePort, cascadeRequestId,
  cascadeTransportLabel, DEFAULT_CASCADE_TRANSPORT, formatProbeMetric,
  idleProbeRows, matchingProbeProgress, newerProbeProgress, progressElapsed, probeRowTone, PROBE_TRANSPORTS, runTransportProbes, testedAwgPorts,
  type TransportProbeRow, type TransportProbeRows,
} from './cascadeUi'
import { CascadeSecurity } from './CascadeSecurity'
import { cascadeEntryHasExistingRoute, cascadeServerEligible } from './serverList'
import { useI18n } from './i18n'
import { useModalDismiss } from './useModalDismiss'

type Step = 'entry' | 'exit' | 'link' | 'install' | 'done'

type EntryRecovery =
  | { state: 'checking' | 'removing' | 'removed' }
  | { state: 'confirm'; preview: CascadeEntryRecovery }

type Props = {
  servers: Server[]
  cascades: Cascade[]
  defaultUser: string
  // открыть сразу на установке уже созданного каскада (ход или ошибка)
  resume?: Cascade
  replacement?: Cascade
  onClose: () => void
  onRemove: (cascade: Cascade) => void
  onChanged: () => void
  onUnauthorized: () => void
}

const STEPS: { key: Step; label: string }[] = [
  { key: 'entry', label: '1. Вход' },
  { key: 'exit', label: '2. Выход' },
  { key: 'link', label: '3. Связь' },
  { key: 'install', label: '4. Установка' },
]

const EMPTY_SERVER_FORM = { name: '', host: '', port: 22, user: 'root', password: '' }

function TransportProbeStatus({ row }: { row: TransportProbeRow }) {
  const { t, lang } = useI18n()
  const tone = probeRowTone(row)
  const result = row.result
  const transferred = result?.ok === true || result?.transfer_ok === true
  const cleanupFailed = result?.cleanup_failed ?? []
  const cleanupText = cleanupFailed.length === 2 ? t('Очистка временных ресурсов не подтверждена на входе и выходе')
    : cleanupFailed.includes('entry') ? t('Очистка временных ресурсов не подтверждена на входе')
    : t('Очистка временных ресурсов не подтверждена на выходе')
  const text = row.state === 'idle' ? t('Еще не проверен') : row.state === 'queued' ? t('В очереди')
    : row.state === 'preparing' ? t('Подготовка образа и проверка…')
    : row.state === 'running' ? t('Проверяется…')
    : row.state === 'error' ? t(row.error)
    : row.state === 'unavailable' ? t(result?.error || row.error || 'Проверка недоступна')
    : transferred ? t('Данные прошли') : t(result?.error || 'Данные не прошли')
  return (
    <div className={`cas-transport-probe cas-probe-${tone}`} data-probe-state={row.state} aria-live="polite" aria-busy={tone === 'run'}>
      {(!cleanupFailed.length || result?.error !== 'Не удалось подтвердить очистку временных ресурсов' || transferred) && <div className={`cas-transport-status${transferred ? ' cas-transport-passed' : ''}`}>
        <span aria-hidden="true">{transferred ? '✓' : tone === 'bad' ? '✕' : tone === 'run' ? '●' : '○'}</span>
        <span>{text}</span>
      </div>}
      {result && result.bytes > 0 && <div className="muted small">
        {transferred && result.secs != null && result.mbps != null
          ? t('{size} за {secs} с, ~{mbps} Мбит/с', { size: formatBytes(result.bytes), secs: formatProbeMetric(result.secs, lang, 'secs'), mbps: formatProbeMetric(result.mbps, lang, 'mbps') })
          : t('Получено: {size}', { size: formatBytes(result.bytes) })}
      </div>}
      {cleanupFailed.length > 0 && <div className="cas-transport-status">
        <span aria-hidden="true">!</span>
        <span>{cleanupText}</span>
      </div>}
      {result?.prerequisite_tcp && !transferred && <div className="muted small">
        {result.prerequisite_tcp.ok ? t('Предварительное TCP-соединение доступно; это не замер VLESS.') : t('Предварительное TCP-соединение недоступно.')}
      </div>}
      {tone === 'run' && <div className="cas-probe-indeterminate" aria-hidden="true" />}
    </div>
  )
}

function SideProgress({ side, now, waiting }: { side?: CascadeSideProgress; now: number; waiting: string }) {
  const { t } = useI18n()
  const elapsed = progressElapsed(side, now)
  const stage = (() => {
    switch (side?.stage) {
      case 'queued': return t('В очереди')
      case 'connecting': return t('Подключение по SSH')
      case 'checking_image': return t('Проверка образа')
      case 'building_image': return t('Сборка образа')
      case 'pulling_image': return t('Загрузка образа')
      case 'preparing': return t('Подготовка проверки')
      case 'ready': return t('Готов к передаче')
      case 'transferring': return t('Передача тестовых данных')
      case 'cleanup': return t('Очистка временных ресурсов')
      case 'completed': return t('Завершено')
      case 'failed': return t('Этап не завершен')
      case 'cancelled': return t('Проверка отменена')
      case 'installing': return t('Установка служб')
      default: return side?.status === 'error' ? t('Этап не завершен') : waiting
    }
  })()
  const tone = side?.status === 'error' ? 'bad' : side?.status === 'done' ? 'ok' : side?.status === 'running' ? 'run' : 'muted'
  return <div className={`cas-side-progress cas-probe-${tone}`} aria-live="polite" aria-busy={side?.status === 'running'}>
    <div className="cas-transport-status"><span aria-hidden="true">{tone === 'ok' ? '✓' : tone === 'bad' ? '✕' : tone === 'run' ? '●' : '○'}</span><span>{stage}</span></div>
    {elapsed !== null && <span className="small muted">{t('Прошло: {seconds} с', { seconds: elapsed })}</span>}
    {tone === 'run' && <div className="cas-probe-indeterminate" aria-hidden="true" />}
  </div>
}

export function CascadeWizard({
  servers,
  cascades,
  defaultUser,
  resume,
  replacement,
  onClose,
  onRemove,
  onChanged,
  onUnauthorized,
}: Props) {
  const { t, lang } = useI18n()
  const [step, setStep] = useState<Step>(
    resume ? (resume.status === 'ready' ? 'done' : 'install') : replacement ? 'exit' : 'entry',
  )
  const [entryId, setEntryId] = useState<number | null>((resume ?? replacement)?.entry_server_id ?? null)
  const [entryCountry, setEntryCountry] = useState(replacement?.entry_country ?? '')
  const [exitId, setExitId] = useState<number | null>(resume?.exit_server_id ?? null)
  const [tab, setTab] = useState<'panel' | 'new'>('panel')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  // новый сервер: по паролю (панель сама ставит ключ) или скриптом
  const [nf, setNf] = useState(EMPTY_SERVER_FORM)
  const [nfMode, setNfMode] = useState<'password' | 'script'>('password')
  const [script, setScript] = useState<{ server: Server; text: string } | null>(null)
  const [copied, setCopied] = useState(false)
  const [probeRows, setProbeRows] = useState<TransportProbeRows>(idleProbeRows)
  const activeProbe = useRef<{ controller: AbortController; preparing: boolean } | null>(null)
  const [probeProgress, setProbeProgress] = useState<CascadeProbeProgress | null>(null)
  const [clockNow, setClockNow] = useState(() => Date.now())
  const probeTimer = useRef<number | undefined>(undefined)
  const preparing = probeRows.awg.state === 'preparing' || probeRows.vless.state === 'preparing'
  const [entryRecovery, setEntryRecovery] = useState<EntryRecovery | null>(null)
  const [createNeedsRecovery, setCreateNeedsRecovery] = useState(false)
  const recoveryBusy = entryRecovery?.state === 'checking' || entryRecovery?.state === 'removing'
  const recoveryConfirm = entryRecovery?.state === 'confirm'
  function close() {
    if (!activeProbe.current?.preparing && !recoveryBusy) onClose()
  }
  const dismiss = useModalDismiss(close)
  const [transport, setTransport] = useState<CascadeTransport>(replacement?.transport ?? DEFAULT_CASCADE_TRANSPORT)
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
  const entryOwnershipError = cascade !== null && cascadeEntryOwnershipError(cascade)
  const recoveryTarget = step === 'install' && cascade && entryOwnershipError
    ? { entryId: cascade.entry_server_id, cascadeId: cascade.id }
    : step === 'link' && createNeedsRecovery && entryId !== null ? { entryId } : null
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
    let cancelled = false
    timer.current = window.setTimeout(async () => {
      try {
        const c = await getCascade(cascade.id)
        if (cancelled) return
        setError(null)
        setCascade(c)
        if (c.status === 'ready') {
          setStep('done')
          onChanged()
        } else if (c.status === 'error') {
          onChanged()
        }
      } catch (err) {
        if (cancelled) return
        handleError(err)
        // панель перезапускают или моргнула сеть - спрашиваем дальше, а не замолкаем
        setPollTick((n) => n + 1)
      }
    }, 3000)
    return () => { cancelled = true; window.clearTimeout(timer.current) }
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
      const name = nf.name.trim()
      server = await api<Server>(`/api/servers?reuse_ssh_endpoint=true${name ? '' : '&name_from_hostname=true'}`, {
        method: 'POST',
        body: JSON.stringify({ ...target, name: name || target.host, note: '', group_name: groupName }),
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
      window.clearTimeout(probeTimer.current)
    }
  }, [])

  useEffect(() => {
    setProbeRows(idleProbeRows())
    setProbeProgress(null)
  }, [entryId, exitId])

  useEffect(() => {
    if (!busy && cascade?.status !== 'installing') return
    const interval = window.setInterval(() => setClockNow(Date.now()), 1000)
    return () => window.clearInterval(interval)
  }, [busy, cascade?.status])

  async function runProbe(eId = entryId, xId = exitId, prepareTransport?: CascadeImageTransport) {
    if (eId == null || xId == null || activeProbe.current) return
    const selectedTransport = prepareTransport ?? transport
    const ports = { entry_port: cascadePort(entryPort), exit_port: cascadePort(exitPort) }
    if (selectedTransport === 'awg' && (ports.entry_port === undefined || ports.exit_port === undefined)) {
      setError(t('UDP-порт должен быть целым числом от 1 до 65535 или пустым для автовыбора.'))
      return
    }
    const controller = new AbortController()
    const run = { controller, preparing: prepareTransport !== undefined }
    activeProbe.current = run
    const runId = cascadeRequestId()
    const pending: CascadeSideProgress = { status: 'pending', stage: 'queued', started_at: null, updated_at: null }
    setProbeProgress({ run_id: runId, entry_server_id: eId, exit_server_id: xId, transport: selectedTransport,
      status: 'running', started_at: '', updated_at: '', sides: { entry: { ...pending }, exit: { ...pending } } })
    setBusy(true)
    setError(null)
    let finished = false
    const poll = async () => {
      if (finished || activeProbe.current !== run || controller.signal.aborted) return
      try {
        const progress = await getCascadeProbeProgress(runId, controller.signal)
        if (!finished && activeProbe.current === run && !controller.signal.aborted
          && matchingProbeProgress(progress, runId, selectedTransport, eId, xId)) setProbeProgress(current => newerProbeProgress(current, progress))
      } catch (err) {
        // Registration may not yet be visible; transient errors do not end the POST.
        if (!controller.signal.aborted && err instanceof ApiError && err.status === 401) {
          controller.abort()
          onUnauthorized()
        }
      } finally {
        if (!finished && activeProbe.current === run && !controller.signal.aborted) probeTimer.current = window.setTimeout(poll, 1000)
      }
    }
    void poll()
    try {
      await runTransportProbes(async (kind, signal) => {
        try {
          return await probeCascadeTransport(eId, xId, kind,
            { entry_port: ports.entry_port ?? null, exit_port: ports.exit_port ?? null }, signal, kind === prepareTransport, runId)
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
      }, controller.signal, err => err instanceof Error ? err.message : t('Ответ проверки не соответствует транспорту.'), prepareTransport, selectedTransport)
      // Fetch the final stage once before stopping the progress loop.
      try {
        const progress = await getCascadeProbeProgress(runId, controller.signal)
        if (activeProbe.current === run && !controller.signal.aborted
          && matchingProbeProgress(progress, runId, selectedTransport, eId, xId)) setProbeProgress(current => newerProbeProgress(current, progress))
      } catch { /* The POST result remains authoritative if progress expired. */ }
    } finally {
      finished = true
      window.clearTimeout(probeTimer.current)
      if (!controller.signal.aborted && activeProbe.current === run) setProbeProgress(current => current?.run_id === runId && current.status === 'running'
        ? { ...current, status: 'error', sides: Object.fromEntries(Object.entries(current.sides).map(([side, value]) => [side,
          value.status === 'running' || value.status === 'pending' ? { ...value, status: 'pending', stage: '' } : value])) as CascadeProbeProgress['sides'] } : current)
      if (activeProbe.current === run) {
        activeProbe.current = null
        if (!controller.signal.aborted) setBusy(false)
      }
    }
  }

  function changeProbePort(set: (value: string) => void, value: string) {
    set(value)
    setProbeProgress(current => current?.transport === 'awg' ? null : current)
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
      ...(replacement?.routes?.length ? { routes: replacement.routes } : {}),
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
      setCreateNeedsRecovery(false)
      setEntryRecovery(null)
      setCascade(c)
      setStep(c.status === 'ready' ? 'done' : 'install')
      onChanged()
    } catch (err) {
      if (err instanceof ApiError && err.code === 'cascade_entry_recovery_required') {
        setCreateNeedsRecovery(true)
        setEntryRecovery(null)
      } else if (err instanceof TypeError || err instanceof ApiError && (err.status === 408 || err.status >= 500)) {
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
    if (!cascade || retryNeedsCountry || busy || recoveryConfirm) return
    setBusy(true)
    setError(null)
    try {
      setCascade(await reinstallCascade(cascade.id, countryError ? entryCountry : undefined))
      setEntryRecovery(null)
    } catch (err) {
      handleError(err)
    } finally {
      setBusy(false)
    }
  }

  async function checkEntryRecovery() {
    if (!recoveryTarget || busy || entryRecovery) return
    setBusy(true)
    setError(null)
    setEntryRecovery({ state: 'checking' })
    try {
      const preview = await previewCascadeEntryRecovery(recoveryTarget.entryId, recoveryTarget.cascadeId)
      setEntryRecovery({ state: 'confirm', preview })
    } catch (err) {
      setEntryRecovery(null)
      handleError(err)
    } finally {
      setBusy(false)
    }
  }

  async function removeOldGateway() {
    if (!recoveryTarget || busy || entryRecovery?.state !== 'confirm') return
    setBusy(true)
    setError(null)
    setEntryRecovery({ state: 'removing' })
    try {
      await recoverCascadeEntry(recoveryTarget.entryId, entryRecovery.preview.token, recoveryTarget.cascadeId)
      setEntryRecovery({ state: 'removed' })
      onChanged()
    } catch (err) {
      setEntryRecovery(null)
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
          disabled={busy || recoveryConfirm}
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
          <strong>{sub}</strong>
          <div className="mono muted small">{ip || s?.host}</div>
        </div>
      </div>
    )
  }

  // Use the role label when the only available name repeats the address.
  const named = (s: Server | null, role: string) =>
    s && s.name !== s.host ? s.name : t(role)

  function sides(installing: boolean) {
    const currentProgress = probeProgress && entryId !== null && exitId !== null
      && matchingProbeProgress(probeProgress, probeProgress.run_id, transport, entryId, exitId) ? probeProgress : null
    const row = probeRows[transport]
    return <div className="cas-sides">
      {(['entry', 'exit'] as const).map(side => {
        const server = side === 'entry' ? entry : exit
        const country = side === 'entry' ? cascade ? cascadeEntryCountry(cascade, entry) : entryCountry || entry?.country : exit?.country
        const flag = countryFlag(country || '')
        const ip = installing ? side === 'entry' ? cascade?.entry_ip : cascade?.exit_ip : server?.host
        let progress = installing ? cascade?.progress?.[side] : currentProgress?.sides[side]
        // Legacy jobs have only a phase. An error without a phase belongs to neither side.
        if (installing && !progress && cascade) progress = {
          status: cascade.status === 'ready' || cascade.phase === 'entry' && side === 'exit' ? 'done'
            : cascade.phase === side ? cascade.status === 'error' ? 'error' : 'running' : 'pending',
          stage: cascade.status === 'ready' || cascade.phase === 'entry' && side === 'exit' ? 'completed'
            : cascade.phase === side ? cascade.status === 'error' ? 'failed' : 'installing' : 'queued',
          started_at: null, updated_at: null,
        }
        const sideError = !installing && row.result?.failed_side === side ? row.result.error : ''
        const cleanupFailed = !installing && row.result?.cleanup_failed?.includes(side)
        return <section key={side} className="cas-side">
          <div className="cas-side-head">
            {flag && <span className="server-flag">{flag}</span>}
            <div><strong>{server?.name || ip || t(side === 'entry' ? 'Вход' : 'Выход')}</strong><span className="mono muted small">{ip || server?.host}</span></div>
          </div>
          <div className="cas-side-role small muted">{side === 'entry' ? t('Вход · подключение клиентов') : t('Выход · доступ в интернет')}</div>
          <SideProgress side={progress} now={clockNow} waiting={installing ? t('Ожидает своей очереди') : currentProgress ? t('Ход этого сервера не подтвержден') : t('Готов к проверке')} />
          {sideError && <p className="small err-text">{t(sideError)}</p>}
          {cleanupFailed && <p className="small err-text">{t('Очистка временных ресурсов не подтверждена')}</p>}
        </section>
      })}
    </div>
  }

  function route(withClients: boolean) {
    const probe = probeRows[transport].result
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
            {kind === 'entry' && entry && cascadeEntryHasExistingRoute(entry) && (
              <p className="muted small" role="status">{t('Обнаружены признаки существующего маршрута. Панель проверит вход перед установкой.')}</p>
            )}
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
            <label>
              {t('Название')}
              <input
                value={nf.name}
                maxLength={128}
                disabled={busy}
                placeholder={t('Автоматически по имени сервера')}
                onChange={(e) => setNf({ ...nf, name: e.target.value })}
              />
            </label>
            <p className="muted small">{t('Если оставить пустым, панель возьмет имя из SSH-проверки, а если оно недоступно - адрес сервера.')}</p>
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
        <button className="ghost" disabled={preparing || recoveryBusy} onClick={close}>
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
            <p className="muted small">{t('Выберите канал и запустите проверку. Этапы показаны отдельно для каждого сервера.')}</p>
            <div className="cas-opts cas-opts-compact">
              {PROBE_TRANSPORTS.map(k => <label key={k} className={`cas-transport-option${transport === k ? ' on' : ''}`}>
                <input type="radio" name="cas-transport" checked={transport === k} disabled={busy || recoveryBusy || recoveryConfirm}
                  onChange={() => setTransport(k)} />
                <span><b>{cascadeTransportLabel(k)}</b><small className="muted">{k === 'awg' ? t('UDP · шифрование') : k === 'vless' ? t('TCP · шифрование') : t('Без шифрования')}</small></span>
              </label>)}
            </div>
            {sides(false)}
            <div className="cas-probe-summary">
              <TransportProbeStatus row={probeRows[transport]} />
              {transport !== 'gre' && probeRows[transport].state === 'unavailable' && probeRows[transport].result?.reason === 'local_image_missing' &&
                <button className="ghost" disabled={busy || recoveryConfirm} onClick={() => void runProbe(entryId, exitId, transport)}>{t('Подготовить и проверить')}</button>}
            </div>
            <p className="muted small">{transport === 'gre' ? t('Туннель без шифрования межсерверного участка. Выбирайте только при осознанной необходимости открытого GRE.') : t('Работаем с межсерверным каналом. Клиентские ключи не меняются.')}</p>
            {(!entry?.country || entryCountry) && countryInput()}
            {transport === 'awg' && <details className="cas-port-options">
              <summary>{t('UDP-порты межсерверного канала')}</summary>
              <p className="muted small">{t('Пустые поля — автоматический выбор. Проверенные UDP-порты сохраняются при установке.')}</p>
              <div className="cas-row2">
                <label>{t('UDP-порт входа')}<input inputMode="numeric" disabled={busy || recoveryConfirm} value={entryPort} onChange={e => changeProbePort(setEntryPort, e.target.value)} placeholder={t('Автоматически')} /></label>
                <label>{t('UDP-порт выхода')}<input inputMode="numeric" disabled={busy || recoveryConfirm} value={exitPort} onChange={e => changeProbePort(setExitPort, e.target.value)} placeholder={t('Автоматически')} /></label>
              </div>
            </details>}
          </>
        )}

        {step === 'install' && cascade && (
          <>
            {head(cascade.status === 'error' ? t('Каскад не собрался') : t('Собираю каскад'))}
            {steps}
            {sides(true)}
            {cascade.error && !entryOwnershipError && <p className="small err-text">{countryError
              ? t('Не удалось определить страну входа. Укажите ее вручную и повторите установку.') : cascade.error}</p>}
            {countryError && countryInput()}
            {cascade.log && <details className="cas-details"><summary>{t('Подробный журнал')}</summary><pre className="script-box deploy-log">{cascade.log}</pre></details>}
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

        {recoveryTarget && <div className="cas-recovery">
          {!entryRecovery && <p className="small err-text">{t('Установка остановилась на проверке старого шлюза на входе.')}</p>}
          {entryRecovery?.state === 'checking' && <p className="muted small" role="status">{t('Проверяем шлюз на входе…')}</p>}
          {entryRecovery?.state === 'confirm' && <>
            <strong>{t('Старый шлюз на входе')} · {cascadeTransportLabel(entryRecovery.preview.transport)}</strong>
            <p>{t('Панель снимет старый шлюз только на входе. VPN-клиенты и их конфигурации сохранятся.')}</p>
            <p className="muted small">{t('До установки нового каскада трафик клиентов может идти напрямую через вход.')}</p>
            <p className="muted small">{t('Затем можно повторить установку на уже выбранный выход.')}</p>
          </>}
          {entryRecovery?.state === 'removing' && <p className="muted small" role="status">{t('Снимаем шлюз…')}</p>}
          {entryRecovery?.state === 'removed' && <p className="ok-text small" role="status">{t('Старый шлюз снят. Повторите установку каскада.')}</p>}
        </div>}
        {error && <p className="small err-text" role="alert">{error}</p>}

        <div className="cas-actions">
          {((step === 'exit' && !replacement) || step === 'link') && (
            <button
              className="ghost"
              disabled={busy || recoveryConfirm}
              onClick={() => {
                setError(null)
                setCreateNeedsRecovery(false)
                setEntryRecovery(null)
                setTab('panel')
                setScript(null)
                setStep(step === 'exit' ? 'entry' : 'exit')
              }}
            >
              {t('Назад')}
            </button>
          )}
          {step === 'link' && (
            <button className="ghost" disabled={busy || recoveryConfirm} onClick={() => runProbe()}>
              {t('Проверить выбранный транспорт')}
            </button>
          )}
          <div className="cas-actions-r">
            {(step === 'entry' || step === 'exit') && (
              <button disabled={busy || !pickReady} onClick={next}>
                {busy ? t('Подключаюсь…') : t('Дальше')}
              </button>
            )}
            {recoveryTarget && !entryRecovery && <button className="ghost" disabled={busy} onClick={checkEntryRecovery}>
              {t('Проверить старый шлюз…')}
            </button>}
            {recoveryConfirm && <>
              <button className="ghost" onClick={() => setEntryRecovery(null)}>{t('Отмена')}</button>
              <button onClick={removeOldGateway}>{t('Снять старый шлюз')}</button>
            </>}
            {step === 'link' && !recoveryConfirm && (
              <button disabled={busy || invalidCountry} onClick={build}>
                {t('Собрать каскад')}
              </button>
            )}
            {step === 'install' && cascade?.status === 'error' && !recoveryConfirm && (
              <>
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
