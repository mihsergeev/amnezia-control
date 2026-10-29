import { useCallback, useEffect, useRef, useState } from 'react'
import {
  api,
  ApiError,
  createCascade,
  getCascade,
  inCascade,
  parseCheckInfo,
  probeCascade,
  reinstallCascade,
  type Cascade,
  type CascadeProbe,
  type CascadeTransport,
  type ProbeSide,
  type Server,
} from './api'
import { copyText } from './clipboard'
import { countryFlag, formatBytes } from './format'
import { useI18n } from './i18n'
import { useModalDismiss } from './useModalDismiss'

type Step = 'entry' | 'exit' | 'link' | 'install' | 'done'

type Props = {
  servers: Server[]
  cascades: Cascade[]
  defaultUser: string
  // открыть сразу на установке уже созданного каскада (ход или ошибка)
  resume?: Cascade
  onClose: () => void
  onChanged: () => void
  onUnauthorized: () => void
}

const STEPS: { key: Step; label: string }[] = [
  { key: 'entry', label: '1. Вход' },
  { key: 'exit', label: '2. Выход' },
  { key: 'link', label: '3. Связь' },
  { key: 'install', label: '4. Установка' },
]

function probeText(t: ReturnType<typeof useI18n>['t'], p: ProbeSide): string {
  if (p.ok) {
    return t('{size} за {secs} с, ~{mbps} Мбит/с', {
      size: formatBytes(p.bytes),
      secs: p.secs,
      mbps: p.mbps,
    })
  }
  if (p.error) return p.error
  return p.bytes > 0
    ? t('замерзает на {size}', { size: formatBytes(p.bytes) })
    : t('не проходит')
}

// шаги установки по фазе: выход ставится первым, потом вход и проверка
function installTasks(c: Cascade) {
  const gre = c.transport === 'gre'
  const order = ['exit', 'entry']
  // ошибка без стороны (установку прервал рестарт панели) - крестик ставить некуда
  const at =
    c.status === 'ready' ? 2 : c.phase ? order.indexOf(c.phase) : c.status === 'error' ? -1 : 0
  const failed = c.status === 'error'
  const state = (i: number) =>
    i < at ? 'ok' : i === at ? (failed ? 'bad' : c.status === 'ready' ? 'ok' : 'run') : 'wait'
  return [
    {
      title: gre ? 'Выход: GRE-туннель и выпуск в интернет' : 'Выход: сервер VLESS Reality',
      sub: gre
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
  onClose,
  onChanged,
  onUnauthorized,
}: Props) {
  const { t } = useI18n()
  const dismiss = useModalDismiss(onClose)
  const [step, setStep] = useState<Step>(
    resume ? (resume.status === 'ready' ? 'done' : 'install') : 'entry',
  )
  const [entryId, setEntryId] = useState<number | null>(resume?.entry_server_id ?? null)
  const [exitId, setExitId] = useState<number | null>(resume?.exit_server_id ?? null)
  const [tab, setTab] = useState<'panel' | 'new'>('panel')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  // новый сервер: по паролю (панель сама ставит ключ) или скриптом
  const [nf, setNf] = useState({ host: '', port: 22, user: 'root', password: '' })
  const [nfMode, setNfMode] = useState<'password' | 'script'>('password')
  const [script, setScript] = useState<{ server: Server; text: string } | null>(null)
  const [copied, setCopied] = useState(false)
  const [probe, setProbe] = useState<CascadeProbe | null>(null)
  const [transport, setTransport] = useState<CascadeTransport>('vless')
  const [cascade, setCascade] = useState<Cascade | null>(resume ?? null)
  const [extra, setExtra] = useState<Server[]>([])
  const timer = useRef<number | undefined>(undefined)
  const [pollTick, setPollTick] = useState(0)

  const all = [...servers, ...extra.filter((x) => !servers.some((s) => s.id === x.id))]
  const byId = (id: number | null) => all.find((s) => s.id === id) ?? null
  const entry = byId(entryId)
  const exit = byId(exitId)

  const handleError = useCallback(
    (err: unknown) => {
      if (err instanceof ApiError && err.status === 401) onUnauthorized()
      else setError(err instanceof Error ? err.message : t('Ошибка'))
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

  const candidates = (exclude: number | null) =>
    all.filter((s) => s.id !== exclude && s.last_check_ok === true && !inCascade(s, cascades))

  async function addServer(groupName: string): Promise<Server | null> {
    setBusy(true)
    setError(null)
    try {
      const created = await api<Server>('/api/servers', {
        method: 'POST',
        body: JSON.stringify({
          name: nf.host.trim(),
          host: nf.host.trim(),
          ssh_port: nf.port,
          ssh_user: nfMode === 'password' ? nf.user.trim() : defaultUser,
          note: '',
          group_name: groupName,
        }),
      })
      onChanged()
      if (nfMode === 'script') {
        const { script: text } = await api<{ script: string }>(
          `/api/servers/${created.id}/setup-script`,
        )
        setScript({ server: created, text })
        setCopied(false)
        return null
      }
      const ready = await api<Server>(`/api/servers/${created.id}/bootstrap`, {
        method: 'POST',
        body: JSON.stringify({ password: nf.password, become_password: null }),
      })
      setExtra((x) => [...x, ready])
      setNf({ host: '', port: 22, user: 'root', password: '' })
      setTab('panel')
      return ready
    } catch (err) {
      handleError(err)
      return null
    } finally {
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
      if (s.last_check_ok !== true) {
        setError(t('Сервер пока не отвечает по ключу панели: скрипт выполнен под root ?'))
        return null
      }
      setExtra((x) => [...x, s])
      setScript(null)
      setTab('panel')
      return s
    } catch (err) {
      handleError(err)
      return null
    } finally {
      setBusy(false)
    }
  }

  async function runProbe(eId = entryId, xId = exitId) {
    if (eId == null || xId == null) return
    setBusy(true)
    setError(null)
    setProbe(null)
    try {
      const p = await probeCascade(eId, xId)
      setProbe(p)
      setTransport(p.recommend || (p.gre.ok ? 'gre' : 'vless'))
    } catch (err) {
      handleError(err)
    } finally {
      setBusy(false)
    }
  }

  async function next() {
    setError(null)
    if (step === 'entry' || step === 'exit') {
      let picked = step === 'entry' ? entry : exit
      if (tab === 'new') {
        picked = script ? await scriptDone() : await addServer(step === 'exit' ? entry?.group_name ?? '' : '')
        if (!picked) return
        if (step === 'entry') setEntryId(picked.id)
        else setExitId(picked.id)
      }
      if (!picked) return
      if (step === 'entry') {
        setStep('exit')
        setTab('panel')
      } else {
        setStep('link')
        void runProbe(entryId, picked.id)
      }
    }
  }

  async function build() {
    if (entryId == null || exitId == null) return
    setBusy(true)
    setError(null)
    try {
      const c = await createCascade(entryId, exitId, transport)
      setCascade(c)
      setStep('install')
      onChanged()
    } catch (err) {
      handleError(err)
    } finally {
      setBusy(false)
    }
  }

  async function retry() {
    if (!cascade) return
    setBusy(true)
    setError(null)
    try {
      setCascade(await reinstallCascade(cascade.id))
    } catch (err) {
      handleError(err)
    } finally {
      setBusy(false)
    }
  }

  const stepIdx = STEPS.findIndex((s) => s.key === step)
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
    const gre = (cascade?.transport ?? transport) === 'gre'
    const exitIp = cascade?.result.egress || probe?.exit_ip || cascade?.exit_ip || exit?.host || ''
    return (
      <div className="srv-route">
        {withClients && (
          <>
            <span className="srv-route-label">{t('Клиенты')}</span>
            <span className="srv-route-arrow">→</span>
          </>
        )}
        {hop(entry, cascade?.entry_ip || probe?.entry_ip || '', named(entry, 'вход'))}
        <span className="srv-route-arrow">
          {(step === 'done' || step === 'install') && (
            <span className="tun-badge">{gre ? 'GRE' : 'VLESS'}</span>
          )}
          →
        </span>
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
    const list = candidates(kind === 'exit' ? entryId : exitId)
    const value = kind === 'entry' ? entryId : exitId
    const set = kind === 'entry' ? setEntryId : setExitId
    return (
      <>
        <div className="tabs">
          <button
            className={tab === 'panel' ? 'tab tab-active' : 'tab'}
            onClick={() => setTab('panel')}
          >
            {t('Уже в панели')}
          </button>
          <button
            className={tab === 'new' ? 'tab tab-active' : 'tab'}
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
              {t('Серверы, которые уже входят в каскад или не на связи, в списке не показаны.')}
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
                {t('Адрес')}
                <input
                  className="mono"
                  value={nf.host}
                  onChange={(e) => setNf({ ...nf, host: e.target.value })}
                  placeholder="203.0.113.10"
                />
              </label>
              <label>
                {t('Порт SSH')}
                <input
                  type="number"
                  value={nf.port}
                  onChange={(e) => setNf({ ...nf, port: Number(e.target.value) || 22 })}
                />
              </label>
            </div>
            <div className="tabs">
              <button
                className={nfMode === 'password' ? 'tab tab-active' : 'tab'}
                onClick={() => setNfMode('password')}
              >
                {t('Пароль')}
              </button>
              <button
                className={nfMode === 'script' ? 'tab tab-active' : 'tab'}
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
                      onChange={(e) => setNf({ ...nf, user: e.target.value })}
                    />
                  </label>
                  <label>
                    {t('Пароль')}
                    <input
                      type="password"
                      autoComplete="new-password"
                      value={nf.password}
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
        <button className="ghost" onClick={onClose}>
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
                'Выход - сервер в другой стране, с его адреса клиенты будут выходить в интернет. Клиентов на нем не будет, можно взять пустой.',
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
            <div className="cas-probe">
              <div className="muted small">
                {t('Проверка канала: панель отправляет 20 мб со входа на выход')}
              </div>
              {busy && !probe ? (
                <div className="cas-probe-row">
                  <span>{t('Проверяю, это до минуты…')}</span>
                </div>
              ) : (
                probe && (
                  <>
                    <div className="cas-probe-row">
                      <span>{t('Обычный TCP')}</span>
                      <span className={probe.tcp.ok ? 'ok-text' : 'err-text'}>
                        {probeText(t, probe.tcp)}
                      </span>
                    </div>
                    <div className="cas-probe-row">
                      <span>GRE</span>
                      <span className={probe.gre.ok ? 'ok-text' : 'err-text'}>
                        {probeText(t, probe.gre)}
                      </span>
                    </div>
                    {!probe.gre.ok && (probe.entry_nat || probe.exit_nat) && (
                      <div className="muted small">
                        {probe.entry_nat && probe.exit_nat
                          ? t(
                              'Вход и выход за NAT хостера: на интерфейсах внутренние адреса. GRE через такой NAT обычно не проходит, это настройки сети хостера, а не панели.',
                            )
                          : probe.exit_nat
                            ? t(
                                'Выход за NAT хостера: на его интерфейсе внутренний адрес. GRE через такой NAT обычно не проходит, это настройки сети хостера, а не панели.',
                              )
                            : t(
                                'Вход за NAT хостера: на его интерфейсе внутренний адрес. GRE через такой NAT обычно не проходит, это настройки сети хостера, а не панели.',
                              )}
                      </div>
                    )}
                    {!probe.tcp.ok && probe.tcp.bytes > 0 && (
                      <div className="muted small">
                        {t(
                          'Так режут фильтры у провайдера входа: в сеть выхода по TCP уходит только несколько десятков килобайт.',
                        )}
                      </div>
                    )}
                    {!probe.recommend && (
                      <div className="small err-text">
                        {t(
                          'Ни один способ не прошел. Проверьте фаервол у провайдера выхода, собрать можно и так, но работать скорее всего не будет.',
                        )}
                      </div>
                    )}
                  </>
                )
              )}
            </div>
            <div className="cas-opts">
              {(['vless', 'gre'] as const).map((k) => (
                <label key={k} className={transport === k ? 'on' : ''}>
                  <input
                    type="radio"
                    name="cas-transport"
                    checked={transport === k}
                    onChange={() => setTransport(k)}
                  />
                  <div>
                    <b>
                      {k === 'vless' ? 'VLESS Reality' : 'GRE'}
                      {probe?.recommend === k && (
                        <span className="cas-rec">{t('рекомендуется')}</span>
                      )}
                    </b>
                    <p className="muted small">
                      {k === 'vless'
                        ? t(
                            'Шифрованный туннель, снаружи похож на обычный HTTPS. Подходит, когда TCP от входа к выходу проходит.',
                          )
                        : t(
                            'Голый туннель, такие фильтры его не трогают. Без шифрования: по дороге видны имена сайтов и незашифрованный трафик клиентов.',
                          )}
                    </p>
                  </div>
                </label>
              ))}
            </div>
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
            {cascade.error && <p className="small err-text">{cascade.error}</p>}
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
            <div className="cas-checks">
              {cascade.result.egress && (
                <div>
                  <span className="ok-text">✓</span>{' '}
                  {t('Остальные сайты открываются с {ip}', { ip: cascade.result.egress })}
                </div>
              )}
              {cascade.result.ru && (
                <div>
                  <span className="ok-text">✓</span>{' '}
                  {t('Сайты страны входа идут напрямую с {ip}', { ip: cascade.result.ru })}
                </div>
              )}
              {(cascade.transport === 'gre' ? cascade.probe.gre : cascade.probe.tcp)?.ok && (
                <div>
                  <span className="ok-text">✓</span>{' '}
                  {t('Канал вход -> выход: ~{mbps} Мбит/с', {
                    mbps: (cascade.transport === 'gre' ? cascade.probe.gre : cascade.probe.tcp)!.mbps,
                  })}
                </div>
              )}
              <div>
                <span className="ok-text">✓</span>{' '}
                {t('Перезагрузку обоих серверов переживает: туннель и шлюз - службы systemd')}
              </div>
            </div>
            {entry && (parseCheckInfo(entry)?.amnezia_containers ?? []).length === 0 && (
              <p className="muted small">
                {t(
                  'Протоколов для клиентов на входе пока нет. Развернуть AmneziaWG или XRay можно в карточке сервера, меню «Ещё».',
                )}
              </p>
            )}
          </>
        )}

        {error && <p className="small err-text">{error}</p>}

        <div className="cas-actions">
          {(step === 'exit' || step === 'link') && (
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
              <button disabled={busy} onClick={build}>
                {t('Собрать каскад')}
              </button>
            )}
            {step === 'install' && cascade?.status === 'error' && (
              <button disabled={busy} onClick={retry}>
                {t('Запустить еще раз')}
              </button>
            )}
            {step === 'done' && <button onClick={onClose}>{t('Готово')}</button>}
          </div>
        </div>
      </div>
    </div>
  )
}
