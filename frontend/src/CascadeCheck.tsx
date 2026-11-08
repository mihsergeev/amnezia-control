import { useEffect, useRef, useState } from 'react'
import { ApiError, checkCascade, type Cascade, type CascadeCheck, type Server } from './api'
import { countryFlag } from './format'
import { cascadeClientExitConfirmed, cascadeEntryCountry, cascadeLocalExpected, cascadeLocalRoute, cascadeTransportLabel } from './cascadeUi'
import { CascadeSecurity } from './CascadeSecurity'
import { greLinkLabel } from './serverList'
import { useI18n } from './i18n'
import { useModalDismiss } from './useModalDismiss'

type Props = {
  cascade: Cascade
  entry?: Server
  exit?: Server
  onClose: () => void
  onChecked: () => void
  onUnauthorized: () => void
}

type StepState = 'wait' | 'ok' | 'bad' | 'warn'
type Step = { label: string; fail: string; detail?: string; state: StepState }

// пауза между шагами, когда пришел ответ: результат "проявляется" по пути трафика
const REVEAL_MS = 260

// Проверка канала каскада: путь клиенты -> вход -> выход -> интернет, по нему бежит
// анимация, пока вход отвечает, потом шаги по очереди отмечаются и красят участки
export function CascadeCheckModal({ cascade, entry, exit, onClose, onChecked, onUnauthorized }: Props) {
  const { t } = useI18n()
  const dismiss = useModalDismiss(onClose)
  const [result, setResult] = useState<CascadeCheck | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [running, setRunning] = useState(true)
  const [progress, setProgress] = useState(0)
  const [shown, setShown] = useState(0)
  const [run, setRun] = useState(0)
  const notify = useRef(onChecked)
  notify.current = onChecked

  const gre = cascade.transport === 'gre'
  const awg = cascade.transport === 'awg'
  const tunnelled = gre || awg
  const entryCountry = cascadeEntryCountry(cascade, entry)

  useEffect(() => {
    let alive = true
    setResult(null)
    setError(null)
    setRunning(true)
    setProgress(0)
    setShown(0)
    // сколько займет проверка, заранее не известно: полоса ползет к 90% и
    // замедляется, а ответ добивает ее до конца
    const tick = window.setInterval(() => setProgress((p) => p + (90 - p) * 0.06), 120)
    checkCascade(cascade.id)
      .then((r) => {
        if (!alive) return
        setResult(r)
        notify.current()
      })
      .catch((err) => {
        if (!alive) return
        if (err instanceof ApiError && err.status === 401) {
          onUnauthorized()
          return
        }
        setError(err instanceof Error ? err.message : t('Ошибка'))
      })
      .finally(() => {
        if (!alive) return
        window.clearInterval(tick)
        setProgress(100)
        setRunning(false)
      })
    return () => {
      alive = false
      window.clearInterval(tick)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [cascade.id, run])

  const steps: Step[] = []
  const st = (ok: boolean | undefined): StepState => (ok === undefined ? 'wait' : ok ? 'ok' : 'bad')
  steps.push({
    label: t('Шлюз на входе запущен'),
    fail: t('шлюз на входе не запущен'),
    state: st(result?.gateway),
  })
  steps.push({
    label: t('Клиенты идут через шлюз'),
    fail: result && result.tproxy && !result.rule
      ? t('пропало правило маршрутизации в шлюз')
      : t('клиенты идут мимо шлюза'),
    state: st(result ? result.tproxy && result.rule !== false : undefined),
  })
  if (tunnelled) {
    // рабочий GRE-интерфейс Linux показывает как UNKNOWN, DOWN - выключен
    const down = result?.tunnel === 'DOWN'
    steps.push({
      label: awg ? t('Туннель AWG до выхода отвечает') : t('GRE-туннель до выхода поднят'),
      fail: awg ? t('Канал AWG до выхода не отвечает') : down ? t('GRE-туннель выключен') : t('GRE-туннеля нет'),
      detail: awg && result?.handshake_age != null ? t('Последний handshake: {n} с назад', { n: result.handshake_age }) : undefined,
      state: st(result ? awg ? result.tunnel === 'UP' : !!result.tunnel && !down : undefined),
    })
  }
  const egressIdx = steps.length
  const gatewayConfirmed = result && (result.egress_confirmed ?? Boolean(result.egress && result.direct && result.egress !== result.direct))
  steps.push({
    label: gatewayConfirmed === false ? t('Выход шлюза через каскад не подтвержден') : t('Интернет через выход'),
    fail: t('Выход шлюза через каскад не подтвержден'),
    detail: result?.egress ? t('адрес {ip}', { ip: result.egress }) : undefined,
    state: st(gatewayConfirmed ?? undefined),
  })
  // путь клиентов целиком: адрес изнутри VPN-контейнера на входе. Шлюз выше
  // проверяется напрямую и не заметит, если клиенты идут в интернет мимо него
  const clientIdx = steps.length
  const clientConfirmed = result ? cascadeClientExitConfirmed(result) : false
  steps.push({
    label: result?.leak
      ? t('Клиенты выходят в интернет мимо выхода')
      : !result || clientConfirmed
        ? t('Клиенты выходят с адреса выхода')
        : t('Выход клиентов через каскад не подтвержден'),
    fail: result?.leak ? t('клиенты выходят в интернет мимо выхода') : t('Выход клиентов через каскад не подтвержден'),
    detail: result
      ? result.client
        ? t('адрес {ip}', { ip: result.client })
        : t('из контейнера спросить нечем')
      : undefined,
    state: !result
      ? 'wait'
      : result.leak
        ? 'bad'
        : clientConfirmed ? 'ok' : result.ok ? 'warn' : 'bad',
  })
  const localRoute = result ? cascadeLocalRoute(result) : 'unknown'
  const localExpected = cascadeLocalExpected(cascade.routes)
  const checksLocalRoute = entryCountry === 'RU' || Boolean(result?.ru)
  const localRouteWarning = checksLocalRoute && localRoute !== localExpected
  if (checksLocalRoute) {
    steps.push({
      label: localExpected === 'exit' && (!result || localRoute === 'exit')
        ? t('Проверочный сайт страны входа идет через выход по ручному правилу')
        : !result || localRoute === 'entry'
        ? t('Проверочный сайт страны входа открыт напрямую')
        : localRoute === 'exit'
          ? t('Проверочный сайт страны входа идет через выход')
          : t('Маршрут для сайта страны входа не подтвержден'),
      fail: '',
      detail: result?.ru ? t('адрес {ip}', { ip: result.ru }) : undefined,
      state: result ? (localRouteWarning ? 'warn' : 'ok') : 'wait',
    })
  }

  // результат проявляется по шагам, после ответа
  useEffect(() => {
    if (!result) return
    if (shown >= steps.length) return
    const id = window.setTimeout(() => setShown((n) => n + 1), REVEAL_MS)
    return () => window.clearTimeout(id)
  }, [result, error, shown, steps.length])

  // без ответа (вход не ответил по SSH) шаги остаются серыми: проверить их не вышло
  const view = (i: number): StepState => (result && i < shown ? steps[i].state : 'wait')
  // участок пути готов, когда проявились все его шаги
  const link = (states: StepState[]): 'run' | 'ok' | 'bad' | 'idle' => {
    if (states.some((s) => s === 'bad')) return 'bad'
    if (states.every((s) => s === 'ok')) return 'ok'
    return running ? 'run' : 'idle'
  }
  const toEntry = link([view(0), view(1)])
  const toExit = link(tunnelled ? [view(2)] : [view(egressIdx)])
  const toNet = link([view(egressIdx), view(clientIdx)])
  const done = !running && !!result && shown >= steps.length
  const healthy = result?.ok && gatewayConfirmed
  const verdictTone = !healthy ? 'bad' : !clientConfirmed || localRouteWarning ? 'warn' : 'ok'

  const reason = result && !healthy
    ? result.reason ? t(result.reason) : steps.find((s) => s.state === 'bad')?.fail ?? ''
    : ''

  const node = (flag: string, title: string, sub: string, state: 'ok' | 'bad' | 'idle') => (
    <div className={`cc-node cc-node-${state}`}>
      {flag && <span className="server-flag">{flag}</span>}
      <div>
        <div className="mono">{title}</div>
        <div className="muted small">{sub}</div>
      </div>
    </div>
  )

  return (
    <div className="modal-backdrop" onClick={dismiss}>
      <div className="card modal modal-wide cc" onClick={(e) => e.stopPropagation()}>
        <h3>{t('Проверка каскада')}</h3>

        <div className="cc-route cc-route-cascade">
          <div className="cc-node cc-node-plain">{t('Клиенты')}</div>
          <div className={`cc-link cc-link-${toEntry}`} />
          {node(
            countryFlag(entryCountry),
            entry?.host || cascade.entry_ip,
            entry?.name || t('вход'),
            toEntry === 'bad' ? 'bad' : toEntry === 'ok' ? 'ok' : 'idle',
          )}
          <div className={`cc-link cc-link-${toExit}`}>
            <span className="tun-badge">{gre ? greLinkLabel(entry) : cascadeTransportLabel(cascade.transport)}</span>
          </div>
          {node(
            countryFlag(exit?.country || ''),
            result?.egress || exit?.host || cascade.exit_ip,
            exit?.name || t('выход'),
            toExit === 'bad' ? 'bad' : toExit === 'ok' ? 'ok' : 'idle',
          )}
          <div className={`cc-link cc-link-${toNet}`} />
          <div className={`cc-node cc-node-plain cc-node-${toNet === 'ok' ? 'ok' : toNet === 'bad' ? 'bad' : 'idle'}`}>
            {t('Интернет')}
          </div>
        </div>

        <CascadeSecurity encrypted={(result ?? cascade).encrypted} encryption={(result ?? cascade).encryption} />

        <div
          className={`cc-progress ${done ? `cc-progress-${verdictTone}` : error ? 'cc-progress-bad' : ''}`}
        >
          <div style={{ width: `${progress}%` }} />
        </div>

        <ul className="cc-steps">
          {steps.map((s, i) => {
            const v = view(i)
            // проверка оборвалась без ответа - шаги не крутятся дальше
            const cls = v === 'wait' && !running && !result ? 'idle' : v
            return (
              <li key={s.label} className={`cc-step cc-step-${cls}`}>
                <span className="cc-icon" aria-hidden="true">
                  {v === 'ok' ? '✓' : v === 'bad' ? '✕' : v === 'warn' ? '!' : ''}
                </span>
                <span>{s.label}</span>
                {i < shown && s.detail && <span className="muted small mono">{s.detail}</span>}
              </li>
            )
          })}
        </ul>

        {done && result && (
          <p className={`cc-verdict cc-verdict-${verdictTone}`}>
            {healthy
              ? !clientConfirmed
                ? t('Шлюз отвечает, выход клиентов через каскад не подтвержден')
                : localRouteWarning ? t('Связь через выход работает') : t('Каскад работает')
              : reason
                ? t('Каскад не работает: {reason}', { reason })
                : t('Каскад не работает')}
            <span className="muted small">
              {' · '}
              {new Date(result.checked_at).toLocaleTimeString()}
            </span>
          </p>
        )}
        {error && !running && (
          <p className="form-error">{t('Вход не ответил: {err}', { err: error })}</p>
        )}

        <div className="modal-actions">
          <button className="ghost" onClick={onClose}>
            {t('Закрыть')}
          </button>
          <button disabled={running} onClick={() => setRun((n) => n + 1)}>
            {running ? t('Проверяю…') : t('Проверить еще раз')}
          </button>
        </div>
      </div>
    </div>
  )
}
