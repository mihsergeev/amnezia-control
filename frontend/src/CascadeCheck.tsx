import { useEffect, useRef, useState } from 'react'
import { ApiError, checkCascade, type Cascade, type CascadeCheck, type Server } from './api'
import { countryFlag } from './format'
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
  const ru = (entry?.country || '').toUpperCase() === 'RU'

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
    fail: t('клиенты идут мимо шлюза'),
    state: st(result?.tproxy),
  })
  if (gre) {
    steps.push({
      label: t('GRE-туннель до выхода поднят'),
      fail: t('GRE-туннеля нет'),
      detail: result?.tunnel ? t('состояние {s}', { s: result.tunnel }) : undefined,
      state: st(result ? !!result.tunnel : undefined),
    })
  }
  const egressIdx = steps.length
  steps.push({
    label: t('Интернет через выход'),
    fail: t('через выход интернет не открывается'),
    detail: result?.egress ? t('адрес {ip}', { ip: result.egress }) : undefined,
    state: st(result ? !!result.egress : undefined),
  })
  if (ru || result?.ru) {
    steps.push({
      label: t('Сайты страны входа напрямую'),
      fail: '',
      detail: result?.ru ? t('адрес {ip}', { ip: result.ru }) : undefined,
      // без этой проверки каскад работает, просто местное идет не так, как задумано
      state: result ? (result.ru ? 'ok' : 'warn') : 'wait',
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
    if (states.every((s) => s === 'ok' || s === 'warn')) return 'ok'
    return running ? 'run' : 'idle'
  }
  const toEntry = link([view(0), view(1)])
  const toExit = link(gre ? [view(2)] : [view(egressIdx)])
  const toNet = link([view(egressIdx)])
  const done = !running && !!result && shown >= steps.length

  const reason = (() => {
    if (!result || result.ok) return ''
    return steps.find((s) => s.state === 'bad')?.fail ?? ''
  })()

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

        <div className="cc-route">
          <div className="cc-node cc-node-plain">{t('Клиенты')}</div>
          <div className={`cc-link cc-link-${toEntry}`} />
          {node(
            countryFlag(entry?.country || ''),
            entry?.host || cascade.entry_ip,
            entry?.name || t('вход'),
            toEntry === 'bad' ? 'bad' : toEntry === 'ok' ? 'ok' : 'idle',
          )}
          <div className={`cc-link cc-link-${toExit}`}>
            <span className="tun-badge">{gre ? 'GRE' : 'VLESS'}</span>
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

        <div
          className={`cc-progress ${done ? (result?.ok ? 'cc-progress-ok' : 'cc-progress-bad') : error ? 'cc-progress-bad' : ''}`}
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
          <p className={result.ok ? 'cc-verdict cc-verdict-ok' : 'cc-verdict cc-verdict-bad'}>
            {result.ok
              ? t('Каскад работает')
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
