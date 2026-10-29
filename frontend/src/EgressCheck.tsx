import { useEffect, useState } from 'react'
import { ApiError, checkEgress, type EgressCheck, type Server } from './api'
import { countryFlag } from './format'
import { useI18n } from './i18n'
import { useModalDismiss } from './useModalDismiss'

type Props = {
  server: Server
  onClose: () => void
  onChecked: () => void
  onUnauthorized: () => void
}

type StepState = 'wait' | 'ok' | 'bad' | 'warn'
type Step = { label: string; detail?: string; state: StepState }

const REVEAL_MS = 200

// Проверка выхода клиентов: откуда трафик клиентов уходит в интернет и
// открываются ли сайты. Панель смотрит путем клиентов (сеть VPN-контейнера),
// поэтому годится и для каскада, собранного руками
export function EgressCheckModal({ server, onClose, onChecked, onUnauthorized }: Props) {
  const { t } = useI18n()
  const dismiss = useModalDismiss(onClose)
  const [result, setResult] = useState<EgressCheck | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [running, setRunning] = useState(true)
  const [progress, setProgress] = useState(0)
  const [shown, setShown] = useState(0)
  const [run, setRun] = useState(0)

  useEffect(() => {
    let alive = true
    setResult(null)
    setError(null)
    setRunning(true)
    setProgress(0)
    setShown(0)
    const tick = window.setInterval(() => setProgress((p) => p + (90 - p) * 0.05), 120)
    checkEgress(server.id)
      .then((r) => {
        if (!alive) return
        setResult(r)
        onChecked()
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
  }, [server.id, run])

  const ru = (server.country || '').toUpperCase() === 'RU'
  const direct = !!result?.egress && result.egress === server.host
  const steps: Step[] = [
    {
      label: t('Интернет из VPN-контейнера'),
      detail: result?.container || undefined,
      state: result ? (result.egress ? 'ok' : 'bad') : 'wait',
    },
  ]
  if (result?.egress) {
    steps.push({
      label: direct
        ? t('Клиенты выходят с этого сервера')
        : t('Выход в интернет: {ip}', { ip: result.egress }),
      detail: [result.egress_country, result.egress_org].filter(Boolean).join(', ') || undefined,
      state: 'ok',
    })
  }
  if (ru) {
    steps.push({
      label: t('Сайты страны сервера'),
      // каскад выпускает местное напрямую с входа; тот же адрес, что у выхода, -
      // местное тоже идет через выход (бывает и так, это не поломка)
      detail: result?.local
        ? result.local === result.egress
          ? t('через выход, {ip}', { ip: result.local })
          : t('напрямую, {ip}', { ip: result.local })
        : undefined,
      // без ответа сервиса адреса это еще не поломка: так бывает и при рабочем выходе
      state: result ? (result.local ? 'ok' : 'warn') : 'wait',
    })
  }
  for (const s of result?.sites ?? []) {
    steps.push({
      label: s.name,
      detail: s.ok ? t('{ms} мс', { ms: String(s.ms) }) : t('не открывается'),
      state: s.ok ? 'ok' : 'bad',
    })
  }

  useEffect(() => {
    if (!result || shown >= steps.length) return
    const id = window.setTimeout(() => setShown((n) => n + 1), REVEAL_MS)
    return () => window.clearTimeout(id)
  }, [result, shown, steps.length])

  const view = (i: number): StepState => (result && i < shown ? steps[i].state : 'wait')
  const done = !running && !!result && shown >= steps.length
  const failed = (result?.sites ?? []).filter((s) => !s.ok).map((s) => s.name)
  const okAll = !!result && !result.error && !!result.egress && failed.length === 0
  const linkState = (): 'run' | 'ok' | 'bad' | 'idle' =>
    done ? (okAll ? 'ok' : 'bad') : running ? 'run' : 'idle'
  const exitFlag = countryFlag(result?.egress_country || server.egress_country || '')

  return (
    <div className="modal-backdrop" onClick={dismiss}>
      <div className="card modal modal-wide cc" onClick={(e) => e.stopPropagation()}>
        <h3>{t('Проверка выхода клиентов')}</h3>

        <div className="cc-route">
          <div className="cc-node cc-node-plain">{t('Клиенты')}</div>
          <div className={`cc-link cc-link-${linkState()}`} />
          <div className="cc-node cc-node-idle">
            {countryFlag(server.country) && (
              <span className="server-flag">{countryFlag(server.country)}</span>
            )}
            <div>
              <div className="mono">{server.host}</div>
              <div className="muted small">{server.name}</div>
            </div>
          </div>
          <div className={`cc-link cc-link-${linkState()}`} />
          <div className={`cc-node cc-node-${done ? (result?.egress ? 'ok' : 'bad') : 'idle'}`}>
            {exitFlag && <span className="server-flag">{exitFlag}</span>}
            <div>
              <div className="mono">{result?.egress || server.egress_ip || '?'}</div>
              <div className="muted small">{t('выход в интернет')}</div>
            </div>
          </div>
        </div>

        <div className={`cc-progress ${done ? (okAll ? 'cc-progress-ok' : 'cc-progress-bad') : error ? 'cc-progress-bad' : ''}`}>
          <div style={{ width: `${progress}%` }} />
        </div>

        {result?.error ? (
          <p className="form-error">{t('Проверить не вышло: {err}', { err: t(result.error) })}</p>
        ) : (
          <ul className="cc-steps">
            {steps.map((s, i) => {
              const v = view(i)
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
        )}

        {done && result && !result.error && (
          <p className={okAll ? 'cc-verdict cc-verdict-ok' : 'cc-verdict cc-verdict-bad'}>
            {!result.egress
              ? t('Из VPN-контейнера интернет не открывается')
              : failed.length
                ? t('Не открывается: {list}', { list: failed.join(', ') })
                : t('Выход работает')}
            <span className="muted small">
              {' · '}
              {new Date(result.checked_at).toLocaleTimeString()}
            </span>
          </p>
        )}
        {error && !running && <p className="form-error">{t('Сервер не ответил: {err}', { err: error })}</p>}

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
