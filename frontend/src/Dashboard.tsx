import { useCallback, useEffect, useState } from 'react'
import {
  api,
  ApiError,
  type History,
  type Overview,
  type TopClient,
} from './api'
import { formatBytes } from './format'
import { LineChart } from './LineChart'
import { useI18n } from './i18n'

const PROTO_LABEL: Record<TopClient['protocol'], string> = {
  awg: 'AmneziaWG',
  openvpn: 'OpenVPN',
  xray: 'XRay',
}

type Props = {
  onUnauthorized: () => void
}

// Пресеты диапазона (в часах): от 3 часов до 90 дней
const PRESETS = [3, 6, 12, 24, 24 * 7, 24 * 30, 24 * 90]

type Custom = { from: number; to: number } | null

export function Dashboard({ onUnauthorized }: Props) {
  const { t } = useI18n()
  const [overview, setOverview] = useState<Overview | null>(null)
  const [history, setHistory] = useState<History | null>(null)
  const [top, setTop] = useState<TopClient[]>([])
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [hours, setHours] = useState(24)
  const [custom, setCustom] = useState<Custom>(null)

  const presetLabel = useCallback(
    (h: number) => (h < 24 ? `${h} ${t('ч')}` : `${h / 24} ${t('дн')}`),
    [t],
  )
  const humanInterval = useCallback(
    (sec: number) => {
      if (sec < 3600) return `${Math.round(sec / 60)} ${t('мин')}`
      if (sec < 86400) return `${Math.round(sec / 3600)} ${t('ч')}`
      return `${Math.round(sec / 86400)} ${t('дн')}`
    },
    [t],
  )
  const fmtDT = (ms: number) =>
    new Date(ms).toLocaleString('ru', {
      day: '2-digit',
      month: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
    })
  const rangeLabel = custom
    ? `${fmtDT(custom.from)} – ${fmtDT(custom.to)}`
    : presetLabel(hours)

  const handleError = useCallback(
    (err: unknown) => {
      if (err instanceof ApiError && err.status === 401) {
        onUnauthorized()
        return
      }
      setError(err instanceof Error ? err.message : t('Ошибка'))
    },
    [onUnauthorized, t],
  )

  const load = useCallback(async () => {
    const q = custom
      ? `from_ms=${custom.from}&to_ms=${custom.to}`
      : `hours=${hours}`
    try {
      const [ov, hist, tc] = await Promise.all([
        api<Overview>('/api/stats/overview'),
        api<History>(`/api/stats/history?${q}`),
        api<TopClient[]>('/api/stats/top-clients?limit=10'),
      ])
      setOverview(ov)
      setHistory(hist)
      setTop(tc)
      setError(null)
    } catch (err) {
      handleError(err)
    } finally {
      setLoading(false)
    }
  }, [handleError, hours, custom])

  useEffect(() => {
    void load()
    const id = window.setInterval(() => void load(), 30000)
    return () => window.clearInterval(id)
  }, [load])

  const zoomTo = useCallback((from: number, to: number) => {
    setCustom({ from, to })
  }, [])

  const throughputPoints =
    history?.points.map((p) => ({ t: Date.parse(p.ts), v: p.throughput })) ?? []
  const onlinePoints =
    history?.points.map((p) => ({ t: Date.parse(p.ts), v: p.clients_online })) ?? []

  const interval = history?.interval_seconds ?? 300

  return (
    <section>
      <div className="page-head">
        <h2>{t('Обзор')}</h2>
        <div className="range-tabs">
          {PRESETS.map((h) => (
            <button
              key={h}
              className={`range-tab${!custom && hours === h ? ' active' : ''}`}
              onClick={() => {
                setCustom(null)
                setHours(h)
              }}
            >
              {presetLabel(h)}
            </button>
          ))}
          {custom && (
            <button
              className="range-tab range-reset"
              onClick={() => setCustom(null)}
              title={t('Сбросить приближение')}
            >
              ✕ {t('зум')}
            </button>
          )}
          <button className="ghost" onClick={() => void load()}>
            {t('Обновить')}
          </button>
        </div>
      </div>

      {error && <p className="form-error">{error}</p>}
      {loading && !overview && <p className="muted">{t('загрузка…')}</p>}

      {overview && (
        <>
          <div className="stat-cards">
            <div className="stat-card">
              <div className="stat-value">
                {overview.servers_online}
                <span className="stat-total">/ {overview.servers_total}</span>
              </div>
              <div className="stat-label">{t('серверов онлайн')}</div>
            </div>
            <div className="stat-card">
              <div className="stat-value">
                {overview.clients_online}
                <span className="stat-total">/ {overview.clients_total}</span>
              </div>
              <div className="stat-label">{t('клиентов онлайн')}</div>
            </div>
            <div className="stat-card">
              <div className="stat-value small-value">
                ↓ {formatBytes(overview.tx_total)}
              </div>
              <div className="stat-value small-value">
                ↑ {formatBytes(overview.rx_total)}
              </div>
              <div className="stat-label">{t('суммарный трафик')}</div>
            </div>
          </div>

          <div className="chart-block card">
            <div className="chart-title">
              {t('Трафик')} · {rangeLabel}{' '}
              <span className="muted small">
                {t('интервал')} ~{humanInterval(interval)}
              </span>
              <span className="chart-hint muted small">
                {t('выделите период мышью для приближения')}
              </span>
            </div>
            <LineChart
              points={throughputPoints}
              color="#3563e9"
              format={(v) => formatBytes(v)}
              onSelectRange={zoomTo}
            />
          </div>

          <div className="chart-block card">
            <div className="chart-title">
              {t('Клиентов онлайн')} · {rangeLabel}
            </div>
            <LineChart
              points={onlinePoints}
              color="#2ecc71"
              format={(v) => String(Math.round(v))}
              onSelectRange={zoomTo}
            />
          </div>

          <div className="card table-card">
            <table>
              <thead>
                <tr>
                  <th>{t('Сервер')}</th>
                  <th>{t('Статус')}</th>
                  <th>{t('Клиенты')}</th>
                  <th>{t('Трафик (↓ / ↑)')}</th>
                </tr>
              </thead>
              <tbody>
                {overview.per_server.map((s) => (
                  <tr key={s.id}>
                    <td>{s.name}</td>
                    <td>
                      <span
                        className={`dot ${s.online ? 'dot-ok' : 'dot-unknown'}`}
                      />{' '}
                      <span className="muted small">
                        {s.online ? t('онлайн') : t('нет данных')}
                      </span>
                    </td>
                    <td className="mono">
                      {s.online ? `${s.clients_online} / ${s.clients_total}` : '—'}
                    </td>
                    <td className="mono muted">
                      {s.online
                        ? `${formatBytes(s.tx_total)} / ${formatBytes(s.rx_total)}`
                        : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {top.length > 0 && (
            <div className="card table-card">
              <div className="chart-title">{t('Топ клиентов по трафику')}</div>
              <table>
                <thead>
                  <tr>
                    <th>{t('Клиент')}</th>
                    <th>{t('Сервер')}</th>
                    <th>{t('Протокол')}</th>
                    <th>{t('Трафик (↓ / ↑)')}</th>
                    <th>{t('Всего')}</th>
                  </tr>
                </thead>
                <tbody>
                  {top.map((c) => (
                    <tr key={`${c.server_id}-${c.protocol}-${c.client_id}`}>
                      <td>
                        <span className="cname" title={c.name}>
                          {c.name}
                        </span>
                      </td>
                      <td className="muted">{c.server_name}</td>
                      <td>
                        <span className="proto-badge">
                          {PROTO_LABEL[c.protocol]}
                        </span>
                      </td>
                      <td className="mono muted">
                        ↓ {formatBytes(c.tx)} · ↑ {formatBytes(c.rx)}
                      </td>
                      <td className="mono">{formatBytes(c.total)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </section>
  )
}
