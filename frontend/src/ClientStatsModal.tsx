import { useEffect, useMemo, useState } from 'react'
import { ApiError, clientHistory, type ClientHistory } from './api'
import { StackedAreaChart, type Series } from './charts/StackedAreaChart'
import { deltasFromTotals, DOWN_COLOR, formatRate, toRate, UP_COLOR } from './charts/series'
import { formatBytes } from './format'
import { useI18n } from './i18n'
import { useModalDismiss } from './useModalDismiss'

type Props = {
  serverId: number
  protocol: 'awg' | 'awg3' | 'awglegacy' | 'openvpn' | 'xray'
  clientId: string
  name: string
  onClose: () => void
  onUnauthorized: () => void
}

// label переводится через t() при отрисовке
const RANGES = [
  { hours: 24, label: '24ч' },
  { hours: 24 * 7, label: '7д' },
  { hours: 24 * 14, label: '14д' },
] as const

export function ClientStatsModal({
  serverId,
  protocol,
  clientId,
  name,
  onClose,
  onUnauthorized,
}: Props) {
  const { t, lang } = useI18n()
  const dismiss = useModalDismiss(onClose)
  const [hours, setHours] = useState(24)
  const [data, setData] = useState<ClientHistory | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    setLoading(true)
    setError(null)
    clientHistory(serverId, protocol, clientId, hours)
      .then(setData)
      .catch((err) => {
        if (err instanceof ApiError && err.status === 401) onUnauthorized()
        else setError(err instanceof Error ? err.message : t('Ошибка'))
      })
      .finally(() => setLoading(false))
  }, [serverId, protocol, clientId, hours, onUnauthorized, t])

  const ts = useMemo(() => data?.points.map((p) => Date.parse(p.ts)) ?? [], [data])
  // тот же вид, что у трафика на "Обзоре": скачивание вверх, отдача вниз
  const series = useMemo<Series[]>(() => {
    const pts = data?.points ?? []
    return [
      {
        name: t('↓ скачивание'),
        color: DOWN_COLOR,
        values: toRate(deltasFromTotals(pts.map((p) => p.tx_total)), ts),
      },
      {
        name: t('↑ отдача'),
        color: UP_COLOR,
        values: toRate(deltasFromTotals(pts.map((p) => p.rx_total)), ts),
      },
    ]
  }, [data, ts, t])
  const fmtDT = (ms: number) =>
    new Date(ms).toLocaleString(lang === 'en' ? 'en-GB' : 'ru-RU', {
      day: '2-digit',
      month: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
    })

  return (
    <div className="modal-backdrop" onClick={dismiss}>
      <div className="card modal modal-wide" onClick={(e) => e.stopPropagation()}>
        <div className="clients-head">
          <h3>{t('Трафик клиента «{name}»', { name })}</h3>
          <button className="ghost" onClick={onClose}>
            {t('Закрыть')}
          </button>
        </div>

        <div className="tabs">
          {RANGES.map((r) => (
            <button
              key={r.hours}
              className={hours === r.hours ? 'tab tab-active' : 'tab'}
              onClick={() => setHours(r.hours)}
            >
              {t(r.label)}
            </button>
          ))}
        </div>

        {data && (
          <div className="stat-totals muted small">
            {t('Накоплено с последнего перевыпуска:')}{' '}
            <b>↓ {formatBytes(data.current_tx)}</b> ·{' '}
            <b>↑ {formatBytes(data.current_rx)}</b>
          </div>
        )}

        {error && <p className="form-error">{error}</p>}

        {loading ? (
          <p className="muted">{t('загрузка…')}</p>
        ) : error ? null : (
          <>
            <p className="muted small">{t('Скорость, наведите курсор, чтобы увидеть значения')}</p>
            <StackedAreaChart
              ts={ts}
              series={series}
              mode="mirror"
              yNice="bytes"
              fmtY={(v) => formatRate(v)}
              fmtTime={fmtDT}
              height={220}
            />
            {ts.length < 2 && (
              <p className="muted small">
                {t('Данные копятся со сбором метрик — загляните позже.')}
              </p>
            )}
          </>
        )}
      </div>
    </div>
  )
}
