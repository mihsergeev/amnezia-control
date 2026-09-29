import { useEffect, useMemo, useState } from 'react'
import { clientHistory, type ClientHistory } from './api'
import { StackedAreaChart, type Series } from './charts/StackedAreaChart'
import { deltasFromTotals, DOWN_COLOR, formatRate, toRate, UP_COLOR } from './charts/series'
import { formatBytes } from './format'
import { useI18n } from './i18n'
import { useModalDismiss } from './useModalDismiss'

type Props = {
  serverId: number
  protocol: 'awg' | 'openvpn' | 'xray'
  clientId: string
  name: string
  onClose: () => void
  onUnauthorized: () => void
}

const RANGES = [
  { hours: 24, label: '24ч' },
  { hours: 24 * 7, label: '7д' },
  { hours: 24 * 14, label: '14д' },
]

export function ClientStatsModal({
  serverId,
  protocol,
  clientId,
  name,
  onClose,
  onUnauthorized,
}: Props) {
  const { t } = useI18n()
  const dismiss = useModalDismiss(onClose)
  const [hours, setHours] = useState(24)
  const [data, setData] = useState<ClientHistory | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    setLoading(true)
    clientHistory(serverId, protocol, clientId, hours)
      .then(setData)
      .catch(() => onUnauthorized())
      .finally(() => setLoading(false))
  }, [serverId, protocol, clientId, hours, onUnauthorized])

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
    new Date(ms).toLocaleString('ru', {
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
              {r.label}
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

        {loading ? (
          <p className="muted">{t('загрузка…')}</p>
        ) : (
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
