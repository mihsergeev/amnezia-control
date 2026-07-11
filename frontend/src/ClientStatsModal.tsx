import { useEffect, useState } from 'react'
import { clientHistory, type ClientHistory } from './api'
import { LineChart } from './LineChart'
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

  const points =
    data?.points.map((p) => ({ t: Date.parse(p.ts), v: p.throughput })) ?? []

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
            <p className="muted small">{t('Скорость (трафик за интервал сбора)')}</p>
            <LineChart
              points={points}
              format={(v) => formatBytes(v)}
              color="#3563e9"
            />
            {points.length < 2 && (
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
