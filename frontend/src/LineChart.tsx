import { useI18n } from './i18n'

type Point = { t: number; v: number }

type Props = {
  points: Point[]
  height?: number
  color?: string
  format?: (v: number) => string
  area?: boolean
}

const W = 640
const PAD_L = 8
const PAD_R = 8
const PAD_T = 10
const PAD_B = 18

export function LineChart({
  points,
  height = 160,
  color = '#3563e9',
  format = (v) => String(Math.round(v)),
  area = true,
}: Props) {
  const { t } = useI18n()
  if (points.length < 2) {
    return <div className="chart-empty muted small">{t('пока недостаточно данных для графика')}</div>
  }

  const H = height
  const tMin = points[0].t
  const tMax = points[points.length - 1].t
  const tSpan = Math.max(tMax - tMin, 1)
  const vMax = Math.max(...points.map((p) => p.v), 1)

  const x = (t: number) => PAD_L + ((t - tMin) / tSpan) * (W - PAD_L - PAD_R)
  const y = (v: number) => PAD_T + (1 - v / vMax) * (H - PAD_T - PAD_B)

  const line = points.map((p) => `${x(p.t).toFixed(1)},${y(p.v).toFixed(1)}`).join(' ')
  const areaPath =
    `${x(points[0].t).toFixed(1)},${(H - PAD_B).toFixed(1)} ` +
    line +
    ` ${x(tMax).toFixed(1)},${(H - PAD_B).toFixed(1)}`

  const fmtTime = (ms: number) =>
    new Date(ms).toLocaleTimeString('ru', { hour: '2-digit', minute: '2-digit' })

  return (
    <svg className="linechart" viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none">
      {/* горизонтальные направляющие */}
      {[0.25, 0.5, 0.75].map((f) => (
        <line
          key={f}
          x1={PAD_L}
          x2={W - PAD_R}
          y1={PAD_T + f * (H - PAD_T - PAD_B)}
          y2={PAD_T + f * (H - PAD_T - PAD_B)}
          className="chart-grid"
        />
      ))}
      {area && <polygon points={areaPath} fill={color} fillOpacity="0.12" />}
      <polyline
        points={line}
        fill="none"
        stroke={color}
        strokeWidth="2"
        strokeLinejoin="round"
        strokeLinecap="round"
      />
      {/* подписи: макс значение и края по времени */}
      <text x={PAD_L} y={PAD_T + 2} className="chart-label" dominantBaseline="hanging">
        {format(vMax)}
      </text>
      <text x={PAD_L} y={H - 4} className="chart-label">
        {fmtTime(tMin)}
      </text>
      <text x={W - PAD_R} y={H - 4} className="chart-label" textAnchor="end">
        {fmtTime(tMax)}
      </text>
    </svg>
  )
}
