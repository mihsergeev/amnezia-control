import { useLayoutEffect, useRef, useState } from 'react'
import { useI18n } from './i18n'

type Point = { t: number; v: number }

type Props = {
  points: Point[]
  height?: number
  color?: string
  format?: (v: number) => string
  area?: boolean
  // Выделение периода мышью (как в Grafana): вызывается с [from, to] в мс
  onSelectRange?: (fromMs: number, toMs: number) => void
}

const PAD_L = 8
const PAD_R = 12
const PAD_T = 12
const PAD_B = 20

// Рисуем SVG в РЕАЛЬНЫХ пикселях (viewBox = измеренная ширина), а не растягиваем
// узкий viewBox через preserveAspectRatio="none" — иначе текст и линия
// расплющивались по горизонтали (выглядело дёшево).
export function LineChart({
  points,
  height = 160,
  color = '#3563e9',
  format = (v) => String(Math.round(v)),
  area = true,
  onSelectRange,
}: Props) {
  const { t } = useI18n()
  const ref = useRef<HTMLDivElement>(null)
  const svgRef = useRef<SVGSVGElement>(null)
  const [w, setW] = useState(0)
  const drag = useRef<{ a: number; b: number } | null>(null)
  const [sel, setSel] = useState<{ a: number; b: number } | null>(null)

  useLayoutEffect(() => {
    const el = ref.current
    if (!el) return
    const update = () => setW(el.clientWidth)
    update()
    const ro = new ResizeObserver(update)
    ro.observe(el)
    return () => ro.disconnect()
  }, [])

  if (points.length < 2) {
    return (
      <div className="chart-empty muted small">
        {t('пока недостаточно данных для графика')}
      </div>
    )
  }

  const H = height
  const W = w
  const tMin = points[0].t
  const tMax = points[points.length - 1].t
  const tSpan = Math.max(tMax - tMin, 1)
  const vMax = Math.max(...points.map((p) => p.v), 1)

  const x = (tt: number) => PAD_L + ((tt - tMin) / tSpan) * (W - PAD_L - PAD_R)
  const y = (v: number) => PAD_T + (1 - v / vMax) * (H - PAD_T - PAD_B)

  const line = points.map((p) => `${x(p.t).toFixed(1)},${y(p.v).toFixed(1)}`).join(' ')
  const areaPath =
    `${x(tMin).toFixed(1)},${(H - PAD_B).toFixed(1)} ` +
    line +
    ` ${x(tMax).toFixed(1)},${(H - PAD_B).toFixed(1)}`

  const fmtTime = (ms: number) =>
    new Date(ms).toLocaleTimeString('ru', { hour: '2-digit', minute: '2-digit' })

  const gradId = `lc-grad-${color.replace(/[^a-z0-9]/gi, '')}`
  const last = points[points.length - 1]

  // --- выделение периода мышью → callback c [from, to] в мс ---
  const plotW = Math.max(W - PAD_L - PAD_R, 1)
  const relX = (clientX: number) => {
    const r = svgRef.current?.getBoundingClientRect()
    return r ? clientX - r.left : 0
  }
  const pxToTime = (px: number) => {
    const clamped = Math.max(PAD_L, Math.min(W - PAD_R, px))
    return tMin + ((clamped - PAD_L) / plotW) * tSpan
  }
  const onDown = (e: React.PointerEvent) => {
    if (!onSelectRange) return
    const px = relX(e.clientX)
    drag.current = { a: px, b: px }
    setSel({ a: px, b: px })
    e.currentTarget.setPointerCapture(e.pointerId)
  }
  const onMove = (e: React.PointerEvent) => {
    if (!drag.current) return
    const next = { a: drag.current.a, b: relX(e.clientX) }
    drag.current = next
    setSel(next)
  }
  const onUp = () => {
    const d = drag.current
    drag.current = null
    setSel(null)
    if (!d || !onSelectRange) return
    if (Math.abs(d.b - d.a) < 6) return // слишком короткое движение — это клик
    const t0 = pxToTime(Math.min(d.a, d.b))
    const t1 = pxToTime(Math.max(d.a, d.b))
    if (t1 - t0 < 1000) return
    onSelectRange(Math.round(t0), Math.round(t1))
  }

  return (
    <div className="linechart" ref={ref} style={{ height }}>
      {W > 0 && (
        <svg ref={svgRef} width={W} height={H} viewBox={`0 0 ${W} ${H}`}>
          <defs>
            <linearGradient id={gradId} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={color} stopOpacity="0.28" />
              <stop offset="100%" stopColor={color} stopOpacity="0" />
            </linearGradient>
          </defs>
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
          {area && <polygon points={areaPath} fill={`url(#${gradId})`} />}
          <polyline
            points={line}
            fill="none"
            stroke={color}
            strokeWidth="2"
            strokeLinejoin="round"
            strokeLinecap="round"
          />
          <circle
            className="chart-dot"
            cx={x(last.t)}
            cy={y(last.v)}
            r="3.5"
            fill={color}
          />
          <text x={PAD_L} y={PAD_T} className="chart-label" dominantBaseline="hanging">
            {format(vMax)}
          </text>
          <text x={PAD_L} y={H - 5} className="chart-label">
            {fmtTime(tMin)}
          </text>
          <text x={W - PAD_R} y={H - 5} className="chart-label" textAnchor="end">
            {fmtTime(tMax)}
          </text>
          {sel && Math.abs(sel.b - sel.a) > 1 && (
            <rect
              className="chart-select-rect"
              x={Math.min(sel.a, sel.b)}
              y={PAD_T}
              width={Math.abs(sel.b - sel.a)}
              height={H - PAD_T - PAD_B}
            />
          )}
          {onSelectRange && (
            <rect
              className="chart-overlay"
              x={PAD_L}
              y={PAD_T}
              width={plotW}
              height={H - PAD_T - PAD_B}
              fill="transparent"
              onPointerDown={onDown}
              onPointerMove={onMove}
              onPointerUp={onUp}
            />
          )}
        </svg>
      )}
    </div>
  )
}
