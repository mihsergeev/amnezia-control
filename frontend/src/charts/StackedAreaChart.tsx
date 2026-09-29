import { useRef, useState } from 'react'
import { timeTicks } from './timeAxis'

// Стек-график с заливкой (площади складываются снизу вверх) ИЛИ зеркальный (одна
// серия вверх, вторая вниз от нуля) ИЛИ overlay (каждая серия - своя площадь от нуля,
// накладываются, НЕ складываются - для независимых величин типа дисков-маунтов).
// Легенда + тултип при наведении. Свой стиль: тонкие линии, мягкие градиенты.

export type Series = { name: string; color: string; values: (number | null)[] }

type Props = {
  ts: number[] // общие метки времени
  series: Series[]
  mode?: 'stack' | 'mirror' | 'overlay'
  yMax?: number // фикс. верх (напр. 100 для %); авто если не задан
  fmtY?: (v: number) => string
  fmtV?: (v: number) => string // формат значения в тултипе
  fmtTime?: (ms: number) => string // подпись времени по оси/в тултипе
  // Круглые деления оси: "0, 200, 400", а не "0, 197, 394". 'bytes' - шаг круглый в
  // своей единице (200 КБ, 1 МБ), а не в байтах.
  yNice?: boolean | 'bytes'
  height?: number
  onZoom?: (fromMs: number, toMs: number) => void // выделение мышью -> зум по времени
  // клик по полотну (нажал-отпустил на месте) -> раскрыть график. Отдельно от onZoom:
  // протяжка остается выделением диапазона, кликом её не подменяем
  onExpand?: () => void
}

const W = 640
const PAD_L = 52
const PAD_R = 12
const PAD_T = 8
const PAD_B = 20

// Шаг оси 1-2-5 и верх, кратный шагу: четыре-восемь делений, пик не упирается в край.
// Пустой график (все по нулю) - шкала 0..1, а не "0 0 0 1 1 1", как было у 5xx; у байтов
// 0..1000 Б вместо "0 Б 0 Б 1 Б 1 Б".
function niceAxis(
  peak: number,
  bytes = false,
  divisions = 8,
): { top: number; step: number; n: number } {
  const target = peak > 0 ? peak * 1.05 : bytes ? 1000 : 1
  const raw = target / divisions
  // У байтов шаг считаем в КБ/МБ/ГБ, иначе "круглые" 500000 байт подписались бы "488 КБ".
  // Единица старшая, только когда ось доходит хотя бы до двух таких: шаг 0.5 МБ - это
  // "512 КБ, 1.0 МБ, 1.5 МБ", а 0.2 МБ дали бы "205 КБ, 410 КБ". Ниже двух мегабайт шаг в
  // килобайтах: "200 КБ ... 1000 КБ, 1.2 МБ".
  const unit = bytes ? 1024 ** Math.max(0, Math.floor(Math.log(target / 2) / Math.log(1024))) : 1
  const u = raw / unit
  const p = Math.pow(10, Math.floor(Math.log10(u)))
  const m = u / p
  let step = (m <= 1 ? 1 : m <= 2 ? 2 : m <= 5 ? 5 : 10) * p * unit
  if (bytes) step = Math.max(1, step) // дробных байтов не бывает
  const n = Math.max(1, Math.ceil(target / step - 1e-9))
  return { top: n * step, step, n }
}

export function StackedAreaChart({
  ts,
  series,
  mode = 'stack',
  yMax: yMaxFix,
  fmtY,
  fmtV,
  fmtTime: fmtTimeProp,
  yNice = false,
  height = 150,
  onZoom,
  onExpand,
}: Props) {
  const H = height
  const ref = useRef<SVGSVGElement>(null)
  const [hi, setHi] = useState<number | null>(null)
  const [drag, setDrag] = useState<{ a: number; b: number } | null>(null)
  const pressRef = useRef<{ x: number; y: number } | null>(null)
  const n = ts.length
  if (n === 0) return <div className="chart-empty">—</div>

  const tMin = ts[0]
  const tMax = ts[n - 1]
  const plotW = W - PAD_L - PAD_R
  const plotH = H - PAD_T - PAD_B
  const sx = (i: number) =>
    n === 1 ? PAD_L + plotW / 2 : PAD_L + (i / (n - 1)) * plotW

  // верхняя граница
  const peak =
    mode === 'stack'
      ? Math.max(0, ...ts.map((_, i) => series.reduce((a, s) => a + (s.values[i] ?? 0), 0)))
      : Math.max(0, ...series.flatMap((s) => s.values.map((v) => Math.abs(v ?? 0))))
  // Сетка частая, как в Grafana: по ней читают значение, не наводя курсор. На шкале
  // процентов - деление на каждые 10%, на остальных пять делений или круглый шаг.
  let gridN = mode === 'mirror' ? 2 : yMaxFix === 100 ? 10 : 5
  let top: number
  let step = 0
  if (yMaxFix != null) top = yMaxFix
  else if (yNice) {
    // У зеркального графика две полуоси, и на каждую нужно вдвое меньше
    // делений: иначе на той же высоте подписи слипаются.
    const ax = niceAxis(peak, yNice === 'bytes', mode === 'mirror' ? 4 : 8)
    top = ax.top
    step = ax.step
    gridN = ax.n
  } else top = Math.max(1, peak) * (mode === 'mirror' ? 1.15 : 1.12)
  const zeroY = mode === 'mirror' ? PAD_T + plotH / 2 : PAD_T + plotH
  const scaleH = mode === 'mirror' ? plotH / 2 : plotH
  const sy = (v: number) => zeroY - (v / top) * scaleH

  // построение площадей; путь линии - отдельно: заливка идет без обводки, а линия
  // рисуется поверх всех заливок, иначе у стека верхний слой перекрывает нижние
  const areas: { s: Series; d: string; line: string; sign: number }[] = []
  const cum = new Array(n).fill(0) // для стека
  series.forEach((s, si) => {
    const sign = mode === 'mirror' && si === 1 ? -1 : 1
    // Пропуск в ряду (null) - "данных нет", и рисуется он разрывом. Раньше пропуск
    // подставлялся нулем: у ноды, которая молчала, или у выделенного мышью участка,
    // дотянутого до края окна, все линии отвесно падали в пол и шли по нулю -
    // график показывал простой процессора там, где просто не было замеров.
    const areaParts: string[] = []
    const lineParts: string[] = []
    let upper: string[] = []
    let lower: string[] = []
    const flush = () => {
      if (upper.length) {
        areaParts.push(`${upper.join(' ')} ${lower.reverse().join(' ')} Z`)
        lineParts.push(upper.join(' '))
      }
      upper = []
      lower = []
    }
    for (let i = 0; i < n; i++) {
      const raw = s.values[i]
      if (raw == null) {
        flush()
        continue
      }
      const base = mode === 'stack' ? cum[i] : 0
      const y0 = sy(base * sign)
      const y1 = sy((base + raw) * sign)
      upper.push(`${upper.length ? 'L' : 'M'}${sx(i).toFixed(1)} ${y1.toFixed(1)}`)
      lower.push(`L${sx(i).toFixed(1)} ${y0.toFixed(1)}`)
      if (mode === 'stack') cum[i] += raw
    }
    flush()
    areas.push({ s, d: areaParts.join(' '), line: lineParts.join(' '), sign })
  })

  // У независимых рядов с плотной заливкой порядок рисования решает все: нарисуй
  // крупный ряд последним - и он закроет мелкие целиком. Крупные - позади, по
  // среднему значению; легенда и подсказка при этом остаются в исходном порядке.
  const avg = (vals: (number | null)[]) =>
    vals.reduce<number>((a, v) => a + Math.abs(v ?? 0), 0) / Math.max(1, vals.length)
  const drawOrder =
    mode === 'overlay' ? [...areas].sort((a, b) => avg(b.s.values) - avg(a.s.values)) : areas
  const grid =
    mode === 'mirror'
      ? // круглые деления на обе стороны от нуля, как у обычной шкалы
        Array.from({ length: 2 * gridN + 1 }, (_, i) => {
          const v = -top + (top * i) / gridN
          return { v, y: sy(v) }
        })
      : Array.from({ length: gridN + 1 }, (_, i) => {
          const v = (top * i) / gridN
          return { v, y: sy(v) }
        })
  // Метки времени по оси X: раньше их было ровно две - по краям, и "когда был
  // этот пик" приходилось выяснивать курсором. Ставим 5-6 круглых моментов.
  const xt = timeTicks(tMin, tMax).map((tk) => ({
    ...tk,
    // ts может быть неравномерным (пропуски метрик), поэтому позицию считаем
    // по ВРЕМЕНИ, а не по индексу точки
    x: PAD_L + ((tk.t - tMin) / Math.max(1, tMax - tMin)) * plotW,
  }))
  const fmt = fmtY ?? ((v: number) => Math.round(v).toString())
  const fmtVal = fmtV ?? fmt
  // Шаг мельче единицы, а формат округляет до целых - подписи слиплись бы в "0 0 1 1".
  // Тогда подписываем столькими знаками, сколько нужно шагу.
  let fmtTick = fmt
  if (step > 0) {
    // у зеркала подписи парные (+5 и -5 выглядят одинаково) - повтор ищем
    // только на одной полуоси, иначе он находился бы всегда
    const labels = grid.filter((g) => g.v >= 0).map((g) => fmt(g.v))
    if (new Set(labels).size < labels.length) {
      const dec = Math.max(0, Math.ceil(-Math.log10(step) - 1e-9))
      fmtTick = (v: number) => v.toFixed(dec)
    }
  }

  // Заливка плотная у всех графиков, как у состава процессора: цвет несет смысл, и
  // бледная заливка читается выцветшей. Исключение одно - много независимых рядов
  // (ядра, интерфейсы): там плотные площади закрыли бы друг друга целиком, поэтому
  // заливка легче, а крупные ряды рисуются позади мелких (см. drawOrder).
  const crowded = mode === 'overlay' && series.length > 3
  const [fillTop, fillBot] = crowded ? [0.55, 0.22] : [0.78, 0.6]
  // id градиента уникален по (режим+цвет) - иначе один цвет в overlay и стеке
  // на одной странице делит defs и заливка "перетекает" между графиками
  const gid = (c: string) => `sac-${mode}-${c.replace('#', '')}`

  const clientToVx = (clientX: number) => {
    const el = ref.current
    if (!el) return PAD_L
    const rect = el.getBoundingClientRect()
    return ((clientX - rect.left) / rect.width) * W
  }
  const vxToTime = (vx: number) => {
    const frac = Math.max(0, Math.min(1, (vx - PAD_L) / plotW))
    const fi = frac * (n - 1)
    const i0 = Math.floor(fi)
    const i1 = Math.min(n - 1, i0 + 1)
    return ts[i0] + (ts[i1] - ts[i0]) * (fi - i0)
  }

  function onMove(e: React.MouseEvent) {
    const vx = clientToVx(e.clientX)
    const frac = (vx - PAD_L) / plotW
    setHi(Math.max(0, Math.min(n - 1, Math.round(frac * (n - 1)))))
    if (drag) setDrag({ a: drag.a, b: vx })
  }
  function onDown(e: React.MouseEvent) {
    // точку нажатия помним ВСЕГДА, даже когда зум диапазоном не подключен:
    // по ней отличаем клик (раскрыть) от протяжки (выделить интервал)
    pressRef.current = { x: e.clientX, y: e.clientY }
    if (!onZoom || n < 2) return
    const vx = clientToVx(e.clientX)
    setDrag({ a: vx, b: vx })
  }
  function onUp(e: React.MouseEvent) {
    let zoomed = false
    if (drag && onZoom) {
      const x0 = Math.min(drag.a, drag.b)
      const x1 = Math.max(drag.a, drag.b)
      if (x1 - x0 > 6) {
        onZoom(vxToTime(x0), vxToTime(x1)) // порог: клик не зумит
        zoomed = true
      }
    }
    setDrag(null)
    const p = pressRef.current
    pressRef.current = null
    // мышь не уехала -> это клик, а не выделение
    if (!zoomed && onExpand && p &&
        Math.abs(e.clientX - p.x) < 5 && Math.abs(e.clientY - p.y) < 5) {
      onExpand()
    }
  }

  const fmtTime =
    fmtTimeProp ??
    ((t: number) =>
      new Date(t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }))
  const tipLeftPct = hi != null ? ((sx(hi) / W) * 100) : 0
  const tipRight = tipLeftPct > 60

  return (
    <div className="sac">
      <div className="mchart-legend">
        {series.map((s) => (
          <span key={s.name} className="mchart-leg">
            <span className="mchart-dot" style={{ background: s.color }} />
            {s.name}
            {hi != null && (
              <b className="sac-legval">{s.values[hi] == null ? '—' : fmtVal(Math.abs(s.values[hi] as number))}</b>
            )}
          </span>
        ))}
      </div>
      <div className="sac-wrap">
        <svg
          ref={ref}
          className={`line-chart${onZoom ? ' sac-zoomable' : ''}${onExpand ? ' sac-expandable' : ''}`}
          viewBox={`0 0 ${W} ${H}`}
          style={{ height: H }}
          preserveAspectRatio="none"
          role="img"
          onMouseMove={onMove}
          onMouseDown={onDown}
          onMouseUp={onUp}
          onMouseLeave={() => {
            setHi(null)
            setDrag(null)
          }}
        >
          <defs>
            {series.map((s) => (
              <linearGradient key={s.name} id={gid(s.color)} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={s.color} stopOpacity={fillTop} />
                {/* средняя остановка: заливка ярче у кромки и уходит в глубину,
                    а не гаснет ровной пленкой */}
                <stop offset="55%" stopColor={s.color} stopOpacity={fillTop * 0.34} />
                <stop offset="100%" stopColor={s.color} stopOpacity={fillBot} />
              </linearGradient>
            ))}
          </defs>
          {grid.map((g, i) => (
            <line key={i} x1={PAD_L} y1={g.y} x2={W - PAD_R} y2={g.y} className="chart-grid" />
          ))}
          {drawOrder.map(({ s, d }) => (
            <path key={`a-${s.name}`} d={d} fill={`url(#${gid(s.color)})`} stroke="none" />
          ))}
          {areas.map(({ s, line }) => (
            <path
              key={`l-${s.name}`}
              d={line}
              fill="none"
              stroke={s.color}
              strokeWidth={1.6}
              strokeLinejoin="round"
              strokeLinecap="round"
              vectorEffect="non-scaling-stroke"
            />
          ))}
          {xt.map((tk) => (
            <line
              key={`x${tk.t}`}
              x1={tk.x}
              y1={PAD_T}
              x2={tk.x}
              y2={PAD_T + plotH}
              className="sac-xgrid"
              vectorEffect="non-scaling-stroke"
            />
          ))}
          {drag && Math.abs(drag.b - drag.a) > 1 && (
            <rect
              x={Math.min(drag.a, drag.b)}
              y={PAD_T}
              width={Math.abs(drag.b - drag.a)}
              height={plotH}
              className="sac-brush"
            />
          )}
          {hi != null && !drag && (
            <line
              x1={sx(hi)}
              y1={PAD_T}
              x2={sx(hi)}
              y2={PAD_T + plotH}
              className="sac-cursor"
              vectorEffect="non-scaling-stroke"
            />
          )}
        </svg>
        {/* подписи осей - HTML, чтобы не растягивались вместе с SVG (preserveAspectRatio=none) */}
        {grid.map((g, i) => (
          <span
            key={i}
            className="sac-ylabel"
            style={{ top: `${(g.y / H) * 100}%`, width: `${(PAD_L / W) * 100}%` }}
          >
            {fmtTick(Math.abs(g.v))}
          </span>
        ))}
        {xt.map((tk) => (
          <span key={tk.t} className="sac-xtick" style={{ left: `${(tk.x / W) * 100}%` }}>
            {tk.label}
          </span>
        ))}
        {hi != null && (
          <div
            className="sac-tip"
            style={tipRight ? { right: `${100 - tipLeftPct}%` } : { left: `${tipLeftPct}%` }}
          >
            <div className="sac-tip-t">{fmtTime(ts[hi])}</div>
            {series.map((s) => (
              <div key={s.name} className="sac-tip-row">
                <span className="mchart-dot" style={{ background: s.color }} />
                <span className="sac-tip-name">{s.name}</span>
                <span className="sac-tip-val">{s.values[hi] == null ? '—' : fmtVal(Math.abs(s.values[hi] as number))}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
