import { useEffect, useState } from 'react'
import { api, ApiError, type NodeHistory, type Server } from './api'
import { StackedAreaChart } from './charts/StackedAreaChart'
import { GRAFANA_COLORS } from './charts/series'
import { useI18n } from './i18n'

type Props = {
  servers: Server[]
  query: string
  fmtTime: (time: number) => string
  onZoom: (from: number, to: number) => void
  onUnauthorized: () => void
}

export function NodeHistoryCharts({ servers, query, fmtTime, onZoom, onUnauthorized }: Props) {
  const { t } = useI18n()
  const [selected, setSelected] = useState<number | null>(null)
  const server = servers.find((s) => s.id === selected) ?? servers[0]
  const path = server ? `/api/stats/node-history?${query}&server_id=${server.id}` : ''
  const [response, setResponse] = useState<{ path: string; data?: NodeHistory; failed?: boolean }>()

  useEffect(() => {
    if (!path) return
    let inFlight: AbortController | undefined
    async function load() {
      if (inFlight) return
      const request = new AbortController()
      inFlight = request
      try {
        const data = await api<NodeHistory>(path, { signal: request.signal })
        if (!request.signal.aborted) setResponse({ path, data })
      } catch (err) {
        if (request.signal.aborted) return
        if (err instanceof ApiError && err.status === 401) onUnauthorized()
        else setResponse({ path, failed: true })
      } finally {
        inFlight = undefined
      }
    }
    void load()
    const timer = window.setInterval(() => void load(), 30000)
    return () => {
      window.clearInterval(timer)
      inFlight?.abort()
    }
  }, [path, onUnauthorized])

  if (!server) return null
  const current = response?.path === path ? response : undefined
  const points = current?.data?.servers[0]?.points ?? []
  const at = new Map(points.map((p) => [Date.parse(p.ts), p]))
  const ts: number[] = []
  const step = (current?.data?.interval_seconds ?? 300) * 1000
  if (points.length && step > 0) {
    const first = Date.parse(points[0].ts)
    const last = Date.parse(points[points.length - 1].ts)
    for (let time = first; time <= last; time += step) ts.push(time)
  }
  return (
    <div className="chart-block card">
      <div className="chart-title">
        {t('История нагрузки')}
        <select
          aria-label={t('Сервер для графика нагрузки')}
          value={server.id}
          onChange={(e) => setSelected(Number(e.target.value))}
        >
          {servers.map((row) => <option key={row.id} value={row.id}>{row.name}</option>)}
        </select>
      </div>
      {!current ? <p className="muted">{t('загрузка…')}</p> :
        current.failed ? <p className="form-error">{t('Не удалось загрузить историю нагрузки')}</p> :
        ts.length ? <>
          <StackedAreaChart
            ts={ts}
            series={[
              { name: 'CPU', color: GRAFANA_COLORS[0], values: ts.map((time) => at.get(time)?.cpu_pct ?? null) },
              { name: t('Память'), color: GRAFANA_COLORS[1], values: ts.map((time) => at.get(time)?.mem_pct ?? null) },
            ]}
            mode="overlay"
            yMax={100}
            fmtY={(v) => `${Math.round(v)}%`}
            fmtTime={fmtTime}
            onZoom={onZoom}
          />
          <StackedAreaChart
            ts={ts}
            series={[
              { name: t('Load average за 1 мин'), color: GRAFANA_COLORS[2], values: ts.map((time) => at.get(time)?.load1 ?? null) },
            ]}
            yNice
            fmtY={(v) => Number(v.toFixed(2)).toString()}
            fmtTime={fmtTime}
            onZoom={onZoom}
          />
        </> : <p className="muted">{t('За этот период нет замеров нагрузки')}</p>}
    </div>
  )
}
