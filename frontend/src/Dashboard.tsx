import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  api,
  ApiError,
  PROTOCOL_LABEL,
  type History,
  type Overview,
  type Server,
  type TopClient,
} from './api'
import { formatBytes } from './format'
import { StackedAreaChart, type Series } from './charts/StackedAreaChart'
import {
  bridgeGaps,
  DOWN_COLOR,
  formatRate,
  GRAFANA_COLORS,
  MAX_SERIES,
  REST_COLOR,
  UP_COLOR,
} from './charts/series'
import { useI18n } from './i18n'
import { ServerFilter } from './ServerFilter'

// Выбор серверов в фильтре - удобство конкретного браузера: открыл "Обзор"
// завтра, и он показывает те же серверы. Хранилище может быть недоступно
// (приватное окно, запрет сайтам) - тогда просто работаем без памяти.
const FILTER_KEY = 'acontrol_overview_servers'

function loadFilter(): number[] {
  try {
    const v: unknown = JSON.parse(localStorage.getItem(FILTER_KEY) || '[]')
    return Array.isArray(v) ? v.filter((x): x is number => Number.isInteger(x)) : []
  } catch {
    return []
  }
}

function saveFilter(ids: number[]) {
  try {
    localStorage.setItem(FILTER_KEY, JSON.stringify(ids))
  } catch {
    // без памяти фильтр все равно работает в пределах вкладки
  }
}

// Подпись протокола клиента. Версию считает бэкенд по последней проверке ноды
// (та же, что на карточке сервера); справочник - запасной вариант для старого
// бэкенда. Ключ как есть - последний рубеж: пустой плашки быть не должно, а
// раньше клиенты Legacy и 3.x выходили именно с пустой.
function protoLabel(c: TopClient): string {
  return c.protocol_label || PROTOCOL_LABEL[c.protocol] || c.protocol
}

type Sort = { key: string; dir: 'asc' | 'desc' }

// Заголовок-столбец с сортировкой: клик переключает направление
function SortTh({
  label,
  col,
  sort,
  onSort,
  numeric,
}: {
  label: string
  col: string
  sort: Sort | null
  onSort: (col: string, numeric: boolean) => void
  numeric?: boolean
}) {
  const active = sort?.key === col
  return (
    <th className="sortable" onClick={() => onSort(col, !!numeric)}>
      {label}
      <span className="sort-ind">
        {active ? (sort!.dir === 'asc' ? ' ▲' : ' ▼') : ''}
      </span>
    </th>
  )
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
  const [servers, setServers] = useState<Server[] | null>(null)
  const [picked, setPicked] = useState<number[]>(loadFilter)

  const pick = useCallback((ids: number[]) => {
    setPicked(ids)
    saveFilter(ids)
  }, [])

  // Сохраненный выбор мог пережить удаление сервера. Такие id выкидываем, иначе
  // фильтр из одних удаленных серверов показал бы пустой обзор вместо всего
  // парка. Пока список серверов не пришел, фильтр еще не применяем (null).
  //
  // Ключ - строка, а не массив, и это важно: список серверов перезапрашивается
  // при каждой загрузке и всякий раз приходит новым массивом. Массив в
  // зависимостях load менялся бы на каждом ответе, эффект снова звал бы load,
  // и "Обзор" слал бы запросы по кругу без остановки.
  const filterKey = useMemo(() => {
    if (picked.length === 0) return ''
    if (!servers) return null
    const known = new Set(servers.map((s) => s.id))
    return picked.filter((id) => known.has(id)).join(',')
  }, [picked, servers])
  const filterIds = filterKey ? filterKey.split(',').map(Number) : []

  const presetLabel = useCallback(
    // 24 ч показываем именно как «24 ч» (а не «1 дн») — это дефолтный вид и так
    // читается естественнее в ряду 3ч…12ч…24ч…7д
    (h: number) => (h <= 24 ? `${h} ${t('ч')}` : `${h / 24} ${t('дн')}`),
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
    if (filterKey === null) {
      // есть сохраненный выбор, но еще неизвестно, какие серверы живы: сначала
      // список, статистика подтянется следующим проходом с уже чистым фильтром
      try {
        setServers(await api<Server[]>('/api/servers'))
      } catch (err) {
        handleError(err)
        setLoading(false)
      }
      return
    }
    try {
      const f = filterKey
        ? filterKey.split(',').map((id) => `&server_id=${id}`).join('')
        : ''
      const [ov, hist, tc, srv] = await Promise.all([
        api<Overview>(`/api/stats/overview?${f.slice(1)}`),
        api<History>(`/api/stats/history?${q}${f}&by_server=true`),
        api<TopClient[]>(`/api/stats/top-clients?limit=10${f}`),
        // список для фильтра обновляем вместе со статистикой: сервер, добавленный
        // при открытом "Обзоре", появится в нем без перезагрузки страницы
        api<Server[]>('/api/servers'),
      ])
      setOverview(ov)
      setHistory(hist)
      setTop(tc)
      setServers(srv)
      setError(null)
    } catch (err) {
      handleError(err)
    } finally {
      setLoading(false)
    }
  }, [handleError, hours, custom, filterKey])

  useEffect(() => {
    void load()
    const id = window.setInterval(() => void load(), 30000)
    return () => window.clearInterval(id)
  }, [load])

  const zoomTo = useCallback((from: number, to: number) => {
    setCustom({ from, to })
  }, [])

  const interval = history?.interval_seconds ?? 300
  const ts = useMemo(() => history?.points.map((p) => Date.parse(p.ts)) ?? [], [history])

  // Трафик - зеркально, как "Сеть" в Kervax: скачивание вверх, отдача вниз.
  // Скорость бэкенд считает по каждому серверу на его собственном промежутке
  // между снимками. У первой точки сравнивать не с чем - там разрыв, а не
  // провал в ноль.
  const trafficSeries = useMemo<Series[]>(() => {
    const pts = history?.points ?? []
    return [
      {
        name: t('↓ скачивание'),
        color: DOWN_COLOR,
        values: pts.map((p, i) => (i === 0 ? null : p.tx_rate)),
      },
      {
        name: t('↑ отдача'),
        color: UP_COLOR,
        values: pts.map((p, i) => (i === 0 ? null : p.rx_rate)),
      },
    ]
  }, [history, t])

  // Клиенты онлайн - стеком по серверам: сумма полос равна общему числу, а по
  // цвету видно, где сидят люди. Крупные серверы снизу своими полосами, хвост
  // после MAX_SERIES сворачивается в "остальные".
  const clientSeries = useMemo<(Series & { id: number | null })[]>(() => {
    if (!history) return []
    const rows = history.servers ?? []
    if (rows.length === 0) {
      return [{
        id: null,
        name: t('клиентов онлайн'),
        color: GRAFANA_COLORS[0],
        values: history.points.map((p) => p.clients_online),
      }]
    }
    const avg = (v: (number | null)[]) =>
      v.reduce<number>((a, x) => a + (x ?? 0), 0) / Math.max(1, v.length)
    // короткие пропуски сбора склеиваем, чтобы они не прорезали весь стек
    const rowsBridged = rows.map((r) => ({ ...r, clients_online: bridgeGaps(r.clients_online) }))
    const sorted = [...rowsBridged].sort(
      (a, b) => avg(b.clients_online) - avg(a.clients_online) || a.name.localeCompare(b.name),
    )
    const keep = sorted.length > MAX_SERIES ? MAX_SERIES - 1 : sorted.length
    const out: (Series & { id: number | null })[] = sorted.slice(0, keep).map((r, i) => ({
      id: r.server_id,
      name: r.name,
      color: GRAFANA_COLORS[i % GRAFANA_COLORS.length],
      values: r.clients_online,
    }))
    const rest = sorted.slice(keep)
    if (rest.length) {
      out.push({
        id: null,
        name: t('остальные ({n})', { n: rest.length }),
        color: REST_COLOR,
        values: history.points.map((_, i) => {
          let sum = 0
          let seen = false
          for (const r of rest) {
            const v = r.clients_online[i]
            if (v != null) {
              sum += v
              seen = true
            }
          }
          return seen ? sum : null
        }),
      })
    }
    return out
  }, [history, t])

  // цвет сервера в таблице тот же, что у его полосы на графике клиентов
  const colorById = useMemo(() => {
    const m = new Map<number, string>()
    for (const sr of clientSeries) if (sr.id != null) m.set(sr.id, sr.color)
    return m
  }, [clientSeries])
  const hasSplit = (history?.servers?.length ?? 0) > 0

  // --- сортировка таблиц ---
  const [srvSort, setSrvSort] = useState<Sort | null>(null)
  const [topSort, setTopSort] = useState<Sort | null>(null)
  const makeToggle =
    (setter: (s: Sort | null) => void, cur: Sort | null) =>
    (col: string, numeric: boolean) =>
      setter(
        cur && cur.key === col
          ? { key: col, dir: cur.dir === 'asc' ? 'desc' : 'asc' }
          : { key: col, dir: numeric ? 'desc' : 'asc' }, // числа: сначала по убыв.
      )
  const cmp = <T,>(arr: T[], sort: Sort | null, val: (x: T, k: string) => number | string) => {
    if (!sort) return arr
    const m = sort.dir === 'asc' ? 1 : -1
    return [...arr].sort((a, b) => {
      const x = val(a, sort.key)
      const y = val(b, sort.key)
      if (typeof x === 'string' || typeof y === 'string') {
        return String(x).localeCompare(String(y), 'ru') * m
      }
      return (x < y ? -1 : x > y ? 1 : 0) * m
    })
  }

  const serversSorted = useMemo(
    () =>
      cmp(overview?.per_server ?? [], srvSort, (s, k) =>
        k === 'name'
          ? s.name
          : k === 'status'
            ? (s.online ? 1 : 0)
            : k === 'clients'
              ? s.clients_online
              : s.tx_total + s.rx_total,
      ),
    [overview, srvSort],
  )
  const topSorted = useMemo(
    () =>
      cmp(top, topSort, (c, k) =>
        k === 'name'
          ? c.name
          : k === 'server'
            ? c.server_name
            : k === 'proto'
              ? protoLabel(c)
              : k === 'down'
                ? c.tx
                : c.total,
      ),
    [top, topSort],
  )

  return (
    <section>
      <div className="page-head page-head-wrap">
        <div className="page-head-title">
          <h2>{t('Обзор')}</h2>
          {servers && servers.length > 1 && (
            <ServerFilter servers={servers} selected={filterIds} onChange={pick} />
          )}
        </div>
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
              <div
                className="stat-label"
                title={t(
                  'Сумма счётчиков всех нод с момента их последнего запуска (сбрасывается при рестарте контейнера) — равна сумме столбца «Трафик» ниже',
                )}
              >
                {t('суммарный трафик')} · {t('с запуска нод')}
              </div>
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
            <StackedAreaChart
              ts={ts}
              series={trafficSeries}
              mode="mirror"
              yNice="bytes"
              fmtY={(v) => formatRate(v)}
              fmtTime={fmtDT}
              height={230}
              onZoom={zoomTo}
            />
          </div>

          <div className="chart-block card">
            <div className="chart-title">
              {t('Клиентов онлайн')} · {rangeLabel}
              {hasSplit && <span className="muted small">{t('по серверам')}</span>}
            </div>
            <StackedAreaChart
              ts={ts}
              series={clientSeries}
              mode="stack"
              yNice
              fmtY={(v) => String(Math.round(v))}
              fmtTime={fmtDT}
              height={230}
              onZoom={zoomTo}
            />
          </div>

          <div className="card table-card">
            <table>
              <thead>
                <tr>
                  {(() => {
                    const onSort = makeToggle(setSrvSort, srvSort)
                    return (
                      <>
                        <SortTh label={t('Сервер')} col="name" sort={srvSort} onSort={onSort} />
                        <SortTh label={t('Статус')} col="status" sort={srvSort} onSort={onSort} numeric />
                        <SortTh label={t('Клиенты')} col="clients" sort={srvSort} onSort={onSort} numeric />
                        <SortTh label={t('Трафик (↓ / ↑)')} col="traffic" sort={srvSort} onSort={onSort} numeric />
                      </>
                    )
                  })()}
                </tr>
              </thead>
              <tbody>
                {serversSorted.map((s) => (
                  <tr key={s.id}>
                    <td>
                      <span className="srv-name-cell">
                        <span
                          className="mchart-dot"
                          style={{ background: colorById.get(s.id) ?? REST_COLOR }}
                        />
                        {s.name}
                      </span>
                    </td>
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
                    {(() => {
                      const onSort = makeToggle(setTopSort, topSort)
                      return (
                        <>
                          <SortTh label={t('Клиент')} col="name" sort={topSort} onSort={onSort} />
                          <SortTh label={t('Сервер')} col="server" sort={topSort} onSort={onSort} />
                          <SortTh label={t('Протокол')} col="proto" sort={topSort} onSort={onSort} />
                          <SortTh label={t('Трафик (↓ / ↑)')} col="down" sort={topSort} onSort={onSort} numeric />
                          <SortTh label={t('Всего')} col="total" sort={topSort} onSort={onSort} numeric />
                        </>
                      )
                    })()}
                  </tr>
                </thead>
                <tbody>
                  {topSorted.map((c) => (
                    <tr key={`${c.server_id}-${c.protocol}-${c.client_id}`}>
                      <td>
                        <span className="cname" title={c.name}>
                          {c.name}
                        </span>
                      </td>
                      <td className="muted">{c.server_name}</td>
                      <td>
                        <span className="proto-badge">
                          {protoLabel(c)}
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
