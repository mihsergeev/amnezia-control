/** Фильтр "Обзора" по серверам: один, несколько или целая группа.
 *
 * Пустой выбор означает весь парк. Отметка одного сервера сразу сужает обзор
 * до него, следующие добавляются к выбору. Если отметить все серверы по
 * одному, выбор схлопывается обратно во "все" - иначе новый сервер, добавленный
 * потом, молча не попал бы в обзор.
 *
 * Имена показываются целиком: в реальном парке они различаются хвостом
 * (vpn-x-manager / -developer / -admin), и обрезка съедала ровно то, по
 * чему их отличают. Поэтому список широкий, в две колонки по группам, а IP ушел
 * в подсказку (искать по нему можно).
 */
import { useEffect, useMemo, useRef, useState, type CSSProperties } from 'react'
import type { Server } from './api'
import { useI18n } from './i18n'

type Props = {
  servers: Server[]
  /** выбранные id; пусто = все серверы */
  selected: number[]
  onChange: (ids: number[]) => void
}

// поиск появляется, когда серверов столько, что их уже ищут глазами
const SEARCH_FROM = 9

// ISO-код страны -> флаг (regional indicator symbols), как на странице серверов
function countryFlag(code: string): string {
  const cc = (code || '').toUpperCase()
  if (!/^[A-Z]{2}$/.test(cc)) return ''
  return String.fromCodePoint(...[...cc].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65))
}

function statusClass(s: Server): string {
  return s.last_check_ok === null ? 'dot-unknown' : s.last_check_ok ? 'dot-ok' : 'dot-fail'
}

export function ServerFilter({ servers, selected, onChange }: Props) {
  const { t } = useI18n()
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState('')
  // Геометрия списка от места на экране. На десктопе - от кнопки вправо, но не
  // дальше края. На телефоне кнопка стоит после заголовка, и привязанный к ней
  // список получал треть экрана - имена обрезались. Там он растягивается на всю
  // ширину, от края до края.
  const [popStyle, setPopStyle] = useState<CSSProperties>()
  const ref = useRef<HTMLDivElement>(null)

  function toggleOpen() {
    if (!open && ref.current) {
      const left = ref.current.getBoundingClientRect().left
      const vw = window.innerWidth
      setPopStyle(
        vw < 640
          ? { left: 12 - left, width: vw - 24, maxWidth: vw - 24 }
          : { maxWidth: Math.max(240, vw - left - 16) },
      )
    }
    setOpen((v) => !v)
  }

  useEffect(() => {
    if (!open) return
    function onDoc(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') setOpen(false)
    }
    document.addEventListener('mousedown', onDoc)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onDoc)
      document.removeEventListener('keydown', onKey)
    }
  }, [open])

  // тот же порядок, что на странице "Серверы": по ручной позиции, группа - по
  // первому своему серверу, серверы без группы в конце
  const groups = useMemo(() => {
    const sorted = [...servers].sort((a, b) => a.position - b.position || a.id - b.id)
    const map = new Map<string, Server[]>()
    for (const s of sorted) {
      const g = s.group_name || ''
      const arr = map.get(g)
      if (arr) arr.push(s)
      else map.set(g, [s])
    }
    const names = [...map.keys()].filter((n) => n !== '')
    if (map.has('')) names.push('')
    return names.map((name) => ({ name, servers: map.get(name)! }))
  }, [servers])

  const sel = new Set(selected)
  const all = selected.length === 0
  const hasGroups = groups.some((g) => g.name !== '')

  const q = query.trim().toLowerCase()
  const visible = groups
    .map((g) => ({
      ...g,
      servers: q
        ? g.servers.filter(
            (s) =>
              s.name.toLowerCase().includes(q) ||
              s.host.includes(q) ||
              g.name.toLowerCase().includes(q),
          )
        : g.servers,
    }))
    .filter((g) => g.servers.length > 0)

  function commit(next: Set<number>) {
    onChange(next.size === servers.length ? [] : [...next])
  }

  function toggle(id: number) {
    const next = new Set(selected)
    if (next.has(id)) next.delete(id)
    else next.add(id)
    commit(next)
  }

  function toggleGroup(ids: number[]) {
    const allIn = ids.every((id) => sel.has(id))
    const next = new Set(selected)
    for (const id of ids) {
      if (allIn) next.delete(id)
      else next.add(id)
    }
    commit(next)
  }

  // "только": один клик - и в обзоре ровно этот сервер или эта группа
  function only(ids: number[]) {
    commit(new Set(ids))
  }

  // подпись кнопки: имя, если сервер один; имя группы, если выбрана ровно она
  const single = selected.length === 1 ? servers.find((s) => s.id === selected[0]) : undefined
  const wholeGroup = groups.find(
    (g) =>
      g.name !== '' &&
      g.servers.length === selected.length &&
      g.servers.every((s) => sel.has(s.id)),
  )
  const label = all
    ? t('Все серверы')
    : single
      ? single.name
      : wholeGroup
        ? wholeGroup.name
        : t('Серверов: {n} из {total}', { n: selected.length, total: servers.length })

  return (
    <div className="menu-wrap srv-filter" ref={ref}>
      <button
        className={`range-tab srv-filter-btn${all ? '' : ' active'}`}
        onClick={toggleOpen}
        aria-haspopup="true"
        aria-expanded={open}
        title={t('Показать статистику только по выбранным серверам')}
      >
        <span className="srv-filter-label">{label}</span>
        <span className="menu-caret"> ▾</span>
      </button>

      {open && (
        <div className="menu-pop menu-pop-left srv-filter-pop" style={popStyle}>
          {servers.length >= SEARCH_FROM && (
            <input
              autoFocus
              className="srv-filter-search"
              placeholder={t('Найти сервер или группу')}
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
          )}

          <div className="srv-filter-summary">
            <span className="muted small">
              {all
                ? t('Показаны все серверы: {n}', { n: servers.length })
                : t('Выбрано {n} из {total}', { n: selected.length, total: servers.length })}
            </span>
            {!all && (
              <button className="linklike srv-filter-reset" onClick={() => onChange([])}>
                {t('Сбросить')}
              </button>
            )}
          </div>

          <div className="srv-filter-scroll">
            {visible.length === 0 ? (
              <p className="muted small srv-filter-empty">{t('Ничего не найдено')}</p>
            ) : (
              <div className={`srv-filter-cols${hasGroups ? '' : ' srv-filter-flat'}`}>
                {visible.map((g) => {
                  const ids = g.servers.map((s) => s.id)
                  const inCount = ids.filter((id) => sel.has(id)).length
                  return (
                    <div key={g.name || '-'} className="srv-filter-group">
                      {hasGroups && (
                        <div className="srv-filter-row srv-filter-head">
                          <label className="checkbox srv-filter-check">
                            <input
                              type="checkbox"
                              checked={inCount === ids.length}
                              ref={(el) => {
                                if (el) el.indeterminate = inCount > 0 && inCount < ids.length
                              }}
                              onChange={() => toggleGroup(ids)}
                            />
                            <span className="srv-filter-gname">{g.name || t('Без группы')}</span>
                            <span className="srv-filter-count">
                              {inCount > 0 ? `${inCount}/${ids.length}` : ids.length}
                            </span>
                          </label>
                          <button className="linklike srv-filter-only" onClick={() => only(ids)}>
                            {t('только')}
                          </button>
                        </div>
                      )}
                      {g.servers.map((s) => (
                        <div key={s.id} className="srv-filter-row" title={s.host}>
                          <label className="checkbox srv-filter-check">
                            <input
                              type="checkbox"
                              checked={sel.has(s.id)}
                              onChange={() => toggle(s.id)}
                            />
                            <span className={`dot ${statusClass(s)}`} />
                            {countryFlag(s.country) && (
                              <span className="srv-filter-flag">{countryFlag(s.country)}</span>
                            )}
                            <span className="srv-filter-name">{s.name}</span>
                          </label>
                          <button className="linklike srv-filter-only" onClick={() => only([s.id])}>
                            {t('только')}
                          </button>
                        </div>
                      ))}
                    </div>
                  )
                })}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
