/** Фильтр "Обзора" по серверам: один, несколько или целая группа.
 *
 * Пустой выбор означает весь парк. Отметка одного сервера сразу сужает обзор
 * до него, следующие добавляются к выбору. Если отметить все серверы по
 * одному, выбор схлопывается обратно во "все" - иначе новый сервер, добавленный
 * потом, молча не попал бы в обзор.
 */
import { useEffect, useMemo, useRef, useState } from 'react'
import type { Server } from './api'
import { useI18n } from './i18n'

type Props = {
  servers: Server[]
  /** выбранные id; пусто = все серверы */
  selected: number[]
  onChange: (ids: number[]) => void
}

// список поиска появляется, только когда серверов столько, что их уже ищут глазами
const SEARCH_FROM = 9

export function ServerFilter({ servers, selected, onChange }: Props) {
  const { t } = useI18n()
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState('')
  // ширина списка не больше места справа от кнопки: на узком телефоне кнопка
  // стоит после заголовка, и список фиксированной ширины уезжал за край экрана
  const [maxWidth, setMaxWidth] = useState<number>()
  const ref = useRef<HTMLDivElement>(null)

  function toggleOpen() {
    if (!open && ref.current) {
      const left = ref.current.getBoundingClientRect().left
      setMaxWidth(Math.max(220, window.innerWidth - left - 16))
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
            (s) => s.name.toLowerCase().includes(q) || s.host.includes(q),
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
        <div className="menu-pop menu-pop-left srv-filter-pop" style={{ maxWidth }}>
          {servers.length >= SEARCH_FROM && (
            <input
              autoFocus
              className="srv-filter-search"
              placeholder={t('Найти сервер')}
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
          )}

          <label className="checkbox srv-filter-row srv-filter-all">
            <input type="checkbox" checked={all} onChange={() => onChange([])} />
            <span>{t('Все серверы')}</span>
          </label>
          <div className="menu-divider" role="separator" />

          <div className="srv-filter-list">
            {visible.length === 0 && (
              <p className="muted small srv-filter-empty">{t('Ничего не найдено')}</p>
            )}
            {visible.map((g) => {
              const ids = g.servers.map((s) => s.id)
              const inCount = ids.filter((id) => sel.has(id)).length
              return (
                <div key={g.name || '-'} className="srv-filter-group">
                  {hasGroups && (
                    <label className="checkbox srv-filter-row srv-filter-head">
                      <input
                        type="checkbox"
                        checked={inCount === ids.length}
                        ref={(el) => {
                          if (el) el.indeterminate = inCount > 0 && inCount < ids.length
                        }}
                        onChange={() => toggleGroup(ids)}
                      />
                      <span>{g.name || t('Без группы')}</span>
                    </label>
                  )}
                  {g.servers.map((s) => (
                    <label
                      key={s.id}
                      className={`checkbox srv-filter-row${hasGroups ? ' srv-filter-nested' : ''}`}
                    >
                      <input
                        type="checkbox"
                        checked={sel.has(s.id)}
                        onChange={() => toggle(s.id)}
                      />
                      <span className="srv-filter-name">{s.name}</span>
                      <span className="srv-filter-host mono">{s.host}</span>
                    </label>
                  ))}
                </div>
              )
            })}
          </div>
        </div>
      )}
    </div>
  )
}
