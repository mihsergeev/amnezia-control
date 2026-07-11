import { useEffect, useRef, useState, type ReactNode } from 'react'

export type MenuItem = {
  label?: string
  onClick?: () => void
  danger?: boolean
  disabled?: boolean
  divider?: boolean
}

type Props = {
  label: ReactNode
  items: MenuItem[]
  className?: string
  align?: 'left' | 'right'
  caret?: boolean
  title?: string
  /** позиционировать всплывашку через position:fixed по координатам кнопки —
   * нужно внутри скролл-контейнеров (таблица клиентов), иначе overflow её режет */
  fixed?: boolean
}

/** Лёгкое выпадающее меню: закрывается по клику вне, Escape и скролле. */
export function Menu({
  label,
  items,
  className = 'ghost',
  align = 'right',
  caret = true,
  title,
  fixed = false,
}: Props) {
  const [open, setOpen] = useState(false)
  const [coords, setCoords] = useState<{ top: number; right: number; left: number } | null>(
    null,
  )
  const ref = useRef<HTMLDivElement>(null)
  const btnRef = useRef<HTMLButtonElement>(null)

  function toggle() {
    if (!open && fixed && btnRef.current) {
      const r = btnRef.current.getBoundingClientRect()
      setCoords({
        top: r.bottom + 4,
        right: window.innerWidth - r.right,
        left: r.left,
      })
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
    // при скролле fixed-координаты устаревают — проще закрыть
    function onScroll() {
      setOpen(false)
    }
    document.addEventListener('mousedown', onDoc)
    document.addEventListener('keydown', onKey)
    if (fixed) window.addEventListener('scroll', onScroll, true)
    return () => {
      document.removeEventListener('mousedown', onDoc)
      document.removeEventListener('keydown', onKey)
      if (fixed) window.removeEventListener('scroll', onScroll, true)
    }
  }, [open, fixed])

  const popStyle =
    fixed && coords
      ? ({
          position: 'fixed',
          top: coords.top,
          ...(align === 'right' ? { right: coords.right } : { left: coords.left }),
        } as const)
      : undefined

  return (
    <div className="menu-wrap" ref={ref}>
      <button
        ref={btnRef}
        className={className}
        title={title}
        aria-label={title}
        onClick={toggle}
      >
        {label}
        {caret && <span className="menu-caret"> ▾</span>}
      </button>
      {open && (
        <div className={`menu-pop menu-pop-${align}`} style={popStyle}>
          {items.map((it, i) =>
            it.divider ? (
              <div key={i} className="menu-divider" role="separator" />
            ) : (
              <button
                key={i}
                className={`menu-item${it.danger ? ' menu-item-danger' : ''}`}
                disabled={it.disabled}
                onClick={() => {
                  setOpen(false)
                  it.onClick?.()
                }}
              >
                {it.label}
              </button>
            ),
          )}
        </div>
      )}
    </div>
  )
}
