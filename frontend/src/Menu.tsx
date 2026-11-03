import { useEffect, useRef, useState, type CSSProperties, type ReactNode } from 'react'

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
  placement?: 'above' | 'below'
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
  placement = 'below',
}: Props) {
  const [open, setOpen] = useState(false)
  const [popStyle, setPopStyle] = useState<CSSProperties>()
  const ref = useRef<HTMLDivElement>(null)
  const btnRef = useRef<HTMLButtonElement>(null)

  function toggle() {
    if (!open && fixed && btnRef.current) {
      const r = btnRef.current.getBoundingClientRect()
      const right = window.innerWidth - r.right
      setPopStyle({
        position: 'fixed',
        ...(placement === 'above'
          ? {
              top: 'auto',
              bottom: window.innerHeight - r.top + 4,
              right: Math.max(8, Math.min(right, window.innerWidth - 188)),
              maxWidth: Math.min(window.innerWidth - 16, Math.max(180, r.right - 8)),
              maxHeight: Math.max(0, r.top - 12),
              overflow: 'auto',
            }
          : { top: r.bottom + 4, ...(align === 'right' ? { right } : { left: r.left }) }),
      })
    }
    setOpen((v) => !v)
  }

  useEffect(() => {
    if (!open) return
    function onDoc(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    // в фазе захвата, чтобы успеть раньше закрытия модалки по Escape
    // (useModalDismiss слушает document на всплытии): закрываем только меню
    function onKey(e: KeyboardEvent) {
      if (e.key !== 'Escape') return
      e.preventDefault()
      e.stopPropagation()
      setOpen(false)
    }
    // при скролле fixed-координаты устаревают — проще закрыть
    function onScroll() {
      setOpen(false)
    }
    document.addEventListener('mousedown', onDoc)
    document.addEventListener('keydown', onKey, true)
    function onFixedScroll(e: Event) {
      if (e.target instanceof Node && ref.current?.contains(e.target)) return
      onScroll()
    }
    if (fixed) {
      window.addEventListener('scroll', onFixedScroll, true)
      window.addEventListener('resize', onScroll)
    }
    return () => {
      document.removeEventListener('mousedown', onDoc)
      document.removeEventListener('keydown', onKey, true)
      if (fixed) {
        window.removeEventListener('scroll', onFixedScroll, true)
        window.removeEventListener('resize', onScroll)
      }
    }
  }, [open, fixed])

  return (
    <div className="menu-wrap" ref={ref}>
      <button
        ref={btnRef}
        className={className}
        title={title}
        aria-label={title}
        aria-expanded={open}
        onClick={toggle}
      >
        {label}
        {caret && <span className="menu-caret"> ▾</span>}
      </button>
      {open && (
        <div className={`menu-pop menu-pop-${align}${placement === 'above' ? ' menu-pop-above' : ''}`} style={fixed ? popStyle : undefined}>
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
