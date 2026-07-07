import { useEffect, useRef, useState, type ReactNode } from 'react'

export type MenuItem = {
  label: string
  onClick: () => void
  danger?: boolean
  disabled?: boolean
}

type Props = {
  label: ReactNode
  items: MenuItem[]
  className?: string
  align?: 'left' | 'right'
}

/** Лёгкое выпадающее меню: закрывается по клику вне и по Escape. */
export function Menu({ label, items, className = 'ghost', align = 'right' }: Props) {
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)

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

  return (
    <div className="menu-wrap" ref={ref}>
      <button className={className} onClick={() => setOpen((v) => !v)}>
        {label} <span className="menu-caret">▾</span>
      </button>
      {open && (
        <div className={`menu-pop menu-pop-${align}`}>
          {items.map((it, i) => (
            <button
              key={i}
              className={`menu-item${it.danger ? ' menu-item-danger' : ''}`}
              disabled={it.disabled}
              onClick={() => {
                setOpen(false)
                it.onClick()
              }}
            >
              {it.label}
            </button>
          ))}
        </div>
      )}
    </div>
  )
}
