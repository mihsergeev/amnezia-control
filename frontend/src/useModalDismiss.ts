import { useEffect, useRef, type MouseEvent } from 'react'

// стек открытых модалок (их onClose): Escape закрывает ВЕРХНЮЮ (последнюю),
// чтобы во вложенных окнах не закрывались сразу оба
const stack: Array<() => void> = []
// что было в фокусе до открытия каждой модалки — чтобы вернуть фокус при закрытии
const prevFocus: Array<HTMLElement | null> = []
let escBound = false

function onEsc(e: KeyboardEvent) {
  if (e.key === 'Escape' && stack.length) stack[stack.length - 1]()
}

const FOCUSABLE =
  'a[href],button:not([disabled]),input:not([disabled]),' +
  'textarea:not([disabled]),select:not([disabled]),[tabindex]:not([tabindex="-1"])'

/** Верхняя модалка в DOM (последняя .modal-backdrop = визуально верхняя). */
function topBackdrop(): HTMLElement | null {
  const all = document.querySelectorAll<HTMLElement>('.modal-backdrop')
  return all.length ? all[all.length - 1] : null
}

function focusables(el: HTMLElement): HTMLElement[] {
  return Array.from(el.querySelectorAll<HTMLElement>(FOCUSABLE)).filter(
    (n) => n.offsetWidth > 0 || n.offsetHeight > 0 || n === document.activeElement,
  )
}

// Глобальный «замок» на Tab: держим фокус внутри верхней модалки (для ЛЮБОЙ
// открытой .modal-backdrop, в т.ч. инлайновых на странице). Дёшево — ранний выход.
function onTab(e: KeyboardEvent) {
  if (e.key !== 'Tab') return
  const bd = topBackdrop()
  if (!bd) return
  const items = focusables(bd)
  if (!items.length) {
    e.preventDefault()
    return
  }
  const first = items[0]
  const last = items[items.length - 1]
  const active = document.activeElement as HTMLElement | null
  if (!active || !bd.contains(active)) {
    e.preventDefault()
    first.focus()
  } else if (e.shiftKey && active === first) {
    e.preventDefault()
    last.focus()
  } else if (!e.shiftKey && active === last) {
    e.preventDefault()
    first.focus()
  }
}

if (typeof document !== 'undefined') {
  document.addEventListener('keydown', onTab, true)
}

function push(close: () => void): () => void {
  stack.push(close)
  prevFocus.push(
    document.activeElement instanceof HTMLElement ? document.activeElement : null,
  )
  if (!escBound) {
    document.addEventListener('keydown', onEsc)
    escBound = true
  }
  // перевести фокус ВНУТРЬ только что открытой модалки
  requestAnimationFrame(() => {
    const bd = topBackdrop()
    if (bd && !bd.contains(document.activeElement)) {
      ;(focusables(bd)[0] || bd).focus()
    }
  })
  return () => {
    const i = stack.lastIndexOf(close)
    if (i >= 0) {
      stack.splice(i, 1)
      const pf = prevFocus.splice(i, 1)[0]
      requestAnimationFrame(() => pf?.focus?.())
    }
    if (!stack.length && escBound) {
      document.removeEventListener('keydown', onEsc)
      escBound = false
    }
  }
}

/** Закрытие модалки по Escape (верхнюю в стеке) + клик по фону (вне карточки),
 * плюс перевод фокуса внутрь при открытии и возврат при закрытии. Tab-замок —
 * глобальный (работает для любой .modal-backdrop). Возвращает onClick для фона. */
export function useModalDismiss(onClose: () => void) {
  const ref = useRef(onClose)
  ref.current = onClose
  useEffect(() => push(() => ref.current()), [])
  return (e: MouseEvent) => {
    if (e.target === e.currentTarget) ref.current()
  }
}
