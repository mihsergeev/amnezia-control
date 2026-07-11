import { useEffect, useRef, type MouseEvent } from 'react'

// стек открытых модалок: Escape закрывает ВЕРХНЮЮ (последнюю открытую),
// чтобы во вложенных окнах не закрывались сразу оба
const stack: Array<() => void> = []
let bound = false

function onKey(e: KeyboardEvent) {
  if (e.key === 'Escape' && stack.length) stack[stack.length - 1]()
}

function push(close: () => void): () => void {
  stack.push(close)
  if (!bound) {
    document.addEventListener('keydown', onKey)
    bound = true
  }
  return () => {
    const i = stack.lastIndexOf(close)
    if (i >= 0) stack.splice(i, 1)
  }
}

/** Закрытие модалки по Escape (верхнюю в стеке) и по клику на фон (вне карточки).
 * Возвращает onClick-хендлер, который вешается на элемент .modal-backdrop. */
export function useModalDismiss(onClose: () => void) {
  const ref = useRef(onClose)
  ref.current = onClose
  // пушим стабильную обёртку один раз на маунт (порядок стека = порядок открытия)
  useEffect(() => push(() => ref.current()), [])
  return (e: MouseEvent) => {
    if (e.target === e.currentTarget) ref.current()
  }
}
