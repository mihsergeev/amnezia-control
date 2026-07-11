/** Копирование в буфер с фолбэком для незащищённого контекста.
 *
 * `navigator.clipboard` доступен только в secure context (https или localhost).
 * Панель часто открыта по http://IP:8080 — там clipboard молча не работает.
 * Тогда падаем на execCommand('copy') через временный textarea.
 * Возвращает true при успехе. */
export async function copyText(text: string): Promise<boolean> {
  if (navigator.clipboard && window.isSecureContext) {
    try {
      await navigator.clipboard.writeText(text)
      return true
    } catch {
      /* провалимся на execCommand ниже */
    }
  }
  try {
    const ta = document.createElement('textarea')
    ta.value = text
    ta.setAttribute('readonly', '')
    ta.style.position = 'fixed'
    ta.style.top = '0'
    ta.style.left = '-9999px'
    ta.style.opacity = '0'
    document.body.appendChild(ta)
    ta.focus()
    ta.select()
    ta.setSelectionRange(0, text.length)
    const ok = document.execCommand('copy')
    document.body.removeChild(ta)
    return ok
  } catch {
    return false
  }
}
