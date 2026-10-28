import { translate as t } from './i18n'

export function formatBytes(bytes: number): string {
  if (!bytes) return '0 B'
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB']
  let value = bytes
  let i = 0
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024
    i++
  }
  return `${value.toFixed(value >= 100 || i === 0 ? 0 : 1)} ${units[i]}`
}

// вызывается из компонентов при отрисовке, язык берется текущий (см. translate)
export function formatHandshake(unix: number | null): string {
  if (!unix) return t('нет')
  const seconds = Math.floor(Date.now() / 1000) - unix
  if (seconds < 0) return t('только что')
  if (seconds < 60) return t('{n} с назад', { n: seconds })
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return t('{n} мин назад', { n: minutes })
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return t('{n} ч назад', { n: hours })
  const days = Math.floor(hours / 24)
  return t('{n} дн назад', { n: days })
}

export function isOnline(unix: number | null): boolean {
  if (!unix) return false
  return Math.floor(Date.now() / 1000) - unix < 180
}

export function formatUptime(seconds: number): string {
  if (!seconds || seconds < 0) return '—'
  const d = Math.floor(seconds / 86400)
  const h = Math.floor((seconds % 86400) / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  if (d > 0) return t('{d}д {h}ч', { d, h })
  if (h > 0) return t('{h}ч {m}м', { h, m })
  return t('{m}м', { m })
}

// ISO-код страны -> эмодзи-флаг (KZ -> 🇰🇿) через regional indicator symbols
export function countryFlag(code: string): string {
  const cc = (code || '').toUpperCase()
  if (!/^[A-Z]{2}$/.test(cc)) return ''
  return String.fromCodePoint(...[...cc].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65))
}
