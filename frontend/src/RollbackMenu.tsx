import { useCallback, useEffect, useState } from 'react'
import {
  ApiError,
  listConfigBackups,
  restoreConfig,
  type SnapProto,
  type Snapshot,
} from './api'
import { Menu } from './Menu'
import { useI18n } from './i18n'

type Props = {
  serverId: number
  serverName: string
  proto: SnapProto
  onRestored: () => void
  onUnauthorized: () => void
}

/** 20260710-021530 -> 2026-07-10 02:15 */
function fmtSnap(id: string): string {
  const m = id.match(/^(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2})\d{2}$/)
  return m ? `${m[1]}-${m[2]}-${m[3]} ${m[4]}:${m[5]}` : id
}

/** Меню отката конфига к снимку (снимки делаются перед каждой пересборкой).
 * Ничего не рисует, если снимков нет. */
export function RollbackMenu({
  serverId,
  serverName,
  proto,
  onRestored,
  onUnauthorized,
}: Props) {
  const { t } = useI18n()
  const [snaps, setSnaps] = useState<Snapshot[]>([])

  const reload = useCallback(() => {
    listConfigBackups(serverId, proto)
      .then(setSnaps)
      .catch(() => setSnaps([]))
  }, [serverId, proto])

  useEffect(reload, [reload])

  if (snaps.length === 0) return null

  async function restore(s: Snapshot) {
    if (
      !window.confirm(
        t(
          'Откатить конфиг «{name}» к снимку от {ts} ({n} клиентов)? Текущий конфиг будет заменён.',
          { name: serverName, ts: fmtSnap(s.id), n: String(s.clients) },
        ),
      )
    )
      return
    try {
      await restoreConfig(serverId, proto, s.id)
      onRestored()
      reload()
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) onUnauthorized()
    }
  }

  return (
    <Menu
      className="ghost"
      label={t('Откатить')}
      items={snaps.map((s) => ({
        label: `${fmtSnap(s.id)} · ${t('{n} клиентов', { n: String(s.clients) })}`,
        onClick: () => restore(s),
      }))}
    />
  )
}
