import { useEffect, useState } from 'react'
import { getTorrent, type Server, type TorrentClient, type TorrentInfo } from './api'
import { useI18n } from './i18n'

export function TorrentBadge({ hit }: { hit?: TorrentClient }) {
  const { t } = useI18n()
  if (!hit) return null
  return (
    <span
      className="torrent-badge"
      title={t('Торренты ловили {n} раз, последний раз {at}', {
        n: hit.hits,
        at: new Date(hit.last_seen).toLocaleString(),
      })}
    >
      {t('торрент')}
    </span>
  )
}

const DAY_MS = 24 * 3600 * 1000

// строка на карточке сервера: блокировка включена, встали ли правила, кто
// попадался за сутки
export function TorrentLine({ server }: { server: Server }) {
  const { t } = useI18n()
  const [info, setInfo] = useState<TorrentInfo | null>(null)
  useEffect(() => {
    let alive = true
    setInfo(null)
    getTorrent(server.id)
      .then((r) => {
        if (alive) setInfo(r)
      })
      .catch(() => {})
    return () => {
      alive = false
    }
  }, [server.id, server.torrent_block, server.updated_at])

  const now = Date.now()
  const recent = (info?.clients ?? []).filter(
    (c) => now - new Date(c.last_seen).getTime() < DAY_MS,
  )
  const names = recent.slice(0, 3).map((c) => c.name || c.client_id.slice(0, 8))
  return (
    <div className="small srv-torrent">
      <span className="muted">
        {server.torrent_autopause
          ? t('Торренты блокируются, кто качает - на паузу')
          : t('Торренты блокируются')}
      </span>
      {info?.active === false && (
        <div className="err-text">
          {t('Правила на сервере не встали: {err}', { err: info.error || t('ошибка') })}
        </div>
      )}
      {recent.length > 0 && (
        <div>
          {t('За сутки качали: {names}', {
            names:
              names.join(', ') +
              (recent.length > names.length
                ? ' ' + t('и еще {n}', { n: recent.length - names.length })
                : ''),
          })}
        </div>
      )}
    </div>
  )
}
