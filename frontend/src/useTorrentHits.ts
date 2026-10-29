import { useEffect, useState } from 'react'
import { getTorrent, type TorrentClient } from './api'

// клиенты сервера, у которых ловили торренты: ключ `${протокол}:${id клиента}`
export function useTorrentHits(serverId: number): Map<string, TorrentClient> {
  const [hits, setHits] = useState<Map<string, TorrentClient>>(new Map())
  useEffect(() => {
    let alive = true
    getTorrent(serverId)
      .then((info) => {
        if (alive) setHits(new Map(info.clients.map((c) => [`${c.protocol}:${c.client_id}`, c])))
      })
      // отметка необязательная: без нее список клиентов работает как раньше
      .catch(() => {})
    return () => {
      alive = false
    }
  }, [serverId])
  return hits
}
