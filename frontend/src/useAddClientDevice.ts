import { useEffect, useRef, useState } from 'react'
import { api } from './api'
import type { PersonClient } from './clientGrouping'

// A single existing config only receives metadata. No create request is sent here.
export function useAddClientDevice({ serverId, protocol, generation, onOpen, onApplied, onError }: {
  serverId: number; protocol: string; generation: { current: number }; onOpen: (group: string) => void
  onApplied: (id: string, group: string) => void; onError: (error: unknown) => void
}) {
  const context = `${serverId}:${protocol}`
  const currentContext = useRef(context)
  currentContext.current = context
  const lock = useRef(false)
  const [busy, setBusy] = useState(false)
  const alive = useRef(true)
  useEffect(() => { alive.current = true; return () => { alive.current = false } }, [])
  async function add(client: PersonClient) {
    if (lock.current) return
    if (client.group_name) { onOpen(client.group_name); return }
    lock.current = true
    setBusy(true)
    const request = generation.current
    try {
      const group = client.name.trim()
      if (!group) throw new Error('Client name is empty')
      await api<void>(`/api/servers/${serverId}/client-metadata`, {
        method: 'POST', body: JSON.stringify({ protocol, client_id: client.id, group_name: group, device_name: client.device_name ?? '' }),
      })
      if (!alive.current || request !== generation.current || context !== currentContext.current) return
      onApplied(client.id, group)
      onOpen(group)
    } catch (error) {
      if (alive.current && request === generation.current && context === currentContext.current) onError(error)
    } finally { lock.current = false; if (alive.current) setBusy(false) }
  }
  return { add, busy }
}
