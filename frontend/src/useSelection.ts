import { useMemo, useState } from 'react'

// После обновления списка исчезнувшие ключи выпадают из выбора.
export function useSelection(keys: string[]) {
  const [picked, setPicked] = useState<Set<string>>(new Set())
  const selected = useMemo(() => keys.filter((k) => picked.has(k)), [keys, picked])
  const all = keys.length > 0 && selected.length === keys.length
  return {
    selected,
    all,
    has: (k: string) => picked.has(k),
    toggle: (k: string) =>
      setPicked((prev) => {
        const next = new Set(prev)
        if (next.has(k)) next.delete(k)
        else next.add(k)
        return next
      }),
    toggleAll: () => setPicked(all ? new Set() : new Set(keys)),
    clear: () => setPicked(new Set()),
  }
}

export type Selection = ReturnType<typeof useSelection>
