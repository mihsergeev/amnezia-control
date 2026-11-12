import { useEffect, useRef, useState } from 'react'
import { api, ApiError } from './api'
import { useI18n } from './i18n'
import type { Selection } from './useSelection'
import { clientGroupNames, type PersonClient } from './clientGrouping'

// Select values are prefixed, so a person's literal name cannot collide with New.
export function ClientGroupSelect({ groups, value, onChange, disabled }: {
  groups: string[]; value: string; onChange: (value: string) => void; disabled: boolean
}) {
  const { t } = useI18n()
  const [creating, setCreating] = useState(!groups.includes(value))
  return <>
    <label><span>{t('Клиент / человек')}</span>
      <span className="client-person-select"><select disabled={disabled} value={creating ? 'new' : `group:${value}`} onChange={(event) => {
        const isNew = event.target.value === 'new'
        setCreating(isNew)
        onChange(isNew ? '' : event.target.value.slice(6))
      }}>
        <option value="new">{t('Новый клиент')}</option>
        {groups.map((group) => <option key={group} value={`group:${group}`}>{group}</option>)}
      </select></span>
    </label>
    {creating && <label><span>{t('Имя нового клиента')}</span>
      <input required maxLength={128} value={value} disabled={disabled} onChange={(event) => onChange(event.target.value)} />
    </label>}
  </>
}

export function ClientViewSwitch({ grouped, onChange }: { grouped: boolean; onChange: (value: boolean) => void }) {
  const { t } = useI18n()
  return <div className="client-view-switch" role="group" aria-label={t('Вид списка')}>
    <button type="button" className={grouped ? 'ghost' : ''} aria-pressed={!grouped} onClick={() => onChange(false)}>{t('Все конфиги')}</button>
    <button type="button" className={grouped ? '' : 'ghost'} aria-pressed={grouped} onClick={() => onChange(true)}>{t('По клиентам')}</button>
  </div>
}

// Headers are real table rows; config rows retain their keys and individual controls.
export function ClientGroupHeader({ name, visible, total, columns, onAdd, disabled }: {
  name: string; visible: number; total: number; columns: number; onAdd: () => void; disabled: boolean
}) {
  const { t } = useI18n()
  return <tr className="client-person-row"><td colSpan={columns}><div className="client-person-heading">
    <div><strong>{name || t('Отдельные конфиги')}</strong>{name && <span className="muted small">{visible === total
      ? t('Устройств: {n}', { n: String(total) }) : t('Устройств: {shown} из {total}', { shown: String(visible), total: String(total) })}</span>}</div>
    {name && <button type="button" className="ghost" disabled={disabled} onClick={onAdd}>{t('Добавить устройство')}</button>}
  </div></td></tr>
}

export function ClientGroupingBar({ serverId, protocol, clients, sel, onDone, onUnauthorized }: {
  serverId: number; protocol: string; clients: PersonClient[]; sel: Selection
  onDone: (ids: string[], group: string) => void; onUnauthorized: () => void
}) {
  const { t } = useI18n()
  const [open, setOpen] = useState(false)
  const [group, setGroup] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const lock = useRef(false)
  const alive = useRef(true)
  useEffect(() => { alive.current = true; return () => { alive.current = false } }, [])
  const currentSelection = useRef(sel)
  currentSelection.current = sel
  const selected = clients.filter((client) => sel.selected.includes(client.id))
  const n = selected.length
  const grouped = selected.some((client) => client.group_name)
  async function save(nextGroup: string) {
    if (lock.current || !n || n > 100) return
    lock.current = true
    setBusy(true)
    setError('')
    const ids = selected.map((client) => client.id)
    try {
      await api<void>(`/api/servers/${serverId}/client-metadata/bulk`, {
        method: 'POST', body: JSON.stringify({ protocol, client_ids: ids, group_name: nextGroup.trim() }),
      })
      if (!alive.current) return
      setOpen(false)
      onDone(ids, nextGroup.trim())
      if (currentSelection.current.selected.length === ids.length && ids.every((id) => currentSelection.current.selected.includes(id))) currentSelection.current.clear()
    } catch (err) {
      if (!alive.current) return
      if (err instanceof ApiError && err.status === 401) return onUnauthorized()
      setError(err instanceof Error ? err.message : t('Неизвестная ошибка'))
    } finally { lock.current = false; if (alive.current) setBusy(false) }
  }
  if (!n) return null
  return <section className="client-group-actions" aria-label={t('Клиентские группы')}>
    <div className="bulk-bar">
      <strong className="small">{t('Клиентские группы')}</strong>
      <button className="ghost" disabled={busy || n > 100} onClick={() => { setOpen(true); setError('') }}>
        {grouped ? t('Перенести в другого клиента') : t('Объединить в клиента')}
      </button>
      {grouped && <button className="ghost" disabled={busy || n > 100} onClick={() => void save('')}>{t('Убрать из клиента')}</button>}
    </div>
    <p className="muted small">{t('Меняется только учет клиентов. Конфиги и доступ сохраняются.')}</p>
    {n > 100 && <p className="form-error">{t('Выберите не больше 100 конфигов.')}</p>}
    {open && <form className="add-form client-group-form" onSubmit={(event) => { event.preventDefault(); if (group.trim()) void save(group) }}>
      <ClientGroupSelect groups={clientGroupNames(clients)} value={group} onChange={setGroup} disabled={busy} />
      <div className="add-form-actions">
        <button type="button" className="ghost" disabled={busy} onClick={() => setOpen(false)}>{t('Отмена')}</button>
        <button type="submit" disabled={busy || !group.trim()}>{busy ? t('Сохранение…') : t('Сохранить')}</button>
      </div>
    </form>}
    {error && <p role="alert" className="form-error">{error}</p>}
  </section>
}
