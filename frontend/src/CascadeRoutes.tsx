import { useRef, useState, type FormEvent } from 'react'
import { ApiError, updateCascadeRoutes, type Cascade, type CascadeRoute } from './api'
import { useI18n } from './i18n'
import { useModalDismiss } from './useModalDismiss'

type Props = {
  cascade: Cascade
  onClose: () => void
  onSaved: (cascade: Cascade) => void
  onUnauthorized: () => void
}

export function CascadeRoutesModal({ cascade, onClose, onSaved, onUnauthorized }: Props) {
  const { t } = useI18n()
  const [rows, setRows] = useState(() => (cascade.routes ?? []).map((route, id) => ({ ...route, id })))
  const nextId = useRef(rows.length)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const dismiss = useModalDismiss(() => { if (!saving) onClose() })

  function edit(id: number, changes: Partial<CascadeRoute>) {
    setRows((prev) => prev.map((row) => row.id === id ? { ...row, ...changes } : row))
  }

  async function save(event: FormEvent) {
    event.preventDefault()
    if (saving) return
    setSaving(true)
    setError('')
    try {
      onSaved(await updateCascadeRoutes(cascade.id, rows.map(({ destination, via }) => ({ destination, via }))))
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) onUnauthorized()
      else setError(t(err instanceof Error ? err.message : 'Не удалось применить маршруты'))
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="modal-backdrop" onClick={dismiss}>
      <form className="card modal" role="dialog" aria-modal="true" aria-labelledby="cascade-routes-title"
        onClick={(event) => event.stopPropagation()} onSubmit={save}>
        <div className="clients-head">
          <h3 id="cascade-routes-title">{t('Маршруты каскада')}</h3>
          <button type="button" className="ghost" disabled={saving} onClick={onClose}>{t('Закрыть')}</button>
        </div>
        <p className="muted small">{t('Укажите домен, IPv4 или подсеть. Для домена правило действует и на поддомены. Первое совпавшее правило задает маршрут, для остальных адресов действуют настройки каскада. При сохранении шлюз кратко перезапускается.')}</p>
        <div className="cascade-route-list">
          {rows.map(({ id, destination, via }) => (
            <div className="cascade-route-row" key={id}>
              <input aria-label={t('Домен, IPv4 или подсеть')} placeholder="example.com"
                required maxLength={253} value={destination} disabled={saving}
                onChange={(event) => edit(id, { destination: event.target.value })} />
              <select aria-label={t('Маршрут')} value={via} disabled={saving}
                onChange={(event) => edit(id, { via: event.target.value as CascadeRoute['via'] })}>
                <option value="entry">{t('Через вход')}</option>
                <option value="exit">{t('Через выход')}</option>
              </select>
              <button type="button" className="ghost" disabled={saving}
                onClick={() => setRows((prev) => prev.filter((row) => row.id !== id))}>{t('Удалить')}</button>
            </div>
          ))}
        </div>
        {error && <div className="err-text small" role="alert">{error}</div>}
        <div className="modal-actions">
          <button type="button" className="ghost" disabled={saving || rows.length >= 100}
            onClick={() => {
              const id = nextId.current++
              setRows((prev) => [...prev, { id, destination: '', via: 'entry' }])
            }}>{t('Добавить правило')}</button>
          <button type="submit" disabled={saving}>{t(saving ? 'Сохраняем…' : 'Сохранить')}</button>
        </div>
      </form>
    </div>
  )
}
