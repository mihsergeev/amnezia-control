import { useRef, useState, type FormEvent } from 'react'
import { ApiError, updateCascadeRoutes, type Cascade, type CascadeRoute, type Server } from './api'
import { cascadeEntryCountry } from './cascadeUi'
import { countryFlag } from './format'
import { useI18n } from './i18n'
import { useModalDismiss } from './useModalDismiss'

type Props = {
  cascade: Cascade
  entry?: Server
  exit?: Server
  onClose: () => void
  onSaved: (cascade: Cascade) => void
  onUnauthorized: () => void
}

export function CascadeRoutesModal({ cascade, entry, exit, onClose, onSaved, onUnauthorized }: Props) {
  const { t } = useI18n()
  const [rows, setRows] = useState(() => (cascade.routes ?? []).map((route, id) => ({ ...route, id })))
  const nextId = useRef(rows.length)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const nodes = [
    { via: 'entry', label: t('Вход'), server: entry, address: cascade.entry_ip, country: cascadeEntryCountry(cascade, entry) },
    { via: 'exit', label: t('Выход'), server: exit, address: cascade.exit_ip, country: exit?.country ?? '' },
  ] as const
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
      <form className="card modal cascade-routes-modal" role="dialog" aria-modal="true" aria-labelledby="cascade-routes-title"
        onClick={(event) => event.stopPropagation()} onSubmit={save}>
        <div className="clients-head">
          <h3 id="cascade-routes-title">{t('Маршруты каскада')}</h3>
          <button type="button" className="ghost" disabled={saving} onClick={onClose}>{t('Закрыть')}</button>
        </div>
        <p className="muted small">{t('Укажите домен, IPv4 или подсеть. Для домена правило действует и на поддомены. Первое совпавшее правило задает маршрут, для остальных адресов действуют настройки каскада. При сохранении шлюз кратко перезапускается.')}</p>
        <div className="cascade-route-list">
          {rows.length === 0 && <div className="muted small cascade-route-empty">{t('Ручных маршрутов пока нет')}</div>}
          {rows.map(({ id, destination, via }, index) => (
            <fieldset className="cascade-route-row" key={id} disabled={saving}>
              <legend>{t('Правило {n}', { n: index + 1 })}</legend>
              <div className="cascade-route-address">
                <label>
                  <span>{t('Домен, IPv4 или подсеть')}</span>
                  <input placeholder="example.com" required maxLength={253} value={destination}
                    onChange={(event) => edit(id, { destination: event.target.value })} />
                </label>
                <button type="button" className="ghost"
                  onClick={() => setRows((prev) => prev.filter((row) => row.id !== id))}>{t('Удалить')}</button>
              </div>
              <div className="cascade-route-options" role="group" aria-label={t('Сервер выхода в интернет')}>
                {nodes.map((node) => {
                  const host = node.server?.host || node.address
                  const flag = countryFlag(node.country)
                  return (
                    <label className="cascade-route-option" key={node.via}>
                      <input type="radio" name={`route-${id}`} checked={via === node.via}
                        onChange={() => edit(id, { via: node.via })} />
                      <span>
                        <strong>{node.label}</strong>
                        <span className="cascade-route-node">
                          {flag && <span className="server-flag" aria-hidden="true">{flag}</span>}
                          {node.server?.name || host || '—'}
                        </span>
                        {node.server?.name && host && <span className="muted small mono">{host}</span>}
                      </span>
                    </label>
                  )
                })}
              </div>
            </fieldset>
          ))}
        </div>
        {error && <div className="err-text small" role="alert">{error}</div>}
        <div className="modal-actions">
          <button type="button" className="ghost" disabled={saving || rows.length >= 100}
            onClick={() => {
              const id = nextId.current++
              setRows((prev) => [...prev, { id, destination: '', via: 'entry' }])
            }}>{t('Добавить правило')}</button>
          <button type="submit" disabled={saving || (rows.length === 0 && !cascade.routes?.length)}>{t(saving ? 'Сохраняем…' : 'Сохранить')}</button>
        </div>
      </form>
    </div>
  )
}
