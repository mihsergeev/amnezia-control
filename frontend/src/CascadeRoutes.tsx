import { useEffect, useRef, useState, type FormEvent } from 'react'
import { ApiError, previewCascadeRoutes, updateCascadeRoutes, type CascadeRouteDestinationResult, type Cascade, type CascadeRoute, type Server } from './api'
import { cascadeEntryCountry } from './cascadeUi'
import { countryFlag } from './format'
import { useI18n } from './i18n'
import { useModalDismiss } from './useModalDismiss'
import { MAX_CASCADE_ROUTES, appendRouteBatch, moveRoute, previewRouteBatch, routeBatchInput, routeOverlap, routeSignature, type RouteOverlap, type BatchRouteLine } from './cascadeRouteDraft'

type Props = {
  cascade: Cascade
  entry?: Server
  exit?: Server
  onClose: () => void
  onSaved: (cascade: Cascade) => void
  onUnauthorized: () => void
}
type Row = CascadeRoute & { id: number }
type Editor = { id: number | null; destination: string; via: CascadeRoute['via']; priority: string }

// Remount drafts when the actual cascade or its gateway identity changes.
export function CascadeRoutesModal(props: Props) {
  return <CascadeRoutesEditor key={`${props.cascade.id}:${props.cascade.entry_server_id}:${props.cascade.exit_server_id}:${props.cascade.entry_ip}:${props.cascade.exit_ip}:${props.cascade.transport}`} {...props} />
}

function CascadeRoutesEditor({ cascade, entry, exit, onClose, onSaved, onUnauthorized }: Props) {
  const { t } = useI18n()
  const initial = useRef((cascade.routes ?? []).map((route, id) => ({ ...route, id })))
  const [rows, setRows] = useState<Row[]>(initial.current)
  const nextId = useRef(rows.length)
  const [saving, setSaving] = useState(false)
  const busy = useRef(false)
  const alive = useRef(true)
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')
  const [query, setQuery] = useState('')
  const [selected, setSelected] = useState<Set<number>>(new Set())
  const [bulkVia, setBulkVia] = useState<CascadeRoute['via']>('exit')
  const [batch, setBatch] = useState('')
  const [batchVia, setBatchVia] = useState<CascadeRoute['via']>('exit')
  const [checkedBatch, setCheckedBatch] = useState<{ text: string; results: CascadeRouteDestinationResult[] } | null>(null)
  const [lastReport, setLastReport] = useState<BatchRouteLine[] | null>(null)
  const [validating, setValidating] = useState<'batch' | 'editor' | null>(null)
  const validationBusy = useRef(false)
  const validationRevision = useRef(0)
  const [editor, setEditor] = useState<Editor | null>(null)
  const [editorError, setEditorError] = useState('')
  const dirty = routeSignature(rows) !== routeSignature(initial.current)
  const pending = dirty || !!batch.trim() || !!editor
  const visible = rows.filter((row) => row.destination.toLowerCase().includes(query.trim().toLowerCase()))
  const hiddenSelected = rows.filter((row) => selected.has(row.id) && !visible.some((shown) => shown.id === row.id)).length
  const preview = checkedBatch?.text === batch ? previewRouteBatch(batch, rows, checkedBatch.results) : null
  const report = preview ?? lastReport
  const valid = preview?.filter((line) => line.status === 'valid') ?? []
  const tooMany = rows.length + valid.length > MAX_CASCADE_ROUTES
  const nodes = [
    { via: 'entry', label: t('Вход'), server: entry, address: cascade.entry_ip, country: cascadeEntryCountry(cascade, entry) },
    { via: 'exit', label: t('Выход'), server: exit, address: cascade.exit_ip, country: exit?.country ?? '' },
  ] as const

  useEffect(() => { alive.current = true; return () => { alive.current = false } }, [])
  useEffect(() => {
    function warn(event: BeforeUnloadEvent) { if (pending) { event.preventDefault(); event.returnValue = '' } }
    window.addEventListener('beforeunload', warn)
    return () => window.removeEventListener('beforeunload', warn)
  }, [pending])

  function close() {
    if (!busy.current && (!pending || window.confirm(t('Закрыть без сохранения? Несохраненные изменения будут потеряны.')))) onClose()
  }
  const dismiss = useModalDismiss(close)

  function changed(updated: Row[]) {
    validationRevision.current++
    setRows(updated)
    setError('')
    setMessage('')
  }
  function edit(id: number, changes: Partial<CascadeRoute>) {
    changed(rows.map((row) => row.id === id ? { ...row, ...changes } : row))
  }
  function overlapText(overlap: RouteOverlap) {
    return t('Пересекается с правилом {n}: {address}. Первое совпадение важнее.', { n: overlap.priority, address: overlap.destination })
  }
  function reset() {
    validationRevision.current++
    if (pending && !window.confirm(t('Отменить изменения? Несохраненные изменения будут потеряны.'))) return
    changed(initial.current)
    setSelected(new Set())
    setBatch('')
    setCheckedBatch(null)
    setLastReport(null)
    setEditor(null)
    setQuery('')
  }
  async function validateBatch() {
    if (validationBusy.current) return
    const input = routeBatchInput(batch)
    if (input.length > 200 || input.some((line) => line.raw.length > 1024)) {
      setError(t('За одну проверку можно отправить до 200 адресов, не больше 1024 символов в строке.')); return
    }
    const revision = ++validationRevision.current
    validationBusy.current = true
    setValidating('batch')
    setError('')
    try {
      const result = await previewCascadeRoutes(input.map((line) => line.raw))
      if (alive.current && revision === validationRevision.current) setCheckedBatch({ text: batch, results: result.results })
    } catch (err) {
      if (alive.current && revision === validationRevision.current) {
        if (err instanceof ApiError && err.status === 401) onUnauthorized()
        else setError(t('Не удалось проверить адреса. Повторите попытку.'))
      }
    } finally {
      validationBusy.current = false
      if (alive.current) setValidating(null)
    }
  }
  async function applyEditor() {
    if (!editor || validationBusy.current) return
    if (editor.destination.length > 1024) { setEditorError(t('Введите домен, IPv4 или подсеть с нулевыми битами хоста')); return }
    const revision = ++validationRevision.current
    validationBusy.current = true
    setValidating('editor')
    setEditorError('')
    let result: CascadeRouteDestinationResult
    try {
      const response = await previewCascadeRoutes([editor.destination])
      if (!alive.current || revision !== validationRevision.current) return
      result = response.results[0]
    } catch (err) {
      if (alive.current && revision === validationRevision.current) {
        if (err instanceof ApiError && err.status === 401) onUnauthorized()
        else setEditorError(t('Не удалось проверить адреса. Повторите попытку.'))
      }
      return
    } finally {
      validationBusy.current = false
      if (alive.current) setValidating(null)
    }
    if (!result?.valid) { setEditorError(result?.error === 'reserved_destination' ? t('Этот домен зарезервирован для проверки каскада') : t('Введите домен, IPv4 или подсеть с нулевыми битами хоста')); return }
    if (rows.some((row) => row.id !== editor.id && row.destination === result.destination)) { setEditorError(t('Такой адрес уже есть в списке')); return }
    const priority = Number(editor.priority)
    const count = rows.length + (editor.id === null ? 1 : 0)
    if (count > MAX_CASCADE_ROUTES || !/^\d+$/.test(editor.priority) || priority < 1 || priority > count) {
      setEditorError(t('Укажите приоритет от 1 до {n}', { n: Math.min(count, MAX_CASCADE_ROUTES) })); return
    }
    const existing = rows.findIndex((row) => row.id === editor.id)
    const updated = editor.id === null
      ? [...rows, { id: nextId.current++, destination: result.destination, via: editor.via }]
      : rows.map((row) => row.id === editor.id ? { ...row, destination: result.destination, via: editor.via } : row)
    changed(moveRoute(updated, existing < 0 ? updated.length - 1 : existing, priority - 1))
    setEditor(null)
  }
  async function save(event: FormEvent) {
    event.preventDefault()
    if (busy.current || validationBusy.current || !dirty || editor || batch.trim()) return
    if (!window.confirm(t('Сохранить маршруты? Шлюз кратко перезапустится, соединение может прерваться.'))) return
    busy.current = true
    setSaving(true)
    setError('')
    try {
      const saved = await updateCascadeRoutes(cascade.id, rows.map(({ destination, via }) => ({ destination, via })))
      if (alive.current) onSaved(saved)
    } catch (err) {
      if (!alive.current) return
      if (err instanceof ApiError && err.status === 401) onUnauthorized()
      else setError(t(err instanceof Error ? err.message : 'Не удалось применить маршруты'))
    } finally {
      busy.current = false
      if (alive.current) setSaving(false)
    }
  }

  return (
    <div className="modal-backdrop cascade-routes-backdrop" onClick={dismiss}>
      <form className="card modal cascade-routes-modal" role="dialog" aria-modal="true" aria-labelledby="cascade-routes-title"
        onClick={(event) => event.stopPropagation()} onSubmit={save}>
        <div className="clients-head">
          <h3 id="cascade-routes-title">{t('Маршруты каскада')}</h3>
          <button type="button" className="ghost" disabled={saving} onClick={close}>{t('Закрыть')}</button>
        </div>
        <div className="cascade-routes-scroll"><fieldset className="cascade-routes-body" disabled={saving}>
          <div className="cascade-route-nodes">
            {nodes.map((node) => <div className="cascade-route-node" key={node.via}>
              <span className="server-flag" aria-hidden="true">{countryFlag(node.country)}</span>
              <div><strong>{node.label} · {node.server?.name || node.server?.host || node.address || '—'}</strong>
                <span className="muted small mono">{node.address || node.server?.host || '—'}</span></div>
            </div>)}
          </div>
          <p className="muted small">{t('Первое совпавшее правило задает маршрут. Домены включают поддомены. Для остальных адресов действуют настройки каскада.')}</p>
          <section className="cascade-route-batch" aria-labelledby="cascade-route-batch-title">
            <h4 id="cascade-route-batch-title">{t('Пакетное добавление')}</h4>
            <div className="cascade-route-batch-inputs">
              <label>{t('По одному адресу на строку')}<textarea rows={4} value={batch} placeholder={'service.example.com\n192.0.2.0/24'}
                onChange={(event) => { validationRevision.current++; setBatch(event.target.value); setCheckedBatch(null); setLastReport(null); setMessage('') }} /></label>
              <label>{t('Направление новых правил')}<select value={batchVia} onChange={(event) => { validationRevision.current++; setBatchVia(event.target.value as CascadeRoute['via']); setCheckedBatch(null) }}>
                <option value="entry">{t('Вход')}</option><option value="exit">{t('Выход')}</option>
              </select></label>
            </div>
            <div className="cascade-route-toolbar">
              <button type="button" className="ghost" disabled={!batch.trim() || !!validating} onClick={validateBatch}>{validating === 'batch' ? t('Проверяем…') : t('Проверить адреса')}</button>
              <button type="button" disabled={!preview || !valid.length || tooMany || !!validating || !!editor} onClick={() => {
                if (!preview || tooMany) return
                const updated = appendRouteBatch(rows, preview, batchVia)
                if (!updated) return
                const added = updated.slice(rows.length).map((route) => ({ ...route, id: nextId.current++ }))
                changed([...rows, ...added])
                setLastReport(preview)
                setBatch('')
                setCheckedBatch(null)
                setMessage(t('Добавлено в конец списка: {n}. Изменения еще не сохранены.', { n: added.length }))
              }}>{t('Добавить {n}', { n: valid.length })}</button>
              {batch && <button type="button" className="ghost" onClick={() => { validationRevision.current++; setBatch(''); setCheckedBatch(null) }}>{t('Очистить ввод')}</button>}
              <span className="muted small">{t('Новые правила добавляются в конец списка')}</span>
            </div>
            {report && <div className="cascade-route-preview" aria-live="polite">
              <p className="small">{preview ? t('К добавлению: {valid}, пропущено: {skipped}', { valid: valid.length, skipped: preview.length - valid.length }) : t('Добавлено: {valid}, пропущено: {skipped}', { valid: report.filter((line) => line.status === 'valid').length, skipped: report.filter((line) => line.status !== 'valid').length })}</p>
              {tooMany && <p className="err-text small" role="alert">{t('Лимит 100 правил. Свободно: {n}. Уменьшите пакет, адреса не будут обрезаны.', { n: MAX_CASCADE_ROUTES - rows.length })}</p>}
              <ol>{report.map((line) => <li key={line.line} className={line.status === 'valid' ? '' : 'err-text'} value={line.line}>
                <span className="mono">{line.destination || line.raw}</span><span className="small">{line.status === 'valid' ? (preview ? t('Готово к добавлению') : t('Добавлено в список')) : line.status === 'duplicate' ? t('Пропуск: адрес уже есть в списке или пакете') : line.status === 'reserved' ? t('Пропуск: домен зарезервирован для проверки каскада') : t('Пропуск: неверный домен, IPv4 или подсеть')}
                  {line.overlap && <span className="cascade-route-warning">{overlapText(line.overlap)}</span>}</span>
              </li>)}</ol>
            </div>}
          </section>
          <div className="cascade-route-toolbar">
            <label className="cascade-route-search">{t('Поиск по адресу')}<input type="search" value={query} onChange={(event) => setQuery(event.target.value)} /></label>
            <button type="button" className="ghost" disabled={rows.length >= MAX_CASCADE_ROUTES || !!editor} onClick={() => {
              setEditor({ id: null, destination: '', via: 'entry', priority: String(rows.length + 1) }); setEditorError('')
            }}>{t('Добавить правило')}</button>
          </div>
          {editor && <section className="cascade-route-editor" aria-label={editor.id === null ? t('Новое правило') : t('Редактирование правила')}>
            <label className="cascade-route-editor-address">{t('Домен, IPv4 или подсеть')}<input autoFocus maxLength={1024} value={editor.destination} onChange={(event) => { validationRevision.current++; setEditor({ ...editor, destination: event.target.value }) }} onKeyDown={(event) => { if (event.key === 'Enter') { event.preventDefault(); applyEditor() } }} /></label>
            <label>{t('Направление')}<select value={editor.via} onChange={(event) => { validationRevision.current++; setEditor({ ...editor, via: event.target.value as CascadeRoute['via'] }) }}><option value="entry">{t('Вход')}</option><option value="exit">{t('Выход')}</option></select></label>
            <label>{t('Приоритет')}<input type="number" min="1" max={Math.min(rows.length + (editor.id === null ? 1 : 0), MAX_CASCADE_ROUTES)} value={editor.priority} onChange={(event) => { validationRevision.current++; setEditor({ ...editor, priority: event.target.value }) }} /></label>
            <div className="cascade-route-toolbar"><button type="button" disabled={!!validating} onClick={applyEditor}>{t('Применить правило')}</button><button type="button" className="ghost" onClick={() => { validationRevision.current++; setEditor(null) }}>{t('Отмена')}</button></div>
            {editorError && <p className="err-text small" role="alert">{editorError}</p>}
          </section>}
          <div className="cascade-route-summary">
            <label className="cascade-route-check"><input type="checkbox" checked={visible.length > 0 && visible.every((row) => selected.has(row.id))} disabled={!visible.length || !!editor}
              onChange={(event) => setSelected((prev) => { const copy = new Set(prev); visible.forEach((row) => event.target.checked ? copy.add(row.id) : copy.delete(row.id)); return copy })} />{t('Выбрать показанные')}</label>
            <span className="muted small">{t('Показано: {shown} из {total}. Лимит: 100.', { shown: visible.length, total: rows.length })}</span>
          </div>
          {selected.size > 0 && <div className="cascade-route-selection">
            <span className="small">{t('Выбрано: {n}, скрыто поиском: {hidden}', { n: selected.size, hidden: hiddenSelected })}</span>
            <label>{t('Направление выбранных')}<select disabled={!!editor} value={bulkVia} onChange={(event) => setBulkVia(event.target.value as CascadeRoute['via'])}><option value="entry">{t('Вход')}</option><option value="exit">{t('Выход')}</option></select></label>
            <button type="button" disabled={!!editor} onClick={() => changed(rows.map((row) => selected.has(row.id) ? { ...row, via: bulkVia } : row))}>{t('Применить к {n}', { n: selected.size })}</button>
            <button type="button" className="ghost" onClick={() => setSelected(new Set())}>{t('Снять выбор')}</button>
          </div>}
          <div className="cascade-route-list" aria-label={t('Существующие правила')}>
            {visible.length === 0 && <div className="muted small cascade-route-empty">{rows.length ? t('Поиск не дал результатов') : t('Ручных маршрутов пока нет')}</div>}
            {visible.map((row) => {
              const index = rows.indexOf(row)
              const overlap = routeOverlap(row.destination, rows, index)
              return <div className="cascade-route-row" key={row.id} data-priority={index + 1}>
                <input className="cascade-route-row-check" type="checkbox" aria-label={t('Выбрать правило {n}', { n: index + 1 })} disabled={!!editor} checked={selected.has(row.id)} onChange={(event) => setSelected((prev) => { const copy = new Set(prev); if (event.target.checked) copy.add(row.id); else copy.delete(row.id); return copy })} />
                <span className="cascade-route-priority muted" title={t('Приоритет')}>{index + 1}</span>
                <div className="cascade-route-destination"><span className="mono">{row.destination}</span>{overlap && <span className="cascade-route-warning small">{overlapText(overlap)}</span>}</div>
                <select disabled={!!editor} aria-label={t('Направление правила {n}', { n: index + 1 })} value={row.via} onChange={(event) => edit(row.id, { via: event.target.value as CascadeRoute['via'] })}><option value="entry">{t('Вход')}</option><option value="exit">{t('Выход')}</option></select>
                <div className="cascade-route-row-actions"><button type="button" className="ghost" disabled={!!editor} aria-label={t('Редактировать правило {n}', { n: index + 1 })} onClick={() => { setEditor({ ...row, priority: String(index + 1) }); setEditorError('') }}>{t('Изменить')}</button>
                  <button type="button" className="ghost" disabled={!!editor} aria-label={t('Удалить правило {n}', { n: index + 1 })} onClick={() => { changed(rows.filter((item) => item.id !== row.id)); setSelected((prev) => { const copy = new Set(prev); copy.delete(row.id); return copy }) }}>{t('Удалить')}</button></div>
              </div>
            })}
          </div>
        </fieldset></div>
        <div className="cascade-route-footer">
          <p className="muted small">{t('При сохранении шлюз кратко перезапускается. Соединение может прерваться.')}</p>
          <div className="small" role="status">{message || (dirty ? t('Есть несохраненные изменения') : pending ? t('Есть незавершенный ввод') : t('Все изменения сохранены'))}</div>
          {(editor || batch.trim()) && <p className="muted small">{t('Завершите редактирование и добавление адресов или очистите ввод перед сохранением.')}</p>}
          {error && <div className="err-text small" role="alert">{error}</div>}
          <div className="modal-actions">
            <button type="button" className="ghost" disabled={saving || !pending} onClick={reset}>{t('Отменить изменения')}</button>
            <button type="submit" disabled={saving || !!validating || !dirty || !!editor || !!batch.trim()}>{t(saving ? 'Сохраняем…' : 'Сохранить')}</button>
          </div>
        </div>
      </form>
    </div>
  )
}
