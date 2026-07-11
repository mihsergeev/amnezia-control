import { useRef, useState } from 'react'
import { useI18n } from './i18n'

type Props = {
  name: string
  note: string
  /** если задан — рисуем точку онлайн/оффлайн слева от имени */
  online?: boolean
  onSave: (note: string) => Promise<void> | void
}

/** Инлайновая заметка к клиенту (как у AmneziaWG): ✎ для правки, Enter — сохранить,
 * Esc — отмена. Опционально показывает индикатор онлайна. Общий для xray/openvpn. */
export function NoteCell({ name, note, online, onSave }: Props) {
  const { t } = useI18n()
  const [editing, setEditing] = useState(false)
  const [draft, setDraft] = useState('')
  const escaping = useRef(false)

  function start() {
    escaping.current = false
    setDraft(note || '')
    setEditing(true)
  }
  function cancel() {
    escaping.current = true
    setEditing(false)
  }
  async function commit() {
    if (escaping.current) {
      escaping.current = false
      return
    }
    const value = draft.trim()
    setEditing(false)
    if (value === (note || '')) return
    await onSave(value)
  }

  return (
    <>
      <div className="client-row-name">
        {online !== undefined && (
          <span className={`dot ${online ? 'dot-ok' : 'dot-unknown'}`} />
        )}
        <span className="cname" title={name}>
          {name}
        </span>
        {!editing && (
          <button className="note-edit" title={t('Заметка')} onClick={start}>
            ✎
          </button>
        )}
      </div>
      {editing ? (
        <input
          className="note-input"
          autoFocus
          value={draft}
          placeholder={t('заметка…')}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') commit()
            if (e.key === 'Escape') cancel()
          }}
          onBlur={commit}
        />
      ) : (
        note && (
          <div className="note-line" title={note} onClick={start}>
            {note}
          </div>
        )
      )}
    </>
  )
}
