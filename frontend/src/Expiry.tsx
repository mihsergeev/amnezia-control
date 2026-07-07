import { useState } from 'react'
import { useI18n } from './i18n'

// ISO-строка через N дней от текущего момента.
export function daysFromNowIso(days: number): string {
  return new Date(Date.now() + days * 86_400_000).toISOString()
}

// ISO → значение для <input type="datetime-local"> в локальной зоне.
function isoToLocalInput(iso: string): string {
  const d = new Date(iso)
  const off = d.getTimezoneOffset() * 60_000
  return new Date(d.getTime() - off).toISOString().slice(0, 16)
}

function localInputToIso(local: string): string | null {
  if (!local) return null
  const ms = new Date(local).getTime()
  if (Number.isNaN(ms)) return null
  return new Date(ms).toISOString()
}

type SelectMode = 'none' | '7' | '30' | '90' | 'custom'

// Выпадающий выбор срока для форм выдачи и инлайн-редактирования.
export function ExpirySelect({
  value,
  onChange,
  autoFocus,
}: {
  value: string | null
  onChange: (iso: string | null) => void
  autoFocus?: boolean
}) {
  const { t } = useI18n()
  const [mode, setMode] = useState<SelectMode>(value ? 'custom' : 'none')
  const [custom, setCustom] = useState<string>(
    value ? isoToLocalInput(value) : '',
  )

  function pick(next: SelectMode) {
    setMode(next)
    if (next === 'none') onChange(null)
    else if (next === 'custom') onChange(localInputToIso(custom))
    else onChange(daysFromNowIso(Number(next)))
  }

  return (
    <span className="expiry-select">
      <select
        autoFocus={autoFocus}
        value={mode}
        onChange={(e) => pick(e.target.value as SelectMode)}
      >
        <option value="none">{t('Бессрочно')}</option>
        <option value="7">{t('7 дней')}</option>
        <option value="30">{t('30 дней')}</option>
        <option value="90">{t('90 дней')}</option>
        <option value="custom">{t('Своя дата…')}</option>
      </select>
      {mode === 'custom' && (
        <input
          type="datetime-local"
          value={custom}
          onChange={(e) => {
            setCustom(e.target.value)
            onChange(localInputToIso(e.target.value))
          }}
        />
      )}
    </span>
  )
}

// Классификация срока для окраски бейджа.
function classify(iso: string): { kind: 'expired' | 'soon' | 'ok'; days: number } {
  const days = Math.ceil((new Date(iso).getTime() - Date.now()) / 86_400_000)
  if (days <= 0) return { kind: 'expired', days }
  if (days <= 3) return { kind: 'soon', days }
  return { kind: 'ok', days }
}

// Ячейка «срок» в таблице клиентов: бейдж + инлайн-редактирование.
export function ExpiryCell({
  value,
  onSave,
  disabled,
}: {
  value: string | null | undefined
  onSave: (iso: string | null) => Promise<void> | void
  disabled?: boolean
}) {
  const { t, lang } = useI18n()
  const [editing, setEditing] = useState(false)
  const [draft, setDraft] = useState<string | null>(value ?? null)
  const [saving, setSaving] = useState(false)

  async function save() {
    setSaving(true)
    try {
      await onSave(draft)
      setEditing(false)
    } finally {
      setSaving(false)
    }
  }

  if (editing) {
    return (
      <span className="expiry-edit">
        <ExpirySelect value={draft} onChange={setDraft} autoFocus />
        <button className="ghost" disabled={saving} onClick={save}>
          {saving ? '…' : t('Сохранить')}
        </button>
        <button
          className="ghost"
          disabled={saving}
          onClick={() => {
            setDraft(value ?? null)
            setEditing(false)
          }}
        >
          {t('Отмена')}
        </button>
      </span>
    )
  }

  const start = () => {
    if (disabled) return
    setDraft(value ?? null)
    setEditing(true)
  }

  if (!value) {
    return (
      <button className="expiry-badge expiry-none" onClick={start} title={t('Задать срок')}>
        ∞
      </button>
    )
  }

  const { kind } = classify(value)
  const date = new Date(value).toLocaleDateString(lang === 'en' ? 'en-GB' : 'ru-RU', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
  })
  const label = kind === 'expired' ? t('истёк') : t('до {date}', { date })

  return (
    <button
      className={`expiry-badge expiry-${kind}`}
      onClick={start}
      title={t('Изменить срок')}
    >
      {label}
    </button>
  )
}
