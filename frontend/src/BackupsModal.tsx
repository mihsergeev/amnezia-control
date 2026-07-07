import { useCallback, useEffect, useState } from 'react'
import { api, downloadSavedBackup, type BackupItem } from './api'
import { formatBytes } from './format'
import { useI18n } from './i18n'

type Props = {
  onClose: () => void
  onUnauthorized: () => void
}

export function BackupsModal({ onClose, onUnauthorized }: Props) {
  const { t, lang } = useI18n()
  const [items, setItems] = useState<BackupItem[] | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(async () => {
    try {
      const r = await api<{ backups: BackupItem[] }>('/api/backup/list')
      setItems(r.backups)
      setError(null)
    } catch {
      setError(t('не удалось загрузить список'))
    }
  }, [t])

  useEffect(() => {
    void load()
  }, [load])

  async function makeNow() {
    setBusy(true)
    setError(null)
    try {
      await api('/api/backup/now', { method: 'POST' })
      await load()
    } catch {
      setError(t('не удалось сделать бэкап'))
    } finally {
      setBusy(false)
    }
  }

  async function download(name: string) {
    try {
      await downloadSavedBackup(name)
    } catch {
      onUnauthorized()
    }
  }

  function fmtDate(iso: string) {
    const d = new Date(iso)
    return d.toLocaleString(lang === 'en' ? 'en-GB' : 'ru-RU', {
      dateStyle: 'medium',
      timeStyle: 'short',
    })
  }

  return (
    <div className="modal-backdrop">
      <div className="card modal modal-wide" onClick={(e) => e.stopPropagation()}>
        <div className="clients-head">
          <h3>{t('Авто-бэкапы БД')}</h3>
          <button className="ghost" onClick={onClose}>
            {t('Закрыть')}
          </button>
        </div>
        <p className="muted small">
          {t('Панель сама делает копии БД по расписанию и хранит последние. Файлы лежат на сервере в data/backups; можно скачать любую или восстановить через «Бэкап → Восстановить из файла».')}
        </p>

        {error && <p className="form-error">{error}</p>}

        <div className="toolbar">
          <button onClick={makeNow} disabled={busy}>
            {busy ? t('Создание…') : t('Сделать бэкап сейчас')}
          </button>
        </div>

        {items === null ? (
          <p className="muted">{t('загрузка…')}</p>
        ) : items.length === 0 ? (
          <p className="muted">{t('Пока нет ни одной копии.')}</p>
        ) : (
          <div className="table-card">
            <table>
              <thead>
                <tr>
                  <th>{t('Дата')}</th>
                  <th>{t('Размер')}</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {items.map((b) => (
                  <tr key={b.filename}>
                    <td>{fmtDate(b.created)}</td>
                    <td className="muted mono">{formatBytes(b.size)}</td>
                    <td className="row-actions">
                      <button className="ghost" onClick={() => download(b.filename)}>
                        {t('Скачать')}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
