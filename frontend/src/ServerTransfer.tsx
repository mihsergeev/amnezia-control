/** Перенос одного сервера между панелями: выгрузка в файл и загрузка из него.
 *
 * Бэкап переносит панель целиком и затирает принимающую — для «отдать один
 * проект другой панели» он не годится. Здесь уезжает ровно один сервер вместе
 * с панельной обвязкой, которой нет на ноде: сохранённые конфиги, заметки,
 * сроки и паузы.
 */
import { useRef, useState } from 'react'
import {
  ApiError,
  exportServer,
  importServerFile,
  type Server,
  type ServerImportResult,
} from './api'
import { useI18n } from './i18n'
import { useModalDismiss } from './useModalDismiss'

type ExportProps = {
  server: Server
  onClose: () => void
  onUnauthorized: () => void
}

export function ServerExportModal({ server, onClose, onUnauthorized }: ExportProps) {
  const { t } = useI18n()
  const dismiss = useModalDismiss(onClose)
  const [history, setHistory] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function run() {
    setBusy(true)
    setError(null)
    try {
      await exportServer(server.id, history)
      onClose()
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) return onUnauthorized()
      setError(err instanceof Error ? err.message : t('Ошибка'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="modal-backdrop" onClick={dismiss}>
      <div className="card modal" onClick={(e) => e.stopPropagation()}>
        <div className="clients-head">
          <h3>
            {t('Выгрузить сервер')} · {server.name}
          </h3>
          <button className="ghost" onClick={onClose}>
            {t('Закрыть')}
          </button>
        </div>

        <p className="muted small">
          {t('В файл уедет карточка сервера и то, чего нет на ноде: сохранённые конфиги клиентов, заметки, сроки действия и паузы. Живых клиентов новая панель прочитает с самого сервера.')}
        </p>
        <p className="muted small">
          {t('SSH-ключ панели в файл не попадает — он общий для всех ваших нод. Новая панель ходит своим ключом, её нужно будет пустить на сервер скриптом настройки.')}
        </p>
        <p className="form-error">
          {t('Файл содержит приватные ключи клиентов — храните его как бэкап.')}
        </p>

        <label className="expiry-row">
          <input
            type="checkbox"
            checked={history}
            onChange={(e) => setHistory(e.target.checked)}
          />
          <span>{t('Включить историю трафика (файл станет в сотни раз больше)')}</span>
        </label>

        {error && <p className="form-error">{error}</p>}

        <div className="modal-actions">
          <button onClick={run} disabled={busy}>
            {busy ? t('Готовим…') : t('Скачать файл')}
          </button>
          <button className="ghost" onClick={onClose}>
            {t('Отмена')}
          </button>
        </div>
      </div>
    </div>
  )
}

type ImportProps = {
  onClose: () => void
  onDone: () => void
  onUnauthorized: () => void
}

export function ServerImportModal({ onClose, onDone, onUnauthorized }: ImportProps) {
  const { t } = useI18n()
  const dismiss = useModalDismiss(onClose)
  const fileRef = useRef<HTMLInputElement>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<ServerImportResult | null>(null)

  async function run() {
    const file = fileRef.current?.files?.[0]
    if (!file) {
      setError(t('Выберите файл выгрузки'))
      return
    }
    setBusy(true)
    setError(null)
    try {
      const res = await importServerFile(file)
      setResult(res)
      onDone()
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) return onUnauthorized()
      setError(err instanceof Error ? err.message : t('Ошибка'))
    } finally {
      setBusy(false)
    }
  }

  const rows = result ? Object.entries(result.imported) : []

  return (
    <div className="modal-backdrop" onClick={dismiss}>
      <div className="card modal" onClick={(e) => e.stopPropagation()}>
        <div className="clients-head">
          <h3>{t('Загрузить сервер из файла')}</h3>
          <button className="ghost" onClick={onClose}>
            {t('Закрыть')}
          </button>
        </div>

        {result ? (
          <>
            <p>
              {t('Сервер «{name}» ({host}) добавлен.', {
                name: result.name,
                host: result.host,
              })}
            </p>
            {rows.length > 0 && (
              <ul className="muted small">
                {rows.map(([table, n]) => (
                  <li key={table}>
                    {table}: {n}
                  </li>
                ))}
              </ul>
            )}
            {result.skipped_tables.length > 0 && (
              <p className="form-error">
                {t('Не удалось принять таблицы (файл из более новой панели): {list}', {
                  list: result.skipped_tables.join(', '),
                })}
              </p>
            )}
            <p className="muted small">
              {t('Осталось пустить эту панель на сервер: откройте «Ещё» → «Скрипт настройки» и выполните его на ноде, затем нажмите «Проверить».')}
            </p>
            <div className="modal-actions">
              <button onClick={onClose}>{t('Готово')}</button>
            </div>
          </>
        ) : (
          <>
            <p className="muted small">
              {t('Файл, выгруженный из другой панели через «Ещё» → «Выгрузить в файл». Существующие серверы не затрагиваются — добавится один новый.')}
            </p>
            <input ref={fileRef} type="file" accept=".json,application/json" />
            {error && <p className="form-error">{error}</p>}
            <div className="modal-actions">
              <button onClick={run} disabled={busy}>
                {busy ? t('Загружаем…') : t('Загрузить')}
              </button>
              <button className="ghost" onClick={onClose}>
                {t('Отмена')}
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  )
}
