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

/** Заголовок окна: длинное имя сервера отдельной строкой, чтобы оно не
 *  распихивало кнопку «Закрыть» и не ломало шапку на две строки. */
function TransferHead({
  title,
  subtitle,
  onClose,
}: {
  title: string
  subtitle?: string
  onClose: () => void
}) {
  const { t } = useI18n()
  return (
    <div className="clients-head transfer-head">
      <div className="transfer-title">
        <h3>{title}</h3>
        {subtitle && <span className="transfer-subtitle">{subtitle}</span>}
      </div>
      <button className="ghost" onClick={onClose}>
        {t('Закрыть')}
      </button>
    </div>
  )
}

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
        <TransferHead
          title={t('Выгрузить сервер')}
          subtitle={server.name}
          onClose={onClose}
        />

        <div className="transfer-section">
          <span className="transfer-label">{t('В файл уедет')}</span>
          <ul className="transfer-list">
            <li>{t('карточка сервера — адрес, доступ, группа')}</li>
            <li>{t('сохранённые конфиги клиентов')}</li>
            <li>{t('заметки, сроки действия и паузы')}</li>
          </ul>
          <p className="muted small transfer-tail">
            {t('Живых клиентов новая панель прочитает с самого сервера.')}
          </p>
        </div>

        <div className="transfer-note transfer-note-danger">
          {t('Внутри — приватные ключи клиентов. Храните файл как бэкап.')}
        </div>

        <label className="checkbox transfer-check">
          <input
            type="checkbox"
            checked={history}
            onChange={(e) => setHistory(e.target.checked)}
          />
          <span>{t('Включить историю трафика')}</span>
        </label>
        <p className="muted small transfer-hint">
          {t('На активной ноде это сотни тысяч строк: файл вырастет с килобайтов до сотен мегабайт. Новая панель наберёт историю заново.')}
        </p>

        <p className="muted small transfer-foot">
          {t('SSH-ключ панели в файл не попадает — он общий для всех ваших нод. Новая панель ходит своим ключом, её нужно будет пустить на сервер скриптом настройки.')}
        </p>

        {error && <p className="form-error">{error}</p>}

        <div className="modal-actions">
          <button className="ghost" onClick={onClose}>
            {t('Отмена')}
          </button>
          <button onClick={run} disabled={busy}>
            {busy ? t('Готовим…') : t('Скачать файл')}
          </button>
        </div>
      </div>
    </div>
  )
}

// Имена таблиц — внутренние; в окне показываем то, что человек узнаёт
const TABLE_LABELS: Record<string, string> = {
  awg_configs: 'сохранённые конфиги',
  ovpn_configs: 'конфиги OpenVPN',
  awg_notes: 'заметки',
  client_limits: 'сроки действия',
  client_names: 'имена клиентов',
  paused_clients: 'клиенты на паузе',
  traffic_samples: 'история трафика сервера',
  client_traffic_samples: 'история трафика клиентов',
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
  const [fileName, setFileName] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<ServerImportResult | null>(null)

  async function run() {
    const file = fileRef.current?.files?.[0]
    if (!file) {
      setError(t('Сначала выберите файл выгрузки'))
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
        <TransferHead
          title={t('Загрузить сервер из файла')}
          subtitle={result ? result.name : undefined}
          onClose={onClose}
        />

        {result ? (
          <>
            <div className="transfer-note transfer-note-ok">
              {t('Сервер «{name}» ({host}) добавлен.', {
                name: result.name,
                host: result.host,
              })}
            </div>

            {rows.length > 0 && (
              <div className="transfer-section">
                <span className="transfer-label">{t('Принято')}</span>
                <ul className="transfer-counts">
                  {rows.map(([table, n]) => (
                    <li key={table}>
                      <span>{t(TABLE_LABELS[table] ?? table)}</span>
                      <b>{n}</b>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {result.skipped_tables.length > 0 && (
              <div className="transfer-note transfer-note-danger">
                {t('Не удалось принять таблицы (файл из более новой панели): {list}', {
                  list: result.skipped_tables.join(', '),
                })}
              </div>
            )}

            <div className="transfer-section">
              <span className="transfer-label">{t('Что дальше')}</span>
              <ol className="transfer-list">
                <li>{t('«Ещё» → «Скрипт настройки» и выполнить его на сервере')}</li>
                <li>{t('«Ещё» → «Проверить» — панель подключится и покажет клиентов')}</li>
              </ol>
            </div>

            <div className="modal-actions">
              <button onClick={onClose}>{t('Готово')}</button>
            </div>
          </>
        ) : (
          <>
            <p className="muted small">
              {t('Файл, выгруженный из другой панели через «Ещё» → «Выгрузить в файл». Существующие серверы не затрагиваются — добавится один новый.')}
            </p>

            <div className="file-pick">
              <button className="ghost" onClick={() => fileRef.current?.click()}>
                {t('Выбрать файл')}
              </button>
              <span className={fileName ? 'file-pick-name' : 'muted small'}>
                {fileName || t('файл не выбран')}
              </span>
              <input
                ref={fileRef}
                type="file"
                accept=".json,application/json"
                hidden
                onChange={(e) => {
                  setFileName(e.target.files?.[0]?.name ?? '')
                  setError(null)
                }}
              />
            </div>

            {error && <p className="form-error">{error}</p>}

            <div className="modal-actions">
              <button className="ghost" onClick={onClose}>
                {t('Отмена')}
              </button>
              <button onClick={run} disabled={busy || !fileName}>
                {busy ? t('Загружаем…') : t('Загрузить')}
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  )
}
