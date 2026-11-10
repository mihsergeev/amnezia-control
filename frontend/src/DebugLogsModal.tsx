import { useEffect, useRef, useState } from 'react'
import { ApiError, downloadDebugLogs, getDebugLogs } from './api'
import { DEBUG_OPERATIONS, type DebugLogLevel, type DebugLogsResponse } from './debugLogs'
import { useI18n } from './i18n'
import { useModalDismiss } from './useModalDismiss'

export function DebugLogsModal({ onClose, onUnauthorized }: {
  onClose: () => void
  onUnauthorized: () => void
}) {
  const { t, lang } = useI18n()
  const dismiss = useModalDismiss(onClose)
  const [level, setLevel] = useState<DebugLogLevel | ''>('')
  const [operation, setOperation] = useState('')
  const [operations, setOperations] = useState<string[]>(Object.keys(DEBUG_OPERATIONS))
  const [data, setData] = useState<DebugLogsResponse | null>(null)
  const [refresh, setRefresh] = useState(0)
  const [loading, setLoading] = useState(true)
  const [downloading, setDownloading] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const downloadRequest = useRef<AbortController | null>(null)

  useEffect(() => () => downloadRequest.current?.abort(), [])

  useEffect(() => {
    const controller = new AbortController()
    setLoading(true)
    setData(null)
    setError('')
    setNotice('')
    getDebugLogs({ level, operation }, controller.signal)
      .then((result) => {
        if (controller.signal.aborted) return
        setData(result)
        setOperations((previous) => [...new Set([...previous, ...result.events.map((event) => event.operation)])].sort())
      })
      .catch((err: unknown) => {
        if (controller.signal.aborted) return
        if (err instanceof ApiError && err.status === 401) onUnauthorized()
        else setError('Не удалось загрузить дебаг-логи. Повторите попытку.')
      })
      .finally(() => { if (!controller.signal.aborted) setLoading(false) })
    return () => controller.abort()
  }, [level, operation, refresh, onUnauthorized])

  async function download() {
    const controller = new AbortController()
    downloadRequest.current = controller
    setDownloading(true)
    setError('')
    setNotice('')
    try {
      await downloadDebugLogs({ level, operation }, controller.signal)
      if (!controller.signal.aborted) setNotice('ZIP готов. Передайте его в поддержку вместе с описанием проблемы.')
    } catch (err) {
      if (controller.signal.aborted) return
      if (err instanceof ApiError && err.status === 401) onUnauthorized()
      else setError('Не удалось скачать дебаг-логи. Повторите попытку.')
    } finally {
      if (!controller.signal.aborted) setDownloading(false)
    }
  }

  async function copyId(value: string) {
    try {
      await navigator.clipboard.writeText(value)
      setNotice('Идентификатор скопирован.')
    } catch {
      setNotice('Не удалось скопировать. Выделите идентификатор и скопируйте вручную.')
    }
  }

  const levelLabel = (value: DebugLogLevel) => value === 'error' ? t('Ошибка') : value === 'warning' ? t('Предупреждение') : t('Информация')

  return (
    <div className="modal-backdrop" onClick={dismiss}>
      <section className="card modal modal-wide debug-logs-modal" role="dialog" aria-modal="true" aria-labelledby="debug-logs-title" aria-describedby="debug-logs-description">
        <div className="clients-head">
          <h3 id="debug-logs-title">{t('Дебаг-логи')}</h3>
          <button className="ghost" onClick={onClose}>{t('Закрыть')}</button>
        </div>
        <p id="debug-logs-description" className="muted">{t('События операций помогают выяснить причину сбоя установки и других действий. ZIP можно передать в поддержку: в нем только обезличенные события, без конфигураций, исходных логов и секретов.')}</p>
        <div className="debug-logs-toolbar">
          <label className="field">
            <span>{t('Уровень')}</span>
            <select aria-label={t('Уровень')} value={level} onChange={(event) => setLevel(event.currentTarget.value as DebugLogLevel | '')}>
              <option value="">{t('Все уровни')}</option>
              <option value="error">{t('Ошибки')}</option>
              <option value="warning">{t('Предупреждения')}</option>
              <option value="info">{t('Информация')}</option>
            </select>
          </label>
          <label className="field">
            <span>{t('Операция')}</span>
            <select aria-label={t('Операция')} value={operation} onChange={(event) => setOperation(event.currentTarget.value)}>
              <option value="">{t('Все операции')}</option>
              {operations.map((value) => <option key={value} value={value}>{t(DEBUG_OPERATIONS[value] || value)}</option>)}
            </select>
          </label>
          <button className="ghost" onClick={() => setRefresh((value) => value + 1)} disabled={loading}>{t('Обновить')}</button>
          <button className="primary" onClick={() => void download()} disabled={downloading}>{downloading ? t('Операция выполняется…') : t('Скачать ZIP')}</button>
        </div>
        <p className="muted small">{t('Показаны последние 200 событий по выбранным фильтрам. ZIP содержит все сохраненные события с этими фильтрами.')}</p>
        {data && <p className="muted small">{t('Хранение: до {days} дней, общий объем до {size} МБ.', { days: data.retention_days, size: Math.round(data.max_bytes / 1024 / 1024) })}</p>}
        {error && <p className="form-error" role="alert">{t(error)}</p>}
        {notice && <p className="muted" role="status">{t(notice)}</p>}
        <div className="debug-logs-events" aria-busy={loading}>
          {loading && <p className="muted" role="status">{t('Загрузка…')}</p>}
          {!loading && data?.events.length === 0 && <p className="muted" role="status">{t('Событий по выбранным фильтрам пока нет. Повторите действие с ошибкой и обновите список.')}</p>}
          {data?.events.map((event) => {
            const date = new Date(event.timestamp)
            const timestamp = Number.isNaN(date.getTime()) ? event.timestamp : date.toLocaleString(lang === 'ru' ? 'ru-RU' : 'en-GB')
            return (
              <details key={event.id} className={`debug-log-event debug-log-${event.level}`}>
                <summary tabIndex={0}>
                  <span className="debug-log-meta">
                    <time dateTime={event.timestamp}>{timestamp}</time>
                    <span className="debug-log-level">{levelLabel(event.level)}</span>
                    <span>{t(DEBUG_OPERATIONS[event.operation] || event.operation)}</span>
                    {event.protocol && <span>{event.protocol}</span>}
                    <code>{event.code}</code>
                  </span>
                  <span className="debug-log-summary">{t(event.summary)}</span>
                </summary>
                <div className="debug-log-details">
                  {event.stage && <p>{t('Этап')}: <code>{event.stage}</code></p>}
                  {event.server_id != null && <p>{t('ID сервера')}: <code>{event.server_id}</code></p>}
                  {event.correlation_id && <div className="debug-log-correlation"><span>{t('Идентификатор операции')}: <code>{event.correlation_id}</code></span><button className="ghost" onClick={() => void copyId(event.correlation_id!)}>{t('Копировать')}</button></div>}
                  {Boolean(event.locations?.length) && <div><p>{t('Место ошибки')}</p><ul>{event.locations!.map((location, index) => <li key={index}><code>{location.module}:{location.line} · {location.function}</code></li>)}</ul></div>}
                </div>
              </details>
            )
          })}
        </div>
      </section>
    </div>
  )
}
