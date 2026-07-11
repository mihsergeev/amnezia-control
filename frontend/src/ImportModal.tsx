import { useState } from 'react'
import { api, ApiError, type ImportResult } from './api'
import { useI18n } from './i18n'
import { useModalDismiss } from './useModalDismiss'

type Props = {
  onClose: () => void
  onDone: () => void
  onUnauthorized: () => void
}

type Tab = 'amnezia' | 'bulk'

export function ImportModal({ onClose, onDone, onUnauthorized }: Props) {
  const { t } = useI18n()
  const dismiss = useModalDismiss(onClose)
  const [tab, setTab] = useState<Tab>('amnezia')
  const [amneziaText, setAmneziaText] = useState('')
  const [bulkText, setBulkText] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [results, setResults] = useState<ImportResult[] | null>(null)

  function handleError(err: unknown) {
    if (err instanceof ApiError && err.status === 401) {
      onUnauthorized()
      return
    }
    setError(err instanceof Error ? err.message : t('Неизвестная ошибка'))
  }

  async function runAmnezia() {
    const links = amneziaText
      .split('\n')
      .map((l) => l.trim())
      .filter(Boolean)
    if (links.length === 0) return
    setBusy(true)
    setError(null)
    try {
      const res = await api<{ results: ImportResult[] }>('/api/import/amnezia', {
        method: 'POST',
        body: JSON.stringify({ links }),
      })
      setResults(res.results)
      onDone()
    } catch (err) {
      handleError(err)
    } finally {
      setBusy(false)
    }
  }

  async function runBulk() {
    if (!bulkText.trim()) return
    setBusy(true)
    setError(null)
    try {
      const res = await api<{ results: ImportResult[] }>('/api/import/bulk', {
        method: 'POST',
        body: JSON.stringify({ text: bulkText }),
      })
      setResults(res.results)
      onDone()
    } catch (err) {
      handleError(err)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="modal-backdrop" onClick={dismiss}>
      <div className="card modal modal-wide" onClick={(e) => e.stopPropagation()}>
        <div className="clients-head">
          <h3>{t('Импорт серверов')}</h3>
          <button className="ghost" onClick={onClose}>
            {t('Закрыть')}
          </button>
        </div>

        <div className="tabs">
          <button
            className={tab === 'amnezia' ? 'tab tab-active' : 'tab'}
            onClick={() => {
              setTab('amnezia')
              setResults(null)
            }}
          >
            {t('Из Amnezia (vpn://)')}
          </button>
          <button
            className={tab === 'bulk' ? 'tab tab-active' : 'tab'}
            onClick={() => {
              setTab('bulk')
              setResults(null)
            }}
          >
            {t('Списком')}
          </button>
        </div>

        {error && <p className="form-error">{error}</p>}

        {tab === 'amnezia' ? (
          <>
            <p className="muted small">
              {t('В клиенте Amnezia: на сервере «Поделиться» → ')}
              <b>{t('Полный доступ')}</b>
              {t(' → скопируйте ссылку ')}
              <span className="mono">vpn://…</span>
              {t(
                ' и вставьте сюда (можно несколько, по одной в строке). Панель извлечёт адрес и SSH-доступ и сама настроит сервер.',
              )}
            </p>
            <textarea
              className="import-area"
              placeholder="vpn://..."
              value={amneziaText}
              onChange={(e) => setAmneziaText(e.target.value)}
              rows={5}
            />
            <div className="modal-actions">
              <button onClick={runAmnezia} disabled={busy || !amneziaText.trim()}>
                {busy ? t('Импорт…') : t('Импортировать')}
              </button>
            </div>
          </>
        ) : (
          <>
            <p className="muted small">
              {t('По одной строке на сервер: ')}
              <span className="mono">{t('хост[:порт] пользователь пароль')}</span>
              {t(
                '. Пароль нужен для автонастройки; без него сервер добавится, но ключ поставите скриптом. Пример:',
              )}
            </p>
            <pre className="script-box">
              203.0.113.10 root MyPass123{'\n'}198.51.100.7:2222 acontrol Pass456
            </pre>
            <textarea
              className="import-area"
              placeholder={t('хост[:порт] пользователь пароль')}
              value={bulkText}
              onChange={(e) => setBulkText(e.target.value)}
              rows={5}
            />
            <div className="modal-actions">
              <button onClick={runBulk} disabled={busy || !bulkText.trim()}>
                {busy ? t('Импорт…') : t('Импортировать')}
              </button>
            </div>
          </>
        )}

        {results && (
          <div className="import-results">
            <h4>{t('Результат')}</h4>
            {results.map((r, i) => (
              <div key={i} className="import-row">
                <span className={`dot ${r.ok ? 'dot-ok' : 'dot-fail'}`} />
                <span className="import-host mono">{r.host}</span>
                <span className={r.ok ? 'muted small' : 'form-error'}>
                  {r.message}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
