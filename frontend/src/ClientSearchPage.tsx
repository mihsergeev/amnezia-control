import { useCallback, useState } from 'react'
import {
  ApiError,
  PROTOCOL_LABEL,
  revokeClientsBulk,
  searchClients,
  type ClientHit,
  type RevokeBulkResult,
} from './api'
import { useI18n } from './i18n'

type Props = { onUnauthorized: () => void }

function hitKey(h: ClientHit): string {
  return `${h.server_id}|${h.protocol}|${h.client_id}`
}

export function ClientSearchPage({ onUnauthorized }: Props) {
  const { t } = useI18n()
  const [query, setQuery] = useState('')
  const [hits, setHits] = useState<ClientHit[] | null>(null)
  const [picked, setPicked] = useState<Set<string>>(new Set())
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState<RevokeBulkResult | null>(null)
  // подтверждение: массовый отзыв необратим, поэтому спрашиваем явно
  const [confirming, setConfirming] = useState(false)

  const handleError = useCallback(
    (err: unknown) => {
      if (err instanceof ApiError && err.status === 401) return onUnauthorized()
      setError(err instanceof Error ? err.message : t('Неизвестная ошибка'))
    },
    [onUnauthorized, t],
  )

  async function run() {
    if (query.trim().length < 2) return
    setBusy(true)
    setResult(null)
    setConfirming(false)
    try {
      const found = await searchClients(query.trim())
      setHits(found)
      // по умолчанию отмечаем всё найденное — обычно отзывают целиком
      setPicked(new Set(found.map(hitKey)))
      setError(null)
    } catch (err) {
      handleError(err)
    } finally {
      setBusy(false)
    }
  }

  function toggle(h: ClientHit) {
    const k = hitKey(h)
    const next = new Set(picked)
    if (next.has(k)) next.delete(k)
    else next.add(k)
    setPicked(next)
  }

  async function revoke() {
    const items = (hits ?? [])
      .filter((h) => picked.has(hitKey(h)))
      .map((h) => ({
        server_id: h.server_id,
        protocol: h.protocol,
        client_id: h.client_id,
      }))
    if (!items.length) return
    setBusy(true)
    setConfirming(false)
    try {
      const res = await revokeClientsBulk(items, query.trim())
      setResult(res)
      // перечитываем: успешно отозванные из выдачи исчезнут
      const found = await searchClients(query.trim())
      setHits(found)
      setPicked(new Set(found.map(hitKey)))
      setError(null)
    } catch (err) {
      handleError(err)
    } finally {
      setBusy(false)
    }
  }

  const pickedCount = (hits ?? []).filter((h) => picked.has(hitKey(h))).length

  return (
    <section>
      <div className="page-head">
        <h2>{t('Поиск клиентов')}</h2>
      </div>

      <div className="card">
        <p className="muted">
          {t(
            'Сквозной поиск по всему парку: имена клиентов, заметки и открытые ключи со всех нод и протоколов. По имени и заметке — совпадение подстроки без учёта регистра; по ключу — точный фрагмент от 8 символов, с учётом регистра. Отзыв выполняется пакетно и параллельно по нодам, с поимённым отчётом: недоступный сервер не срывает операцию, его клиенты остаются в выдаче для повтора.',
          )}
        </p>
        <div className="row">
          <input
            autoFocus
            value={query}
            placeholder={t('Например: фамилия, имя устройства или часть ключа')}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && void run()}
          />
          <button onClick={run} disabled={busy || query.trim().length < 2}>
            {busy ? t('Ищу…') : t('Найти')}
          </button>
        </div>
      </div>

      {error && <p className="form-error">{error}</p>}

      {result && (
        <div className="card">
          <h3>{t('Результат отзыва')}</h3>
          <p>
            {t('Отозвано: {n}', { n: String(result.revoked) })}
            {result.failed > 0 && (
              <span className="form-error">
                {' · '}
                {t('не удалось: {n}', { n: String(result.failed) })}
              </span>
            )}
          </p>
          {result.items.some((i) => !i.ok) && (
            <ul className="muted small">
              {result.items
                .filter((i) => !i.ok)
                .map((i) => (
                  <li key={`${i.server_id}|${i.protocol}|${i.client_id}`}>
                    {i.server_name} · {PROTOCOL_LABEL[i.protocol] ?? i.protocol}:{' '}
                    {i.error}
                  </li>
                ))}
            </ul>
          )}
          {result.failed > 0 && (
            <p className="muted small">
              {t(
                'Клиенты, которых не удалось отозвать, остались в поиске — повторите, когда нода станет доступна.',
              )}
            </p>
          )}
        </div>
      )}

      {hits !== null && hits.length === 0 && (
        <div className="card">
          <p className="muted">{t('Ничего не найдено.')}</p>
        </div>
      )}

      {hits !== null && hits.length > 0 && (
        <>
          <div className="page-head">
            <span className="muted">
              {t('Найдено: {n}', { n: String(hits.length) })} ·{' '}
              {t('выбрано: {n}', { n: String(pickedCount) })}
            </span>
            <div className="page-head-actions">
              <button
                className="ghost"
                onClick={() =>
                  setPicked(
                    pickedCount === hits.length
                      ? new Set()
                      : new Set(hits.map(hitKey)),
                  )
                }
              >
                {pickedCount === hits.length ? t('Снять все') : t('Выбрать все')}
              </button>
              <button
                className="danger"
                disabled={busy || pickedCount === 0}
                onClick={() => setConfirming(true)}
              >
                {t('Отозвать выбранные')}
              </button>
            </div>
          </div>

          {confirming && (
            <div className="card">
              <p className="form-error">
                {t(
                  'Отозвать {n} доступ(ов)? Клиенты будут удалены с серверов — подключиться по старым конфигам станет нельзя. Отменить это нельзя.',
                  { n: String(pickedCount) },
                )}
              </p>
              <div className="row">
                <button className="danger" onClick={revoke} disabled={busy}>
                  {busy ? t('Отзываю…') : t('Да, отозвать')}
                </button>
                <button className="ghost" onClick={() => setConfirming(false)}>
                  {t('Отмена')}
                </button>
              </div>
            </div>
          )}

          <div className="table-card">
            <table>
              <thead>
                <tr>
                  <th></th>
                  <th>{t('Клиент')}</th>
                  <th>{t('Сервер')}</th>
                  <th>{t('Протокол')}</th>
                  <th>{t('Заметка')}</th>
                </tr>
              </thead>
              <tbody>
                {hits.map((h) => (
                  <tr key={hitKey(h)}>
                    <td>
                      <input
                        type="checkbox"
                        checked={picked.has(hitKey(h))}
                        onChange={() => toggle(h)}
                      />
                    </td>
                    <td>
                      {h.name || <span className="muted">{t('без имени')}</span>}
                      <div className="mono muted small">
                        {h.client_id.slice(0, 16)}…
                      </div>
                    </td>
                    <td>{h.server_name}</td>
                    <td className="muted">
                      {h.protocol_label || PROTOCOL_LABEL[h.protocol] || h.protocol}
                    </td>
                    <td className="muted small">{h.note}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </section>
  )
}
