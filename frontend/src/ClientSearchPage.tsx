import { useCallback, useState } from 'react'
import {
  api,
  ApiError,
  PROTOCOL_LABEL,
  parseCheckInfo,
  pauseClient,
  protocolsFromContainers,
  revokeClientsBulk,
  searchClients,
  type ClientHit,
  type Protocol,
  type RevokeBulkResult,
  type Server,
} from './api'
import { ClientsModal } from './ClientsModal'
import { useI18n } from './i18n'

type Props = { onUnauthorized: () => void }

function hitKey(h: ClientHit): string {
  return `${h.server_id}|${h.protocol}|${h.client_id}`
}

// протокол клиента -> путь API возобновления
const RESUME_PATH: Record<string, 'awg' | 'awg-legacy' | 'awg3' | 'xray' | 'openvpn'> = {
  awg: 'awg',
  awg3: 'awg3',
  awglegacy: 'awg-legacy',
  xray: 'xray',
  openvpn: 'openvpn',
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
  // что показано: результат поиска или список клиентов на паузе
  const [pausedMode, setPausedMode] = useState(false)
  const [resuming, setResuming] = useState<string | null>(null)
  // карточка клиента: окно клиентов его сервера, где показан только он
  const [opened, setOpened] = useState<{ hit: ClientHit; server: Server } | null>(null)

  const handleError = useCallback(
    (err: unknown) => {
      if (err instanceof ApiError && err.status === 401) return onUnauthorized()
      setError(err instanceof Error ? err.message : t('Неизвестная ошибка'))
    },
    [onUnauthorized, t],
  )

  async function run(paused = false) {
    if (!paused && query.trim().length < 2) return
    setBusy(true)
    setResult(null)
    setConfirming(false)
    try {
      const found = await searchClients(query.trim(), paused)
      setHits(found)
      setPausedMode(paused)
      // по умолчанию отмечаем все найденное - обычно отзывают целиком. Список
      // пауз открывают посмотреть, его не отмечаем
      setPicked(paused ? new Set() : new Set(found.map(hitKey)))
      setError(null)
    } catch (err) {
      handleError(err)
    } finally {
      setBusy(false)
    }
  }

  async function resume(h: ClientHit) {
    const path = RESUME_PATH[h.protocol]
    if (!path) return
    setResuming(hitKey(h))
    setError(null)
    try {
      await pauseClient(h.server_id, path, h.client_id, true)
      setHits((cur) =>
        pausedMode
          ? (cur ?? []).filter((x) => hitKey(x) !== hitKey(h))
          : (cur ?? []).map((x) => (hitKey(x) === hitKey(h) ? { ...x, paused: false } : x)),
      )
    } catch (err) {
      handleError(err)
    } finally {
      setResuming(null)
    }
  }

  async function open(h: ClientHit) {
    setError(null)
    try {
      const server = await api<Server>(`/api/servers/${h.server_id}`)
      setOpened({ hit: h, server })
    } catch (err) {
      handleError(err)
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
      const found = await searchClients(query.trim(), pausedMode)
      setHits(found)
      setPicked(pausedMode ? new Set() : new Set(found.map(hitKey)))
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
        <div className="toolbar">
          <input
            autoFocus
            className="search-box"
            value={query}
            placeholder={t('Имя клиента, заметка или ключ')}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && void run()}
          />
          <button onClick={() => void run()} disabled={busy || query.trim().length < 2}>
            {busy ? t('Ищу…') : t('Найти')}
          </button>
          <button
            className="ghost"
            onClick={() => void run(true)}
            disabled={busy}
            title={t('Все клиенты на паузе по всем серверам; запрос в поле сужает список')}
          >
            {t('⏸ На паузе')}
          </button>
        </div>
        <p className="muted small">
          {t('По всем серверам и протоколам сразу. Найденное можно отозвать одним действием.')}
        </p>
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
          <p className="muted">
            {pausedMode ? t('Клиентов на паузе нет.') : t('Ничего не найдено.')}
          </p>
        </div>
      )}

      {hits !== null && hits.length > 0 && (
        <>
          <div className="page-head">
            <span className="muted">
              {pausedMode
                ? t('На паузе: {n}', { n: String(hits.length) })
                : t('Найдено: {n}', { n: String(hits.length) })}{' '}
              ·{' '}
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
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {hits.map((h) => (
                  <tr
                    key={hitKey(h)}
                    className="row-link"
                    title={t('Нажмите на строку, чтобы открыть клиента')}
                    onClick={() => void open(h)}
                  >
                    <td onClick={(e) => e.stopPropagation()}>
                      <input
                        type="checkbox"
                        checked={picked.has(hitKey(h))}
                        onChange={() => toggle(h)}
                      />
                    </td>
                    <td>
                      {h.name || <span className="muted">{t('без имени')}</span>}
                      {h.paused && <span className="pause-badge">{t('⏸ пауза')}</span>}
                      {h.paused && h.paused_at && (
                        <div className="muted small">
                          {t('на паузе с {at}', {
                            at: new Date(h.paused_at).toLocaleString(),
                          })}
                        </div>
                      )}
                      <div className="mono muted small">
                        {h.client_id.slice(0, 16)}…
                      </div>
                    </td>
                    <td>{h.server_name}</td>
                    <td className="muted">
                      {h.protocol_label || PROTOCOL_LABEL[h.protocol] || h.protocol}
                    </td>
                    <td className="muted small">{h.note}</td>
                    <td onClick={(e) => e.stopPropagation()}>
                      {h.paused && RESUME_PATH[h.protocol] && (
                        <button
                          className="ghost"
                          disabled={resuming !== null}
                          onClick={() => void resume(h)}
                        >
                          {resuming === hitKey(h) ? t('Возобновляю…') : t('Возобновить')}
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {opened && (
        <ClientsModal
          server={opened.server}
          protocols={protocolsFromContainers(
            parseCheckInfo(opened.server)?.amnezia_containers ?? [],
            parseCheckInfo(opened.server)?.protocols ?? {},
          )}
          initialProtocol={opened.hit.protocol as Protocol['key']}
          focusClient={opened.hit.client_id}
          onClose={() => {
            setOpened(null)
            // в карточке могли переименовать, поставить на паузу или отозвать
            if (pausedMode || query.trim().length >= 2) void run(pausedMode)
          }}
          onUnauthorized={onUnauthorized}
        />
      )}
    </section>
  )
}
