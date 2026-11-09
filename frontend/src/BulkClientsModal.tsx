import { useEffect, useMemo, useRef, useState, type FormEvent } from 'react'
import {
  api, ApiError, downloadClientBatch, issueClientBatch, pendingClientBatch, revokeClientBatch,
  type AwgState, type BulkIssueRequest, type BulkIssueResult, type ClientProtocol,
  type OvpnState, type Protocol, type RevokeBulkResult, type XrayState,
} from './api'
import { cascadeRequestId } from './cascadeUi'
import { useI18n } from './i18n'
import { useModalDismiss } from './useModalDismiss'
import { useSelection } from './useSelection'

type Mode = 'issue' | 'export' | 'revoke'
type Status = 'all' | 'active' | 'paused'
type Client = { id: string; name: string; paused: boolean }
type ExportResult = Awaited<ReturnType<typeof downloadClientBatch>>

const ISSUE_PROTOCOLS: readonly ClientProtocol[] = ['awg3', 'wireguard', 'xray']
const LIMIT = { issue: 100, export: 1000, revoke: 100 }
const PRESETS = [10, 25, 50, 100]

function savedRequest(key: string): BulkIssueRequest | null {
  try {
    const value = JSON.parse(sessionStorage.getItem(key) ?? 'null') as BulkIssueRequest | null
    return value && typeof value.request_id === 'string' && typeof value.prefix === 'string'
      && Number.isInteger(value.count) && value.count > 0 && value.count <= LIMIT.issue
      ? value : null
  } catch {
    return null
  }
}

function saveRequest(key: string, request: BulkIssueRequest | null) {
  try {
    if (request) sessionStorage.setItem(key, JSON.stringify(request))
    else sessionStorage.removeItem(key)
  } catch {
    // Private browsing can disable storage. Retries in this window still reuse the request.
  }
}

async function listClients(serverId: number, protocol: ClientProtocol, signal: AbortSignal): Promise<Client[]> {
  const path = `/api/servers/${serverId}/${protocol === 'awglegacy' ? 'awg-legacy' : protocol}`
  if (protocol === 'xray' || protocol === 'openvpn' || protocol === 'openvpn-native') {
    const { clients } = await api<XrayState | OvpnState>(path, { signal })
    return clients.map((client) => ({ id: client.client_id, name: client.name, paused: !!client.paused }))
  }
  const { clients } = await api<AwgState>(path, { signal })
  return clients.map((client) => ({ id: client.public_key, name: client.name, paused: !!client.paused }))
}

type Props = {
  serverId: number
  serverName: string
  protocols: Protocol[]
  initialProtocol: ClientProtocol
  onChanged: () => void
  onClose: () => void
  onUnauthorized: () => void
}

export function BulkClientsModal({
  serverId, serverName, protocols, initialProtocol, onChanged, onClose, onUnauthorized,
}: Props) {
  const { t } = useI18n()
  const [protocol, setProtocol] = useState(initialProtocol)
  const [mode, setMode] = useState<Mode>(ISSUE_PROTOCOLS.includes(initialProtocol) ? 'issue' : 'export')
  const working = useRef(false)
  const dismiss = useModalDismiss(() => { if (!working.current) onClose() })
  const label = protocols.find(({ key }) => key === protocol)?.label ?? protocol

  return (
    <div className="modal-backdrop" onClick={dismiss}>
      <div className="card modal modal-wide client-batch" role="dialog" aria-modal="true" aria-labelledby="client-batch-title">
        <ClientBatchForm
          key={`${protocol}:${mode}`}
          serverId={serverId}
          serverName={serverName}
          protocols={protocols}
          protocol={protocol}
          label={label}
          mode={mode}
          onMode={setMode}
          onProtocol={(next) => {
            if (mode !== 'export' && !ISSUE_PROTOCOLS.includes(next)) setMode('export')
            setProtocol(next)
          }}
          working={working}
          onChanged={onChanged}
          onClose={onClose}
          onUnauthorized={onUnauthorized}
          title={t('Массовые операции с клиентами')}
        />
      </div>
    </div>
  )
}

function ClientBatchForm({
  serverId, serverName, protocols, protocol, label, mode, onMode, onProtocol, working,
  onChanged, onClose, onUnauthorized, title,
}: Omit<Props, 'initialProtocol'> & {
  protocol: ClientProtocol
  label: string
  mode: Mode
  onMode: (mode: Mode) => void
  onProtocol: (protocol: ClientProtocol) => void
  working: { current: boolean }
  title: string
}) {
  const { t } = useI18n()
  const storageKey = `acontrol_bulk_issue:${serverId}:${protocol}`
  const [pending, setPending] = useState(() => savedRequest(storageKey))
  const [pendingIds, setPendingIds] = useState<string[]>([])
  const [pendingChecked, setPendingChecked] = useState(false)
  const [prefix, setPrefix] = useState(pending?.prefix ?? '')
  const [count, setCount] = useState(String(pending?.count ?? 10))
  const [clients, setClients] = useState<Client[]>([])
  const [loading, setLoading] = useState(false)
  const [reload, setReload] = useState(0)
  const [query, setQuery] = useState('')
  const [status, setStatus] = useState<Status>('all')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [issued, setIssued] = useState<BulkIssueResult | null>(null)
  const [exported, setExported] = useState<ExportResult | null>(null)
  const [revoked, setRevoked] = useState<RevokeBulkResult | null>(null)
  const [revokeNames, setRevokeNames] = useState<Record<string, string>>({})

  const visible = useMemo(() => {
    const term = query.trim().toLowerCase()
    return clients.filter((client) =>
      (status === 'all' || client.paused === (status === 'paused'))
      && client.name.toLowerCase().includes(term),
    )
  }, [clients, query, status])
  const selection = useSelection(useMemo(() => visible.map(({ id }) => id), [visible]))

  function showError(err: unknown) {
    if (err instanceof ApiError && err.status === 401) onUnauthorized()
    else setError(err instanceof Error ? t(err.message) : t('Неизвестная ошибка'))
  }

  useEffect(() => {
    const controller = new AbortController()
    setLoading(true)
    const load = mode === 'issue'
      ? pendingClientBatch(serverId, protocol, controller.signal).then((saved) => {
        if (controller.signal.aborted) return
        setPendingIds(saved?.client_ids ?? [])
        if (saved) {
          const request = { request_id: saved.request_id, prefix: saved.prefix, count: saved.count }
          saveRequest(storageKey, request)
          setPending(request)
          setPrefix(request.prefix)
          setCount(String(request.count))
        }
        setPendingChecked(true)
      })
      : listClients(serverId, protocol, controller.signal).then((rows) => {
        if (!controller.signal.aborted) setClients(rows)
      })
    load.catch((err: unknown) => {
      if (controller.signal.aborted) return
      setClients([])
      setPendingIds([])
      setPendingChecked(false)
      if (err instanceof ApiError && err.status === 401) onUnauthorized()
      else setError(err instanceof Error ? t(err.message) : t('Неизвестная ошибка'))
    }).finally(() => {
      if (!controller.signal.aborted) setLoading(false)
    })
    return () => controller.abort()
  }, [mode, protocol, reload, serverId, storageKey, onUnauthorized, t])

  async function run(action: () => Promise<void>) {
    if (working.current) return
    working.current = true
    setBusy(true)
    setError('')
    try {
      await action()
    } catch (err) {
      showError(err)
    } finally {
      working.current = false
      setBusy(false)
    }
  }

  const requested = Number(count)
  const valid = prefix.trim() !== '' && Number.isInteger(requested)
    && requested >= 1 && requested <= LIMIT.issue
  const picked = selection.selected
  const limit = LIMIT[mode]
  const maxExceeded = picked.length > limit

  function issue(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!valid || !pendingChecked || loading || working.current || issued) return
    if (!window.confirm(t('Выдать {count} профилей {protocol} на сервере «{server}»?', {
      count, protocol: label, server: serverName,
    }))) return
    const request = pending ?? { request_id: cascadeRequestId(), prefix: prefix.trim(), count: requested }
    saveRequest(storageKey, request)
    setPending(request)
    void run(async () => {
      try {
        setIssued(await issueClientBatch(serverId, protocol, request))
        setPendingIds([])
        onChanged()
      } catch (err) {
        setReload((value) => value + 1)
        throw err
      }
    })
  }

  function resetIssue() {
    saveRequest(storageKey, null)
    setPending(null)
    setPendingIds([])
    setIssued(null)
    setExported(null)
    setRevoked(null)
    setPrefix('')
    setError('')
  }

  function cancelIssue() {
    if (!pendingIds.length || working.current) return
    if (!window.confirm(t('Отменить выдачу и отозвать {count} профилей из этой группы?', { count: pendingIds.length }))) return
    void run(async () => {
      const result = await revokeClientBatch(serverId, protocol, pendingIds)
      if (!result.failed) resetIssue()
      else setReload((value) => value + 1)
      setRevoked(result)
      onChanged()
    })
  }

  function download(ids: string[]) {
    if (!ids.length) return
    setExported(null)
    void run(async () => setExported(await downloadClientBatch(serverId, protocol, ids)))
  }

  function revoke() {
    if (!picked.length || maxExceeded || working.current) return
    const details = { count: picked.length, protocol: label, server: serverName }
    const message = protocol === 'xray'
      ? t('Отозвать {count} профилей {protocol} на сервере «{server}»? Новые подключения будут запрещены.', details)
      : t('Отозвать {count} профилей {protocol} на сервере «{server}»? Они потеряют доступ к VPN.', details)
    if (!window.confirm(message)) return
    const names = Object.fromEntries(visible.map((client) => [client.id, client.name]))
    setRevoked(null)
    void run(async () => {
      const result = await revokeClientBatch(serverId, protocol, picked)
      setRevokeNames(names)
      setRevoked(result)
      const succeeded = new Set(result.items.filter((item) => item.ok).map((item) => item.client_id))
      setClients((rows) => rows.filter((row) => !succeeded.has(row.id)))
      setReload((value) => value + 1)
      onChanged()
    })
  }

  return (
    <>
      <div className="clients-head client-batch-head">
        <h3 id="client-batch-title">{title}</h3>
        <button className="ghost" onClick={onClose} disabled={busy}>{t('Закрыть')}</button>
      </div>
      <label className="client-batch-field">
        {t('Протокол')}
        <select aria-label={t('Протокол')} value={protocol} onChange={(event) => onProtocol(event.target.value as ClientProtocol)} disabled={busy}>
          {protocols.map(({ key, label: option }) => <option key={key} value={key}>{option}</option>)}
        </select>
      </label>
      <div className="tabs client-batch-tabs">
        {([
          ['issue', t('Выдача')],
          ['export', t('Экспорт')],
          ['revoke', t('Отзыв')],
        ] as const).map(([key, name]) => (
          <button
            key={key}
            className={mode === key ? 'tab tab-active' : 'tab'}
            aria-pressed={mode === key}
            onClick={() => onMode(key)}
            disabled={busy || (key !== 'export' && !ISSUE_PROTOCOLS.includes(protocol))}
          >{name}</button>
        ))}
      </div>
      {mode === 'issue' ? (
        <form className="client-batch-form" onSubmit={issue}>
          <div className="client-batch-fields">
            <label className="client-batch-field">
              {t('Префикс имени')}
              <input value={prefix} onChange={(event) => setPrefix(event.target.value)} placeholder="Client" maxLength={124} required disabled={busy || loading || !!pending} />
            </label>
            <label className="client-batch-field">
              {t('Количество')}
              <input type="number" min={1} max={LIMIT.issue} value={count} onChange={(event) => setCount(event.target.value)} required disabled={busy || loading || !!pending} />
            </label>
          </div>
          <div className="client-batch-buttons">
            {PRESETS.map((value) => (
              <button type="button" className="ghost" key={value} aria-pressed={requested === value}
                onClick={() => setCount(String(value))} disabled={busy || loading || !!pending}>{value}</button>
            ))}
          </div>
          <p className="muted small">{t('Имена профилей будут пронумерованы, например Client-001 и Client-002.')}</p>
          {pending && !issued && (
            <p className="muted small">{t('Повтор выдачи продолжит тот же запрос с теми же именами и ключами.')}</p>
          )}
          {issued && (
            <p role="status">{t('Выдано {count} из {total} профилей.', { count: issued.items.length, total: requested })}
              {issued.cancelled > 0 && <> {t('Отменено {count}.', { count: issued.cancelled })}</>}
            </p>
          )}
          <div className="modal-actions client-batch-buttons">
            {!loading && !pendingChecked && (
              <button type="button" className="ghost" onClick={() => { setError(''); setReload((value) => value + 1) }} disabled={busy}>{t('Проверить еще раз')}</button>
            )}
            {pendingIds.length > 0 && !issued && <button type="button" className="ghost" onClick={cancelIssue} disabled={busy || loading}>{t('Отменить выдачу')}</button>}
            {pending && (issued || (pendingChecked && !pendingIds.length)) && (
              <button type="button" className="ghost" onClick={resetIssue} disabled={busy || loading}>{t('Новая выдача')}</button>
            )}
            {issued ? (
              <button type="button" disabled={busy || issued.items.length === 0} onClick={() => download(issued.items.map((item) => item.client_id))}>{t('Скачать ZIP')}</button>
            ) : (
              <button type="submit" disabled={busy || loading || !pendingChecked || !valid}>{pending ? t('Повторить выдачу') : t('Выдать профили')}</button>
            )}
          </div>
        </form>
      ) : (
        <>
          <div className="client-batch-fields">
            <label className="client-batch-field">
              {t('Поиск по имени')}
              <input value={query} onChange={(event) => { selection.clear(); setQuery(event.target.value) }} disabled={busy} />
            </label>
            <label className="client-batch-field">
              {t('Статус')}
              <select aria-label={t('Статус')} value={status} onChange={(event) => { selection.clear(); setStatus(event.target.value as Status) }} disabled={busy}>
                <option value="all">{t('Все')}</option>
                <option value="active">{t('Активные')}</option>
                <option value="paused">{t('На паузе')}</option>
              </select>
            </label>
          </div>
          <div className="client-batch-buttons">
            <button className="ghost" disabled={busy || loading || !visible.length} onClick={selection.toggleAll}>
              {selection.all ? t('Снять все') : t('Выбрать всех в списке')}
            </button>
            <button className="ghost" disabled={busy || loading} onClick={() => { setError(''); setReload((value) => value + 1) }}>
              {t('Обновить список')}
            </button>
            <span className="muted small">{t('выбрано: {n}', { n: picked.length })}</span>
          </div>
          <div className="client-batch-list" aria-busy={loading}>
            {visible.map(({ id, name, paused }) => (
              <label key={id} className="client-batch-row">
                <input type="checkbox" checked={selection.has(id)} onChange={() => selection.toggle(id)} disabled={busy || loading} />
                <span className="client-batch-name" title={name}>{name}</span>
                {paused && <span className="pause-badge">{t('На паузе')}</span>}
              </label>
            ))}
            {!visible.length && <p className="muted small">{loading ? t('Загрузка…') : t('Ничего не найдено.')}</p>}
          </div>
          {maxExceeded && <p className="form-error">{t('За одну операцию можно выбрать до {limit} профилей.', { limit })}</p>}
          {protocol === 'xray' && mode === 'export' && <p className="muted small">{t('Профили Xray собираются по текущим настройкам сервера.')}</p>}
          {protocol === 'xray' && mode === 'revoke' && <p className="muted small">{t('Отзыв Xray запрещает новые подключения. Открытые соединения работают до закрытия.')}</p>}
          <div className="modal-actions client-batch-buttons">
            {mode === 'export' ? (
              <button disabled={busy || loading || maxExceeded || !picked.length} onClick={() => {
                if (window.confirm(t('Скачать ZIP с конфигурациями {count} клиентов?', { count: picked.length }))) download(picked)
              }}>{t('Скачать ZIP')}</button>
            ) : (
              <button className="danger-solid" disabled={busy || loading || maxExceeded || !picked.length} onClick={revoke}>{t('Отозвать выбранные')}</button>
            )}
          </div>
        </>
      )}
      {busy && <p className="muted small" role="status">{t('Операция выполняется…')}</p>}
      {error && <p className="form-error" role="alert">{error}</p>}
      {exported && (
        <p role="status">{t('В ZIP {count} профилей. Пропущено {missing}. Подробности в manifest.json.', {
          count: exported.exported, missing: exported.missing,
        })}</p>
      )}
      {revoked && (
        <div role="status">
          <p>{t('Отозвано {count}. Ошибок {failed}.', { count: revoked.revoked, failed: revoked.failed })}</p>
          {revoked.failed > 0 && <ul className="small">
            {revoked.items.filter((item) => !item.ok).map((item) => (
              <li key={item.client_id}>{revokeNames[item.client_id] ?? item.client_id} · {t(item.error)}</li>
            ))}
          </ul>}
        </div>
      )}
    </>
  )
}
