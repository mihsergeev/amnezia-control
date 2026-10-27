import { useMemo, useState } from 'react'
import {
  ApiError,
  removeProtocol,
  revokeClientsBulk,
  type Protocol,
  type RevokeBulkResult,
} from './api'
import { StepUpModal } from './StepUpModal'
import { useI18n } from './i18n'

// Выбор клиентов галочками в таблице протокола. Ключи, которых после
// перезагрузки списка уже нет (клиента отозвали), из выбора выпадают сами.
export function useSelection(keys: string[]) {
  const [picked, setPicked] = useState<Set<string>>(new Set())
  const selected = useMemo(() => keys.filter((k) => picked.has(k)), [keys, picked])
  const all = keys.length > 0 && selected.length === keys.length
  return {
    selected,
    all,
    has: (k: string) => picked.has(k),
    toggle: (k: string) =>
      setPicked((prev) => {
        const next = new Set(prev)
        if (next.has(k)) next.delete(k)
        else next.add(k)
        return next
      }),
    toggleAll: () => setPicked(all ? new Set() : new Set(keys)),
    clear: () => setPicked(new Set()),
  }
}

export type Selection = ReturnType<typeof useSelection>

export function SelectAllCell({ sel }: { sel: Selection }) {
  return (
    <th className="check-col">
      <input type="checkbox" checked={sel.all} onChange={sel.toggleAll} />
    </th>
  )
}

export function SelectCell({ sel, id }: { sel: Selection; id: string }) {
  return (
    <td className="check-col">
      <input type="checkbox" checked={sel.has(id)} onChange={() => sel.toggle(id)} />
    </td>
  )
}

type BarProps = {
  serverId: number
  serverName: string
  protocol: string
  protocolLabel: string
  sel: Selection
  onDone: () => void
  onUnauthorized: () => void
}

// Панель над таблицей, когда отмечены клиенты: отозвать их одним действием.
export function BulkRevokeBar({
  serverId,
  serverName,
  protocol,
  protocolLabel,
  sel,
  onDone,
  onUnauthorized,
}: BarProps) {
  const { t } = useI18n()
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState<RevokeBulkResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const n = sel.selected.length

  async function revoke() {
    if (
      !window.confirm(
        t('Отозвать {n} доступ(ов)? Клиенты будут удалены с серверов — подключиться по старым конфигам станет нельзя. Отменить это нельзя.', {
          n: String(n),
        }),
      )
    )
      return
    setBusy(true)
    setError(null)
    try {
      const res = await revokeClientsBulk(
        sel.selected.map((id) => ({ server_id: serverId, protocol, client_id: id })),
        `${serverName} / ${protocolLabel}`,
      )
      setResult(res.failed > 0 ? res : null)
      sel.clear()
      onDone()
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) return onUnauthorized()
      setError(err instanceof Error ? err.message : t('Неизвестная ошибка'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      {n > 0 && (
        <div className="bulk-bar">
          <span className="muted">{t('выбрано: {n}', { n: String(n) })}</span>
          <button className="ghost" onClick={sel.clear} disabled={busy}>
            {t('Снять все')}
          </button>
          <button className="danger-solid" onClick={revoke} disabled={busy}>
            {busy ? t('Отзываю…') : t('Отозвать выбранные')}
          </button>
        </div>
      )}
      {error && <p className="form-error">{error}</p>}
      {result && (
        <div className="form-error">
          {t('Отозвано: {n}', { n: String(result.revoked) })}
          {' · '}
          {t('не удалось: {n}', { n: String(result.failed) })}
          <ul className="small">
            {result.items
              .filter((i) => !i.ok)
              .map((i) => (
                <li key={i.client_id}>
                  <span className="mono">{i.client_id.slice(0, 16)}...</span>: {i.error}
                </li>
              ))}
          </ul>
        </div>
      )}
    </>
  )
}

type RemoveProps = {
  serverId: number
  serverName: string
  protocol: Protocol
  onRemoved: () => void
  onUnauthorized: () => void
}

// Удаление протокола с ноды целиком, вместе со всеми клиентами. Внизу модалки,
// подальше от частых кнопок, и только после повторного ввода пароля.
export function RemoveProtocol({
  serverId,
  serverName,
  protocol,
  onRemoved,
  onUnauthorized,
}: RemoveProps) {
  const { t } = useI18n()
  const [asking, setAsking] = useState(false)

  function start() {
    if (
      !window.confirm(
        t('Удалить {proto} с сервера «{server}» вместе со ВСЕМИ его клиентами? Их конфиги перестанут работать. Перед удалением на ноде сохраняется снимок конфига.', {
          proto: protocol.label,
          server: serverName,
        }),
      )
    )
      return
    setAsking(true)
  }

  async function submit(password: string) {
    try {
      await removeProtocol(serverId, protocol.key, password)
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        onUnauthorized()
        return
      }
      throw err
    }
    setAsking(false)
    onRemoved()
  }

  return (
    <div className="danger-zone">
      <button className="ghost danger" onClick={start}>
        {t('Удалить протокол {proto}', { proto: protocol.label })}
      </button>
      {asking && (
        <StepUpModal
          text={t('Удаление {proto} с сервера «{server}». Все клиенты протокола потеряют доступ.', {
            proto: protocol.label,
            server: serverName,
          })}
          onSubmit={submit}
          onCancel={() => setAsking(false)}
        />
      )}
    </div>
  )
}
