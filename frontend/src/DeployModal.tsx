import { useEffect, useRef, useState } from 'react'
import { api, ApiError, type DeployStatus } from './api'
import { useI18n } from './i18n'

type Props = {
  serverId: number
  serverName: string
  mode: 'deploy' | 'update'
  protocol?: 'awg' | 'xray'
  onClose: () => void
  onDone: () => void
  onUnauthorized: () => void
}

export function DeployModal({
  serverId,
  serverName,
  mode,
  protocol = 'awg',
  onClose,
  onDone,
  onUnauthorized,
}: Props) {
  const { t } = useI18n()
  const label = protocol === 'xray' ? 'XRay' : 'AmneziaWG'
  const [status, setStatus] = useState<DeployStatus | null>(null)
  const [error, setError] = useState<string | null>(null)
  const startedRef = useRef(false)

  useEffect(() => {
    if (startedRef.current) return
    startedRef.current = true
    let alive = true
    let timer: number | undefined

    function handleError(err: unknown) {
      if (err instanceof ApiError && err.status === 401) {
        onUnauthorized()
        return
      }
      setError(err instanceof Error ? err.message : t('Ошибка'))
    }

    async function poll() {
      if (!alive) return
      try {
        const s = await api<DeployStatus>(
          `/api/servers/${serverId}/${protocol}/deploy/status`,
        )
        if (!alive) return
        setStatus(s)
        if (s.state === 'done') {
          onDone()
          return
        }
        if (s.state === 'error') return
      } catch (err) {
        handleError(err)
        return
      }
      timer = window.setTimeout(poll, 3000)
    }

    async function start() {
      try {
        const path =
          mode === 'update'
            ? `/api/servers/${serverId}/${protocol}/update`
            : `/api/servers/${serverId}/${protocol}/deploy`
        const deployBody =
          protocol === 'xray' ? JSON.stringify({ port: 443 }) : JSON.stringify({ port: 47180 })
        await api(path, {
          method: 'POST',
          body: mode === 'deploy' ? deployBody : undefined,
        })
      } catch (err) {
        handleError(err)
        return
      }
      timer = window.setTimeout(poll, 2500)
    }

    void start()
    return () => {
      alive = false
      if (timer) window.clearTimeout(timer)
    }
  }, [serverId, mode, protocol, onDone, onUnauthorized])

  const running = !error && (!status || status.state === 'running' || status.state === 'unknown')
  const done = status?.state === 'done'
  const failed = status?.state === 'error'

  const title =
    mode === 'update'
      ? t('Обновление {label}', { label })
      : t('Установка {label}', { label })

  return (
    <div className="modal-backdrop">
      <div className="card modal modal-wide" onClick={(e) => e.stopPropagation()}>
        <div className="clients-head">
          <h3>
            {title} · {serverName}
          </h3>
          <button className="ghost" onClick={onClose}>
            {t('Закрыть')}
          </button>
        </div>

        <p className="muted small">
          {mode === 'update'
            ? t('Сервер тянет свежий базовый образ и пересобирает контейнер. Клиенты и ключи сохраняются.')
            : protocol === 'xray'
              ? t('Сервер собирает образ Xray-core (alpine) и запускает VLESS+REALITY на 443. Это займёт 1–3 минуты.')
              : t('Сервер собирает образ из amneziavpn/amneziawg-go:latest и запускает AmneziaWG. Это займёт 1–3 минуты.')}
        </p>

        <div className="deploy-state">
          {running && <span className="deploy-spinner">{t('● выполняется…')}</span>}
          {done && <span className="status-ok">{t('✓ готово')}</span>}
          {failed && <span className="status-fail">{t('✗ ошибка (см. лог)')}</span>}
        </div>

        {error && <p className="form-error">{error}</p>}

        <pre className="script-box deploy-log">
          {status?.log || t('запуск…')}
        </pre>

        <div className="modal-actions">
          <button onClick={onClose}>{done ? t('Готово') : t('Закрыть')}</button>
        </div>
        {running && (
          <p className="muted small">
            {t('Можно закрыть окно — процесс продолжится на сервере.')}
          </p>
        )}
      </div>
    </div>
  )
}
