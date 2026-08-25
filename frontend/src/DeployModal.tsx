import { useCallback, useEffect, useRef, useState } from 'react'
import { api, ApiError, type DeployStatus } from './api'
import { useI18n } from './i18n'
import { useModalDismiss } from './useModalDismiss'

type Props = {
  serverId: number
  serverName: string
  mode: 'deploy' | 'update' | 'adopt'
  protocol?: 'awg' | 'awg3' | 'xray' | 'openvpn'
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
  const dismiss = useModalDismiss(onClose)
  const label =
    protocol === 'xray'
      ? 'XRay'
      : protocol === 'openvpn'
        ? 'OpenVPN/Cloak'
        : protocol === 'awg3'
          ? 'AmneziaWG 3.1'
          : 'AmneziaWG'
  const [status, setStatus] = useState<DeployStatus | null>(null)
  const [error, setError] = useState<string | null>(null)
  // Порт по умолчанию СВОЙ у каждого протокола: у 3.0 он обязан отличаться от
  // 2.0, иначе установка целилась бы в порт работающего сервера и упиралась в
  // защиту (а раньше — снесла бы его контейнер вместе с клиентами).
  const defaultPort =
    protocol === 'xray' ? 443 : protocol === 'openvpn' ? 8443 : protocol === 'awg3' ? 47300 : 47180
  const [port, setPort] = useState(defaultPort)
  // порт занят другим контейнером — предлагаем выбрать свободный и повторить
  const [portBusy, setPortBusy] = useState(false)
  const startedRef = useRef(false)
  const aliveRef = useRef(true)
  const timerRef = useRef<number | undefined>(undefined)

  const handleError = useCallback(
    (err: unknown) => {
      if (err instanceof ApiError && err.status === 401) {
        onUnauthorized()
        return
      }
      // 409 от развёртывания = порт занят другим контейнером: показываем поле
      // выбора порта, чтобы можно было повторить, а не упираться в тупик
      if (err instanceof ApiError && err.status === 409) {
        setPortBusy(true)
        // подставляем соседний порт, чтобы не пришлось придумывать самому
        setPort((prev) => (prev >= 65535 ? prev : prev + 1))
      }
      setError(err instanceof Error ? err.message : t('Ошибка'))
    },
    [onUnauthorized, t],
  )

  const poll = useCallback(async () => {
    if (!aliveRef.current) return
    try {
      const s = await api<DeployStatus>(
        `/api/servers/${serverId}/${protocol}/deploy/status`,
      )
      if (!aliveRef.current) return
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
    timerRef.current = window.setTimeout(() => void poll(), 3000)
  }, [serverId, protocol, onDone, handleError])

  const start = useCallback(
    async (p: number) => {
      setError(null)
      setPortBusy(false)
      try {
        const path =
          mode === 'update'
            ? `/api/servers/${serverId}/${protocol}/update`
            : mode === 'adopt'
              ? `/api/servers/${serverId}/${protocol}/adopt`
              : `/api/servers/${serverId}/${protocol}/deploy`
        await api(path, {
          method: 'POST',
          body: mode === 'deploy' ? JSON.stringify({ port: p }) : undefined,
        })
      } catch (err) {
        handleError(err)
        return
      }
      timerRef.current = window.setTimeout(() => void poll(), 2500)
    },
    [serverId, mode, protocol, handleError, poll],
  )

  useEffect(() => {
    if (startedRef.current) return
    startedRef.current = true
    aliveRef.current = true
    void start(defaultPort)
    return () => {
      aliveRef.current = false
      if (timerRef.current) window.clearTimeout(timerRef.current)
    }
  }, [start, defaultPort])

  const running = !error && (!status || status.state === 'running' || status.state === 'unknown')
  const done = status?.state === 'done'
  const failed = status?.state === 'error'

  const title =
    mode === 'update'
      ? t('Обновление {label}', { label })
      : mode === 'adopt'
        ? t('Взятие под управление · {label}', { label })
        : t('Установка {label}', { label })

  return (
    <div className="modal-backdrop" onClick={dismiss}>
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
          {mode === 'adopt'
            ? t('Панель перечитывает конфиг из текущего контейнера, сохраняет его порт и ключи и заменяет его своим образом. Клиенты остаются — туннель кратко перезапустится. Перед этим снят снимок для отката.')
            : mode === 'update'
            ? t('Сервер тянет свежий базовый образ и пересобирает контейнер. Клиенты и ключи сохраняются.')
            : protocol === 'xray'
              ? t('Сервер собирает образ Xray-core (alpine) и запускает VLESS+REALITY на 443. Это займёт 1–3 минуты.')
              : protocol === 'openvpn'
                ? t('Сервер собирает образ (openvpn + Cloak + shadowsocks) и генерирует PKI. Это займёт 1–3 минуты.')
                : protocol === 'awg3'
                  ? t('Сервер собирает AmneziaWG 3.1 из исходников (движок + утилиты закреплённых версий) и запускает его. Готового образа с бинарями 3.x пока нет, поэтому первая сборка занимает 3–7 минут.')
                  : t('Сервер собирает образ из amneziavpn/amneziawg-go:latest и запускает AmneziaWG. Это займёт 1–3 минуты.')}
        </p>

        <div className="deploy-state">
          {running && <span className="deploy-spinner">{t('● выполняется…')}</span>}
          {done && <span className="status-ok">{t('✓ готово')}</span>}
          {failed && <span className="status-fail">{t('✗ ошибка (см. лог)')}</span>}
        </div>

        {error && <p className="form-error">{error}</p>}

        {portBusy && (
          <div className="row port-retry">
            <label className="muted small">{t('Порт для установки')}</label>
            <input
              type="number"
              min={1}
              max={65535}
              value={port}
              onChange={(e) => setPort(Number(e.target.value))}
              style={{ maxWidth: 140 }}
            />
            <button
              onClick={() => {
                startedRef.current = true
                void start(port)
              }}
              disabled={!port || port < 1 || port > 65535}
            >
              {t('Развернуть на этом порту')}
            </button>
          </div>
        )}

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
