import { useCallback, useEffect, useRef, useState } from 'react'
import { api, ApiError, type DeployStatus, type DeployProtocol } from './api'
import { useI18n } from './i18n'
import { useModalDismiss } from './useModalDismiss'

// после стольких неудачных опросов статуса подряд перестаем опрашивать
const MAX_POLL_FAILS = 5

type Props = {
  serverId: number
  serverName: string
  mode: 'deploy' | 'update' | 'adopt' | 'upgrade31'
  protocol?: DeployProtocol
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
  const nativeProtocol = protocol === 'wireguard' || protocol === 'openvpn-native'
  const label =
    protocol === 'xray'
      ? 'XRay'
      : protocol === 'wireguard' ? 'WireGuard'
      : protocol === 'openvpn-native' ? 'OpenVPN'
      : protocol === 'openvpn'
        ? 'OpenVPN + Cloak'
        : protocol === 'awg3'
          ? 'AmneziaWG 3.1'
          : 'AmneziaWG'
  const [status, setStatus] = useState<DeployStatus | null>(null)
  const [error, setError] = useState<string | null>(null)
  // Порт по умолчанию СВОЙ у каждого протокола: у 3.0 он обязан отличаться от
  // 2.0, иначе установка целилась бы в порт работающего сервера и упиралась в
  // защиту (а раньше — снесла бы его контейнер вместе с клиентами).
  const defaultPort =
    protocol === 'wireguard' ? 51820 : protocol === 'openvpn-native' ? 1194 : protocol === 'xray' ? 443 : protocol === 'openvpn' ? 8443 : protocol === 'awg3' ? 47300 : 47180
  const [port, setPort] = useState(defaultPort)
  const [transport, setTransport] = useState<'udp' | 'tcp'>('udp')
  const [configured, setConfigured] = useState(!(nativeProtocol && mode === 'deploy'))
  // порт занят другим контейнером — предлагаем выбрать свободный и повторить
  const [portBusy, setPortBusy] = useState(false)
  const startedRef = useRef(false)
  const aliveRef = useRef(true)
  const timerRef = useRef<number | undefined>(undefined)
  // сколько опросов статуса подряд упали; pollWarn - показать, что связь сбоит
  const pollFailsRef = useRef(0)
  const [pollWarn, setPollWarn] = useState(false)
  // колбэки родителя пересоздаются при каждой его перерисовке (тема, язык):
  // через ref, чтобы опрос не перезапускал эффект и не обрывался
  const onDoneRef = useRef(onDone)
  const onUnauthorizedRef = useRef(onUnauthorized)
  useEffect(() => {
    onDoneRef.current = onDone
    onUnauthorizedRef.current = onUnauthorized
  })

  const handleError = useCallback(
    (err: unknown) => {
      if (err instanceof ApiError && err.status === 401) {
        onUnauthorizedRef.current()
        return
      }
      // 409 бывает разный (чужой контейнер, уже 3.1, идет другая установка).
      // Поле выбора порта нужно только при установке и только когда бэкенд
      // пишет "Порт {port}/{proto} уже занят: ...", остальное просто показываем
      if (
        mode === 'deploy' &&
        err instanceof ApiError &&
        err.status === 409 &&
        /^Порт \d+\/\w+ уже занят/.test(err.message)
      ) {
        setPortBusy(true)
        // подставляем соседний порт, чтобы не пришлось придумывать самому. Для
        // XRay с занятым 443 (часто это веб-сервер или сама панель) сразу 8443:
        // привычный TLS-порт выглядит естественнее, чем 444
        setPort((prev) =>
          protocol === 'xray' && prev === 443 ? 8443 : prev >= 65535 ? prev : prev + 1,
        )
      }
      setError(err instanceof Error ? err.message : t('Ошибка'))
    },
    [t, protocol, mode],
  )

  const poll = useCallback(async () => {
    if (!aliveRef.current) return
    try {
      const s = await api<DeployStatus>(
        `/api/servers/${serverId}/${protocol}/deploy/status`,
      )
      if (!aliveRef.current) return
      pollFailsRef.current = 0
      setPollWarn(false)
      setStatus(s)
      if (s.state === 'done') {
        onDoneRef.current()
        return
      }
      if (s.state === 'error') return
    } catch (err) {
      if (!aliveRef.current) return
      if (err instanceof ApiError && err.status === 401) {
        onUnauthorizedRef.current()
        return
      }
      // разовый сбой сети/панели не должен останавливать опрос: установка на
      // ноде идет дальше. Сдаемся только после нескольких неудач подряд
      pollFailsRef.current += 1
      setPollWarn(true)
      if (pollFailsRef.current >= MAX_POLL_FAILS) {
        setError(
          t('Не удалось получить статус, установка на ноде может продолжаться. Проверьте позже: {err}', {
            err: err instanceof Error ? err.message : t('Ошибка'),
          }),
        )
        return
      }
    }
    schedule(3000)
  }, [serverId, protocol, t])

  // один отложенный опрос за раз: новый заменяет прежний
  const schedule = (ms: number) => {
    window.clearTimeout(timerRef.current)
    timerRef.current = window.setTimeout(() => void pollRef.current(), ms)
  }
  const pollRef = useRef(poll)
  pollRef.current = poll

  const start = useCallback(
    async (p: number) => {
      setError(null)
      setPortBusy(false)
      pollFailsRef.current = 0
      setPollWarn(false)
      try {
        const path =
          mode === 'update'
            ? `/api/servers/${serverId}/${protocol}/update`
            : mode === 'adopt'
              ? `/api/servers/${serverId}/${protocol}/adopt`
              : mode === 'upgrade31'
                ? `/api/servers/${serverId}/${protocol}/upgrade31`
                : `/api/servers/${serverId}/${protocol}/deploy`
        await api(path, {
          method: 'POST',
          body: mode === 'deploy' ? JSON.stringify({ port: p, ...(nativeProtocol ? { transport: protocol === 'wireguard' ? 'udp' : transport } : {}) }) : undefined,
        })
      } catch (err) {
        handleError(err)
        return
      }
      schedule(2500)
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [serverId, mode, protocol, nativeProtocol, transport, handleError],
  )

  // установка запускается один раз за жизнь окна; остановка опроса - только
  // при закрытии окна, а не при пересоздании start (иначе опрос обрывался, а
  // повторный запуск эффект пропускал, и окно висело на "выполняется")
  const startRef = useRef(start)
  startRef.current = start
  useEffect(() => {
    aliveRef.current = true
    if (!startedRef.current && !(nativeProtocol && mode === 'deploy')) {
      startedRef.current = true
      void startRef.current(defaultPort)
    } else if (startedRef.current && timerRef.current === undefined) {
      // StrictMode: первый cleanup снял таймер - продолжаем опрос
      schedule(1000)
    }
    return () => {
      aliveRef.current = false
      if (timerRef.current) window.clearTimeout(timerRef.current)
      timerRef.current = undefined
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const running = configured && !error && (!status || status.state === 'running' || status.state === 'unknown')
  const done = status?.state === 'done'
  const failed = status?.state === 'error'

  const title =
    mode === 'update'
      ? t('Обновление {label}', { label })
      : mode === 'adopt'
        ? t('Взятие под управление · {label}', { label })
        : mode === 'upgrade31'
          ? t('Обновление до AmneziaWG 3.1')
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
          {mode === 'upgrade31'
            ? t('Контейнер amnezia-awg2 обновляется до протокола 3.1 на месте: порт, ключ сервера и подсеть сохраняются, к конфигу добавляются параметры третьей версии. Клиенты 2.0 после этого не подключатся — их нужно перевыпустить. Перед обновлением снят снимок для отката.')
            : mode === 'adopt'
            ? t('Панель перечитывает конфиг из текущего контейнера, сохраняет его порт и ключи и заменяет его своим образом. Клиенты остаются — туннель кратко перезапустится. Перед этим снят снимок для отката.')
            : mode === 'update'
            ? t('Сервер тянет свежий базовый образ и пересобирает контейнер. Клиенты и ключи сохраняются.')
            : protocol === 'wireguard'
              ? t('Отдельный обычный WireGuard по UDP. Клиентам выдаются стандартные .conf, без параметров AmneziaWG.')
            : protocol === 'openvpn-native'
              ? t('Отдельный обычный OpenVPN с сертификатами клиентов. Для подключения нужен только файл .ovpn, без Cloak.')
            : protocol === 'xray'
              ? t('Сервер собирает образ Xray-core (alpine) и запускает VLESS+REALITY на 443. Это займёт 1–3 минуты.')
              : protocol === 'openvpn'
                ? t('Сервер собирает образ (openvpn + Cloak + shadowsocks) и генерирует PKI. Это займёт 1–3 минуты.')
                : protocol === 'awg3'
                  ? t('Сервер собирает AmneziaWG 3.1 из исходников (движок + утилиты закреплённых версий) и запускает его. Готового образа с бинарями 3.x пока нет, поэтому первая сборка занимает 3–7 минут.')
                  : t('Сервер собирает образ из amneziavpn/amneziawg-go:latest и запускает AmneziaWG. Это займёт 1–3 минуты.')}
        </p>

        {configured && <div className="deploy-state">
          {running && <span className="deploy-spinner">{t('● выполняется…')}</span>}
          {done && <span className="status-ok">{t('✓ готово')}</span>}
          {failed && <span className="status-fail">{t('✗ ошибка (см. лог)')}</span>}
        </div>}

        {error && <p className="form-error">{error}</p>}
        {!error && pollWarn && (
          <p className="muted small">{t('Не удалось получить статус, повторяем запрос...')}</p>
        )}

        {(!configured || portBusy) && (
          <div className="row port-retry">
            <label className="muted small">{t('Порт для установки')}
            <input
              type="number"
              min={1}
              max={65535}
              value={port}
              onChange={(e) => setPort(Number(e.target.value))}
              style={{ maxWidth: 140 }}
            />
            </label>
            {protocol === 'openvpn-native' && <label className="muted small">{t('Транспорт')}
              <select aria-label={t('Транспорт')} value={transport} onChange={e => setTransport(e.target.value as 'udp' | 'tcp')}><option value="udp">UDP</option><option value="tcp">TCP</option></select>
            </label>}
            <button
              onClick={() => {
                startedRef.current = true
                setConfigured(true)
                void start(port)
              }}
              disabled={!Number.isInteger(port) || port < 1 || port > 65535}
            >
              {t('Развернуть на этом порту')}
            </button>
          </div>
        )}

        {configured && <pre className="script-box deploy-log">
          {status?.log || t('запуск…')}
        </pre>}

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
