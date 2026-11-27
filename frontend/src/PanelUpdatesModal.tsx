import { useEffect, useId, useState } from 'react'
import { PROJECT_URL } from './AboutModal'
import { ApiError, type PanelInstallation, type PanelUpdateInfo } from './api'
import { useI18n } from './i18n'
import { StepUpModal } from './StepUpModal'
import { useModalDismiss } from './useModalDismiss'
import { isInstallationActive, usePanelInstallation } from './usePanelInstallation'

const LABELS = {
  release: {
    available: 'Доступно обновление панели.',
    up_to_date: 'Установлена последняя стабильная версия.',
    ahead: 'Установленная версия новее последнего стабильного релиза.',
    unavailable: 'Не удалось проверить обновления.',
    disabled: 'Проверка обновлений отключена в конфигурации панели.',
    unknown: 'Не удалось сравнить установленную версию со стабильным релизом.',
    stale: 'Не удалось обновить сведения о релизе. Показана ранее полученная версия.',
    checking: 'Проверяем обновления…',
  },
  phase: {
    queued: 'Обновление поставлено в очередь.',
    verifying: 'Проверяем подпись образов.',
    backing_up: 'Создаём и проверяем резервную копию.',
    installing: 'Устанавливаем обновление. Панель может быть временно недоступна.',
    checking: 'Проверяем работу панели после установки.',
    succeeded: 'Обновление установлено.',
    rolling_back: 'Восстанавливаем предыдущую версию.',
    rolled_back: 'Предыдущая версия восстановлена.',
    failed: 'Установка завершилась ошибкой.',
    recovery_required: 'Требуется ручное восстановление на сервере.',
  },
  error: {
    invalid_password: 'Неверный пароль.',
    '2fa_required': 'Введите свежий код из приложения 2FA.',
    '2fa_invalid': 'Код 2FA неверен или уже использован. Введите новый код.',
    '2fa_setup_required': 'Включите двухфакторную аутентификацию в меню панели.',
    https_required: 'Для установки откройте панель по HTTPS.',
    browser_request_required: 'Откройте панель напрямую в браузере по её адресу HTTPS.',
    release_unavailable: 'Версия для установки изменилась или недоступна. Проверьте обновления ещё раз.',
    installation_busy: 'На сервере уже выполняется обновление.',
    installation_rejected: 'Установщик отклонил запрос.',
    busy: 'На сервере уже выполняется обновление.',
    incompatible: 'Обновление несовместимо с текущей конфигурацией. Обновите панель вручную.',
    verification_failed: 'Проверка подлинности образов не прошла.',
    backup_failed: 'Проверка резервной копии не прошла.',
    install_failed: 'Установщик не смог запустить новую версию.',
    health_failed: 'Новая версия не прошла проверку работоспособности.',
    interrupted: 'Работа установщика прервана.',
    recovery_failed: 'Автоматическое восстановление завершилось ошибкой.',
    unusable_state: 'Состояние установщика требует проверки на сервере.',
  },
}

function installationError(code: string | null) {
  if (code && Object.hasOwn(LABELS.error, code)) return LABELS.error[code as keyof typeof LABELS.error]
}

function sameVersion(first: string | null | undefined, second: string | null | undefined) {
  return first && second && first.replace(/^v/, '') === second.replace(/^v/, '')
}

export function PanelUpdatesModal({ info, version, checking, failed, onCheck, onRefreshRelease, onUnauthorized, onClose }: {
  info: PanelUpdateInfo | null
  version: string | null
  checking: boolean
  failed: boolean
  onCheck: () => void
  onRefreshRelease: () => void
  onUnauthorized: () => void
  onClose: () => void
}) {
  const { lang, t } = useI18n()
  const title = useId()
  const dismiss = useModalDismiss(onClose)
  const installation = usePanelInstallation(onUnauthorized)
  const [target, setTarget] = useState<string | null>(null)
  const [unconfirmed, setUnconfirmed] = useState<{ target: string; statusBefore: PanelInstallation | null } | null>(null)
  const [notice, setNotice] = useState('')
  const latest = info?.latest_version
  const checkedAt = info?.checked_at
  const timestamp = checkedAt ? Date.parse(checkedAt) : NaN
  const expectedUrl = latest && /^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/.test(latest)
    ? `${PROJECT_URL}/releases/tag/${latest}`
    : null
  const releaseUrl = expectedUrl === info?.release_url ? expectedUrl : null

  let status: keyof typeof LABELS.release = info?.status ?? 'unavailable'
  if (failed) status = latest ? 'stale' : 'unavailable'
  if (info?.stale) status = 'stale'
  if (checking) status = 'checking'

  const installationStatus = installation.status
  const phase = installationStatus?.phase ?? 'idle'
  const updateVersion = installationStatus?.version
  const secure = window.location.protocol === 'https:'
  const installerVersion = latest?.match(/^v((?:0|[1-9]\d{0,7})(?:\.(?:0|[1-9]\d{0,7})){2})$/)?.[1]
  const canInstall = secure && status === 'available' && releaseUrl && installerVersion
    && installationStatus?.enabled && installation.reachable === true && !installation.submitting
    && !isInstallationActive(phase) && phase !== 'recovery_required'
    && !(phase === 'succeeded' && sameVersion(updateVersion, latest))

  useEffect(() => {
    if (phase === 'succeeded' || phase === 'rolled_back') onRefreshRelease()
  }, [phase, updateVersion, onRefreshRelease])

  const statusChanged = unconfirmed && sameVersion(updateVersion, unconfirmed.target)
    && (phase !== unconfirmed.statusBefore?.phase || installationStatus?.error !== unconfirmed.statusBefore?.error)
  useEffect(() => {
    if (statusChanged) setUnconfirmed(null)
  }, [statusChanged])

  async function confirmInstall(password: string, otp: string) {
    if (!target || target !== latest || !canInstall || !installerVersion) {
      throw new Error(t('Установка сейчас недоступна. Проверьте состояние обновления.'))
    }
    setUnconfirmed(null)
    setNotice('')
    try {
      await installation.install(installerVersion, password, otp)
      setTarget(null)
    } catch (err) {
      const code = err instanceof ApiError ? err.code ?? err.message : null
      if (err instanceof ApiError && err.status === 401) {
        onUnauthorized()
        return
      }
      if (err instanceof ApiError && err.status === 429) {
        throw new Error(t('Слишком много неверных попыток. Попробуйте позже.'))
      }
      if (code === 'invalid_password' || code === '2fa_required' || code === '2fa_invalid' || code === '2fa_setup_required') {
        throw new Error(t(installationError(code) ?? 'Не удалось запустить установку.'))
      }
      setTarget(null)
      if (code === 'release_unavailable') onRefreshRelease()
      const known = installationError(code)
      if (err instanceof ApiError && err.status < 500) setNotice(known ?? 'Не удалось запустить установку.')
      else setUnconfirmed({ target, statusBefore: installationStatus })
    }
  }

  const installerError = installationError(installationStatus?.error ?? null)

  return (
    <>
      <div className="modal-backdrop" inert={target !== null} onClick={dismiss}>
        <section className="card modal panel-updates-modal" role="dialog" aria-modal="true" aria-labelledby={title}>
          <div className="clients-head">
            <h3 id={title}>{t('Обновления')}</h3>
            <button className="ghost" onClick={onClose}>{t('Закрыть')}</button>
          </div>
          <dl className="panel-update-details">
            <dt>{t('Установленная версия')}</dt>
            <dd><code>{info?.current_version || version || '—'}</code></dd>
            <dt>{t('Последняя стабильная версия')}</dt>
            <dd><code>{latest || '—'}</code></dd>
            <dt>{t('Последняя проверка')}</dt>
            <dd>{Number.isFinite(timestamp)
              ? <time dateTime={checkedAt ?? undefined}>{new Intl.DateTimeFormat(lang, { dateStyle: 'medium', timeStyle: 'short' }).format(timestamp)}</time>
              : '—'}</dd>
          </dl>
          <div className="panel-update-statuses" role="status" aria-atomic="false">
            <p className="muted">{t(LABELS.release[status] ?? LABELS.release.unavailable)}</p>
            {phase !== 'idle' && (
              <div className="panel-install-status">
                {updateVersion && <code>{updateVersion}</code>}
                <p>{t(LABELS.phase[phase])}</p>
                {installerError && <p className="muted small">{t(installerError)}</p>}
              </div>
            )}
            {installation.reachable === false && (
              <p className="muted">{t('Не удалось получить статус установки. Повторяем запрос…')}</p>
            )}
            {unconfirmed && !statusChanged && (
              <p className="muted">{installation.reachable === true
                ? t('Сервер не подтвердил запуск установки.')
                : t('Ответ на запрос установки потерян. Проверяем её статус…')}</p>
            )}
          </div>
          {notice && <p className="form-error" role="alert">{t(notice)}</p>}
          {status === 'available' && installationStatus && !installationStatus.enabled && (
            <p className="muted">{t('Установка из панели отключена на сервере.')} {' '}
              <a href={`${PROJECT_URL}/blob/main/docs/panel-updater.md`} target="_blank" rel="noopener noreferrer">{t('Как включить установщик')}</a>
            </p>
          )}
          {status === 'available' && installationStatus?.enabled && !secure && (
            <p className="muted">{t('Для установки откройте панель по HTTPS.')}</p>
          )}
          <div className="modal-actions">
            {releaseUrl && <a href={releaseUrl} target="_blank" rel="noopener noreferrer">{t('Открыть релиз')}</a>}
            <button className={canInstall ? 'ghost' : 'primary'} onClick={() => {
              onCheck()
              installation.refresh()
              setNotice('')
            }} disabled={checking || info?.status === 'disabled'}>{t('Проверить')}</button>
            {canInstall && latest && (
              <button className="primary" onClick={() => setTarget(latest)}>{t('Установить {version}', { version: latest })}</button>
            )}
          </div>
        </section>
      </div>
      {target && (
        <StepUpModal requiredOtp
          text={t('Для установки {version} введите пароль панели и свежий шестизначный код 2FA. Во время обновления панель может быть недоступна.', { version: target })}
          onCancel={() => setTarget(null)}
          onSubmit={confirmInstall}
        />
      )}
    </>
  )
}
