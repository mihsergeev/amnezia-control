import { useCallback, useEffect, useState } from 'react'
import { api, ApiError } from './api'
import { useI18n } from './i18n'

type AuditEntry = {
  id: number
  ts: string
  username: string
  action: string
  target: string
  detail: string
}

type Props = { onUnauthorized: () => void }

const LABELS: Record<string, string> = {
  awg_issue: 'Выдан AmneziaWG',
  awg_revoke: 'Отозван AmneziaWG',
  awg_reissue: 'Перевыпущен AmneziaWG',
  awg_deploy: 'Развёрнут AmneziaWG',
  awg_update: 'Обновлён AmneziaWG',
  awg_adopt: 'AmneziaWG взят под управление',
  awg_pause: 'AmneziaWG на паузе',
  awg_resume: 'AmneziaWG возобновлён',
  awg_config_restore: 'Откат конфига AmneziaWG',
  awglegacy_issue: 'Выдан AmneziaWG Legacy',
  awglegacy_reissue: 'Перевыпущен AmneziaWG Legacy',
  awglegacy_revoke: 'Отозван AmneziaWG Legacy',
  awglegacy_pause: 'AmneziaWG Legacy на паузе',
  awglegacy_resume: 'AmneziaWG Legacy возобновлён',
  awg_upgrade31: 'AmneziaWG обновлен до 3.1',
  awg3_issue: 'Выдан AmneziaWG 3.1',
  awg3_reissue: 'Перевыпущен AmneziaWG 3.1',
  awg3_revoke: 'Отозван AmneziaWG 3.1',
  awg3_pause: 'AmneziaWG 3.1 на паузе',
  awg3_resume: 'AmneziaWG 3.1 возобновлен',
  awg3_deploy: 'Развернут AmneziaWG 3.1',
  awg3_update: 'Пересобран AmneziaWG 3.1',
  awg3_config_restore: 'Откат конфига AmneziaWG 3.1',
  awg3_rollback: 'Откат движка 3.1',
  // авто-отзыв по сроку (expiry.py пишет {protocol}_expired от "система")
  awg_expired: 'Истек срок AmneziaWG',
  awg3_expired: 'Истек срок AmneziaWG 3.1',
  awglegacy_expired: 'Истек срок AmneziaWG Legacy',
  openvpn_expired: 'Истек срок OpenVPN',
  xray_expired: 'Истек срок XRay',
  limit_set: 'Задан срок клиента',
  limit_clear: 'Снят срок клиента',
  clients_bulk_revoke: 'Массовый отзыв клиентов',
  openvpn_issue: 'Выдан OpenVPN',
  openvpn_revoke: 'Отозван OpenVPN',
  openvpn_reissue: 'Перевыпущен OpenVPN',
  openvpn_deploy: 'Развёрнут OpenVPN/Cloak',
  openvpn_update: 'Пересобран OpenVPN/Cloak',
  openvpn_pause: 'OpenVPN на паузе',
  openvpn_resume: 'OpenVPN возобновлён',
  openvpn_config_restore: 'Откат конфига OpenVPN',
  xray_config_restore: 'Откат конфига XRay',
  xray_issue: 'Выдан XRay',
  xray_reissue: 'Перевыпущен XRay',
  xray_pause: 'XRay на паузе',
  xray_resume: 'XRay возобновлён',
  xray_revoke: 'Отозван XRay',
  xray_deploy: 'Развёрнут XRay',
  xray_update: 'Обновлён XRay',
  server_create: 'Добавлен сервер',
  server_delete: 'Удалён сервер',
  server_export: 'Сервер выгружен в файл',
  server_import_file: 'Сервер загружен из файла',
  alerts_update: 'Изменены настройки алертов',
  alerts_test: 'Тестовый алерт',
  share_link: 'Конфиг отправлен ссылкой',
  share_service_add: 'Добавлен сервис ссылок',
  share_service_delete: 'Удален сервис ссылок',
  fullaccess_export: 'Экспорт полного доступа',
  fullaccess_denied: 'Экспорт полного доступа отклонён',
  restore: 'Восстановление из бэкапа',
  restore_denied: 'Восстановление из бэкапа отклонено',
  backup_restore: 'Восстановление из бэкапа',
  backup_download: 'Скачан бэкап',
  backup_download_denied: 'Скачивание бэкапа отклонено',
  login_ok: 'Вход выполнен',
  logout: 'Выход',
  admin_password_reset: 'Аварийный сброс пароля из .env',
  login_fail: 'Неудачный вход',
  login_2fa_fail: 'Неудачный вход (2FA)',
  login_blocked: 'Вход заблокирован (лимит)',
  login_lockout: 'Блокировка входа (брутфорс)',
  password_change: 'Смена пароля',
  host_key_changed: 'Host-ключ ноды изменился',
  '2fa_enable': 'Включена 2FA',
  '2fa_disable': 'Отключена 2FA',
  apikey_create: 'Создан API-ключ',
  apikey_revoke: 'Отозван API-ключ',
  apikey_update: 'Изменен API-ключ',
}

export function AuditPage({ onUnauthorized }: Props) {
  const { t, lang } = useI18n()
  const [items, setItems] = useState<AuditEntry[] | null>(null)
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(async () => {
    try {
      setItems(await api<AuditEntry[]>('/api/audit?limit=300'))
      setError(null)
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) return onUnauthorized()
      setError(t('не удалось загрузить журнал'))
    }
  }, [onUnauthorized, t])

  useEffect(() => {
    void load()
  }, [load])

  function fmt(iso: string) {
    return new Date(iso).toLocaleString(lang === 'en' ? 'en-GB' : 'ru-RU', {
      dateStyle: 'medium',
      timeStyle: 'short',
    })
  }

  return (
    <section>
      <div className="page-head">
        <h2>{t('Журнал действий')}</h2>
        <div className="page-head-actions">
          <button className="ghost" onClick={load}>
            {t('Обновить')}
          </button>
        </div>
      </div>

      {error && <p className="form-error">{error}</p>}

      {items === null ? (
        <p className="muted">{t('загрузка…')}</p>
      ) : items.length === 0 ? (
        <div className="card">
          <p className="muted">{t('Пока пусто — действия появятся здесь.')}</p>
        </div>
      ) : (
        <div className="table-card">
          <table>
            <thead>
              <tr>
                <th>{t('Когда')}</th>
                <th>{t('Кто')}</th>
                <th>{t('Действие')}</th>
                <th>{t('Объект')}</th>
              </tr>
            </thead>
            <tbody>
              {items.map((e) => (
                <tr key={e.id}>
                  <td className="muted small">{fmt(e.ts)}</td>
                  <td className="mono">{e.username || '—'}</td>
                  <td>{t(LABELS[e.action] || e.action)}</td>
                  <td className="muted">
                    {e.target}
                    {e.detail && (
                      <span className="muted small"> · {e.detail}</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}
