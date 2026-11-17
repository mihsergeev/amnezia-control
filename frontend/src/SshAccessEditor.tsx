import { useId } from 'react'
import type { Server } from './api'
import { useI18n } from './i18n'
import type { AccessPolicy } from './sshAccess'

export function SshAccessEditor({ value, servers, serverId, onChange }: {
  value: AccessPolicy; servers: Server[]; serverId?: number | null; onChange: (update: AccessPolicy) => void
}) {
  const { t } = useI18n()
  const id = useId()
  const firewallMode = value.ssh_firewall_mode ?? 'add'

  return <div className="ssh-access-options" role="group" aria-labelledby={`${id}-title`}>
    <div>
      <h4 id={`${id}-title`}>{t('Доступ SSH')}</h4>
      <p className="muted small">{t('Панель подключается напрямую или через промежуточный сервер.')}</p>
    </div>
    <div className="ssh-access-field">
      <label htmlFor={`${id}-connection`}>{t('Подключение')}</label>
      <div className="ssh-access-select">
        <select
          id={`${id}-connection`}
          aria-describedby={value.ssh_jump_server_id ? `${id}-jump-help` : undefined}
          value={value.ssh_jump_server_id ?? ''}
          onChange={e => onChange({ ...value, ssh_jump_server_id: e.target.value ? Number(e.target.value) : null })}
        >
          <option value="">{t('Напрямую')}</option>
          {servers.filter(node => node.id !== serverId && !node.ssh_jump_server_id).map(node => <option key={node.id} value={node.id}>{t('Через сервер')} {node.name}</option>)}
        </select>
      </div>
      {value.ssh_jump_server_id && <p className="muted small" id={`${id}-jump-help`}>{t('На выбранной ноде будет создан отдельный доступ только к SSH этой цели. Ключ остается в панели. Другие пользователи SSH не меняются.')}</p>}
    </div>
    <details className="ssh-access-advanced">
      <summary>{t('Расширенные настройки SSH и firewall')}</summary>
      <div className="ssh-access-advanced-fields">
        <div className="ssh-access-field">
          <label htmlFor={`${id}-source`}>{t('Разрешенные источники ключа панели')}</label>
          <div className="ssh-access-select">
            <select
              id={`${id}-source`}
              aria-describedby={value.ssh_source_mode === 'any' ? `${id}-source-help` : undefined}
              value={value.ssh_source_mode ?? 'panel'}
              onChange={e => onChange({ ...value, ssh_source_mode: e.target.value as 'panel' | 'custom' | 'any' })}
            >
              <option value="panel">{value.ssh_jump_server_id ? t('IP панели и промежуточной ноды') : t('IP панели')}</option>
              <option value="custom">{t('Указать IP или CIDR')}</option>
              <option value="any">{t('С любого IP')}</option>
            </select>
          </div>
          {value.ssh_source_mode === 'any' && <p className="muted small" id={`${id}-source-help`}>{t('Ключ принимается с любого IP. Это не открывает firewall и не меняет доступ других пользователей.')}</p>}
        </div>
        {value.ssh_source_mode === 'custom' && <label>{t('IP или CIDR через запятую')}
          <input value={(value.ssh_source_ips ?? []).join(', ')} onChange={e => onChange({ ...value, ssh_source_ips: e.target.value.split(',').map(s => s.trim()) })} placeholder="203.0.113.10, 198.51.100.0/24" />
        </label>}
        <div className="ssh-access-field">
          <label htmlFor={`${id}-firewall`}>{t('Firewall сервера')}</label>
          <div className="ssh-access-select">
            <select
              id={`${id}-firewall`}
              aria-describedby={`${id}-firewall-help`}
              value={firewallMode}
              onChange={e => onChange({ ...value, ssh_firewall_mode: e.target.value as 'add' | 'preserve' })}
            >
              <option value="add">{t('Добавить правила SSH')}</option>
              <option value="preserve">{t('Не менять firewall')}</option>
            </select>
          </div>
          <p className="muted small" id={`${id}-firewall-help`}>
            {firewallMode === 'add' && <>{t('Панель добавит правила SSH для выбранных источников.')} </>}
            {t('Существующие правила сохраняются. Ограничение ключа не закрывает SSH для других ключей и пользователей.')}
          </p>
        </div>
      </div>
    </details>
  </div>
}
