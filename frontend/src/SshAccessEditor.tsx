import type { Server } from './api'
import { useI18n } from './i18n'
import type { AccessPolicy } from './sshAccess'

export function SshAccessEditor({ value, servers, serverId, onChange }: {
  value: AccessPolicy; servers: Server[]; serverId?: number | null; onChange: (update: AccessPolicy) => void
}) {
  const { t } = useI18n()
  return <fieldset className="ssh-access-options">
    <legend>{t('Доступ SSH')}</legend>
    <label>{t('Подключение')}
      <select value={value.ssh_jump_server_id ?? ''} onChange={e => onChange({ ...value, ssh_jump_server_id: e.target.value ? Number(e.target.value) : null })}>
        <option value="">{t('Напрямую')}</option>
        {servers.filter(node => node.id !== serverId && !node.ssh_jump_server_id).map(node => <option key={node.id} value={node.id}>{t('Через сервер')} {node.name}</option>)}
      </select>
    </label>
    {value.ssh_jump_server_id && <p className="muted small">{t('На выбранной ноде будет создан отдельный доступ только к SSH этой цели. Ключ остается в панели. Другие пользователи SSH не меняются.')}</p>}
    <details><summary>{t('Расширенные настройки SSH и firewall')}</summary>
      <label>{t('Разрешенные источники ключа панели')}
        <select value={value.ssh_source_mode ?? 'panel'} onChange={e => onChange({ ...value, ssh_source_mode: e.target.value as 'panel' | 'custom' | 'any' })}>
          <option value="panel">{value.ssh_jump_server_id ? t('IP панели и промежуточной ноды') : t('IP панели')}</option>
          <option value="custom">{t('Указать IP или CIDR')}</option>
          <option value="any">{t('Без ограничения источника ключа')}</option>
        </select>
      </label>
      {value.ssh_source_mode === 'custom' && <label>{t('IP или CIDR через запятую')}
        <input value={(value.ssh_source_ips ?? []).join(', ')} onChange={e => onChange({ ...value, ssh_source_ips: e.target.value.split(',').map(s => s.trim()) })} placeholder="203.0.113.10, 198.51.100.0/24" />
      </label>}
      {value.ssh_source_mode === 'any' && <p className="muted small">{t('Ключ принимается с любого IP. Это не открывает firewall и не меняет доступ других пользователей.')}</p>}
      <label>{t('Firewall сервера')}
        <select value={value.ssh_firewall_mode ?? 'add'} onChange={e => onChange({ ...value, ssh_firewall_mode: e.target.value as 'add' | 'preserve' })}>
          <option value="add">{t('Добавить разрешения SSH для выбранных источников')}</option>
          <option value="preserve">{t('Не менять firewall')}</option>
        </select>
      </label>
      <p className="muted small">{t('Существующие правила сохраняются. Ограничение ключа не закрывает SSH для других ключей и пользователей.')}</p>
    </details>
  </fieldset>
}
