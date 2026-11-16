import { useEffect, useState } from 'react'
import { api, ApiError } from './api'
import { awgSettingsError } from './awgSettingsError'
import { useI18n } from './i18n'
import { useModalDismiss } from './useModalDismiss'

export type AwgParameters = Record<string, string | number>
type Defaults = { version: string; params: AwgParameters; supported_params: string[] }
type Settings = Defaults & { port: number; subnet: string; server_address: string; revision: string }

export function AwgAdvanced({ params, onChange, loadDefaults }: {
  params: AwgParameters | null
  onChange: (value: AwgParameters) => void
  loadDefaults: () => Promise<Defaults>
}) {
  const { t } = useI18n()
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  return <details onToggle={async event => {
    if (!event.currentTarget.open || params || loading) return
    setLoading(true)
    try { onChange((await loadDefaults()).params) }
    catch (err) { setError(awgSettingsError(err, t)) }
    finally { setLoading(false) }
  }}>
    <summary>{t('Расширенные параметры AmneziaWG')}</summary>
    <p className="muted small">{t('Jc: количество мусорных пакетов, Jmin/Jmax: размер в байтах. S1-S4: дополнение пакетов. H1-H4: непересекающиеся диапазоны заголовков uint32. I1-I5: CPS-пакеты клиента. Пустые I2-I5 допустимы.')}</p>
    <p className="muted small">{t('Показаны параметры выбранной версии. Для 3.1 при RandomTrailers = on значения S1-S4 должны совпадать и быть >= 12. Параметры проверяются до применения.')}</p>
    {error && <p className="form-error">{error}</p>}
    {loading && <p>{t('Загрузка...')}</p>}
    <div className="awg-settings-fields">
      {params && Object.entries(params).map(([key, value]) => <label key={key}>{key}
        {key === 'RandomTrailers' || key === 'DisableCookies'
          ? <select value={String(value)} onChange={e => onChange({ ...params, [key]: e.target.value })}><option>on</option><option>off</option></select>
          : <input type={key === 'HeaderProtectionKey' ? 'password' : 'text'} value={value} autoComplete="off" spellCheck={false}
            maxLength={key.startsWith('I') ? 4000 : 128}
            onChange={e => onChange({ ...params, [key]: e.target.value })} />}
      </label>)}
    </div>
  </details>
}

export function AwgSettingsModal({ serverId, protocol, onClose, onSaved, onUnauthorized }: {
  serverId: number; protocol: 'awg' | 'awg3'; onClose: () => void
  onSaved: () => void; onUnauthorized: () => void
}) {
  const { t } = useI18n()
  const [value, setValue] = useState<Settings | null>(null)
  const [error, setError] = useState('')
  const [ack, setAck] = useState(false)
  const [busy, setBusy] = useState(false)
  const [saved, setSaved] = useState(false)
  const dismiss = useModalDismiss(() => { if (!busy) onClose() })
  const path = `/api/servers/${serverId}/${protocol}/settings`
  useEffect(() => {
    let active = true
    api<Settings>(path).then(data => { if (active) setValue(data) }).catch(err => {
      if (!active) return
      if (err instanceof ApiError && err.status === 401) onUnauthorized()
      else setError(awgSettingsError(err, t))
    })
    return () => { active = false }
  // Parent callbacks may change on a theme/language render.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [path])
  return <div className="modal-backdrop" onClick={dismiss}><div className="card modal modal-wide" onClick={e => e.stopPropagation()}>
    <div className="clients-head"><h3>{t('Настройки AmneziaWG')}{value && ` ${value.version}`}</h3><button className="ghost" disabled={busy} onClick={onClose}>{t('Закрыть')}</button></div>
    <p className="muted small">{t('Изменение порта, подсети или обфускации отключит клиентов. Старые профили могут перестать работать. Сохраненные профили будут обновлены с прежними ключами: скачайте их заново и передайте клиентам. Для внешних клиентов нужен исходный профиль. Серверы с каскадами или нестандартными контейнерами защищены от изменения.')}</p>
    <p className="muted small">{t('Перед применением сохраняется резервная копия. При ошибке выполняется откат. Если связь прервется, повторный запрос сверит и восстановит состояние.')}</p>
    {error && <p className="form-error">{error}</p>}
    {saved && <p className="status-ok">{t('Настройки сохранены. Скачайте существующие профили заново: ключи клиентов сохранены.')}</p>}
    {value && !saved && <form onSubmit={async e => {
      e.preventDefault(); setBusy(true); setError('')
      try {
        await api(path, { method: 'PUT', body: JSON.stringify({ ...value, acknowledge_disconnect: ack }) })
        setSaved(true); onSaved()
      } catch (err) {
        if (err instanceof ApiError && err.status === 401) onUnauthorized()
        else setError(awgSettingsError(err, t))
      } finally { setBusy(false) }
    }}>
      <fieldset disabled={busy} style={{ border: 0, padding: 0 }}>
        <div className="awg-settings-fields">
          <label>{t('UDP-порт')}<input type="number" min={1} max={65535} required value={value.port} onChange={e => setValue({ ...value, port: Number(e.target.value) })} /></label>
          <label>{t('IPv4-подсеть (CIDR)')}<input required value={value.subnet} onChange={e => setValue({ ...value, subnet: e.target.value })} /></label>
          <label>{t('IPv4-адрес интерфейса')}<input required value={value.server_address} onChange={e => setValue({ ...value, server_address: e.target.value })} /></label>
        </div>
        <AwgAdvanced params={value.params} onChange={params => setValue({ ...value, params })} loadDefaults={() => api(`${path}/defaults?protocol_version=${value.version}`)} />
        <label className="check-row"><input type="checkbox" checked={ack} onChange={e => setAck(e.target.checked)} />{t('Подтверждаю отключение клиентов и необходимость обновить их профили')}</label>
        <div className="modal-actions"><button type="submit" disabled={!ack || busy}>{busy ? t('Применение...') : t('Применить настройки')}</button></div>
      </fieldset>
    </form>}
  </div></div>
}
